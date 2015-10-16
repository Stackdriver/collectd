/**
 * collectd - src/write_gcm.c
 * Copyright (C) 2014  Google Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Zhihua Wen <zhihuawen at google.com>
 *   Florian Forster <octo at google.com>
 *   Corey Kosak <kosak at google.com>
 **/

#include "collectd.h"
#include "common.h"
#include "daemon/collectd.h"
#include "plugin.h"
#include "configfile.h"
#include "utils_avltree.h"

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "curl/curl.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>

#include <yajl/yajl_gen.h>
#include <yajl/yajl_parse.h>
#include <yajl/yajl_tree.h>

#if HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include <inttypes.h>

//==============================================================================
//==============================================================================
//==============================================================================
// Settings that affect the behavior of this plugin.
//==============================================================================
//==============================================================================
//==============================================================================

static const char this_plugin_name[] = "write_gcm";

// The URL of the GCP metadata server.
static const char gcp_metadata_server[] =
    "http://169.254.169.254/computeMetadata/v1beta1/";

// The URL to get the auth token from the metadata server.
static const char metadata_fetch_auth_token[] =
  "http://169.254.169.254/computeMetadata/v1beta1/instance/service-accounts/default/token";

// The Agent Translation Service endpoint. This is in printf format,
// with a single %s placeholder which holds the name of the project.
static const char agent_translation_service_default_format_string[] =
  "https://monitoring.googleapis.com/v3/%s/collectd/timeSeries";

// The application/JSON content header.
static const char json_content_type_header[] = "Content-Type: application/json";

// The special HTTP header that needs to be added to any call to the GCE
// metadata server.
static const char google_metadata_header[] = "Metadata-Flavor: Google";

// The maximum number of entries we keep in our processing queue before flushing
// it. Ordinarily a flush happens every minute or so, but we also flush if the
// list size exceeds a certain value.
#define MAX_QUEUE_SIZE 100

// Size of the JSON buffer sent to the server. At flush time we format a JSON
// message to send to the server.  We would like it to be no more than a certain
// number of bytes in size. We make this a 'soft' limit so that when the target
// is reached, there is a little bit of margin to close out the JSON message
// (finish the current array we are building, close out various records etc)
// so that we cam always try to send a valid JSON message. The total size of the
// buffer we allocate is (JSON_SOFT_TARGET_SIZE + JSON_LOW_WATER_MARK)

// The "soft target" for the max size of our json messages.
#define JSON_SOFT_TARGET_SIZE 64000

// Additional slop so that we have enough space to close out the message.
#define JSON_LOW_WATER_MARK 5000

//==============================================================================
//==============================================================================
//==============================================================================
// Misc utility functions.
//==============================================================================
//==============================================================================
//==============================================================================

// Prints data to a buffer. *buffer and *size are adjusted by the number of
// characters printed. Remaining arguments are the same as snprintf. Does not
// overwrite the bounds of the buffer under any circumstances. When successful,
// leaves *buffer pointing directly at a terminating NUl character (just like
// snprintf).
//
// This method is designed to allow the caller to do series of calls to
// bufprintf, and only check for errors at the end of the series rather than
// after every call. This leads to shorter, more readable code in exchange for
// wasted CPU effort in the event of an error. Since errors are expected to be
// rare, this is a worthwhile tradeoff.
//
// Two kinds of errors are possible, and are indicated by the value of *size.
// 1. If the buffer fills up (because the number of characters fed to it either
// reached or exceeded its capacity), *size will be 1. (This represents the
// fact that there is just enough space left for the terminating NUL). Note that
// a buffer which is exactly full is indistinguishable from a buffer that has
// overflowed. This distinction does not matter for our purposes, and it is far
// more convenient to treat the "buffer exactly full" case as though it was an
// overflow rather than separating it out.
//
// 2. If vsprintf returns an error, *size will be forced to 0.
//
// Callers who do not care about this distinction can just check for *size > 1
// as a success indication.
//
// Example usage:
//   char buffer[1024];
//   char *p = buffer;
//   size_t s = sizeof(buffer);
//   bufprintf(&p, &s, fmt, args...);
//   bufprintf(&p, &s, fmt, args...);  /* add more */
//   bufprintf(&p, &s, fmt, args...);  /* add yet more */
//   /* check for errors here */
//   if (s < 2) {
//     ERROR("error (s==0) or overflow (s==1)");
//     return -1;
//   }
static void bufprintf(char **buffer, size_t *size, const char *fmt, ...) {
  if (*size == 0) {
    return;
  }
  va_list ap;
  va_start(ap, fmt);
  int result = vsnprintf(*buffer, *size, fmt, ap);
  va_end(ap);

  if (result < 0) {
    *size = 0;
    return;
  }
  // If the result was *size or more, the output was truncated. In that case,
  // adjust the pointer and size so they are pointing to the last byte (the
  // terminating NUL).
  if (result >= *size) {
    result = *size - 1;
  }
  *buffer += result;
  *size -= result;
}

//==============================================================================
//==============================================================================
//==============================================================================
// Credential submodule.
//==============================================================================
//==============================================================================
//==============================================================================
typedef struct {
  char *email;
  EVP_PKEY *private_key;
} credential_ctx_t;

static credential_ctx_t *wg_credential_ctx_create(
    const char *email, const char *key_file, const char *passphrase);
static void wg_credential_ctx_destroy(credential_ctx_t *ctx);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
// Load the private key from 'filename'. Caller owns result.
static EVP_PKEY *wg_credential_contex_load_pkey(char const *filename,
                                                char const *passphrase);

static credential_ctx_t *wg_credential_ctx_create(
    const char *email, const char *key_file, const char *passphrase) {
  credential_ctx_t *result = calloc(1, sizeof(*result));
  if (result == NULL) {
    ERROR("write_gcm: wg_credential_ctx_create: calloc failed.");
    return NULL;
  }
  result->email = sstrdup(email);
  result->private_key = wg_credential_contex_load_pkey(key_file, passphrase);
  if (result->private_key == NULL) {
    wg_credential_ctx_destroy(result);
    return NULL;
  }
  return result;
}

static void wg_credential_ctx_destroy(credential_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  if (ctx->private_key != NULL) {
    EVP_PKEY_free(ctx->private_key);
  }
  sfree(ctx->email);
  sfree(ctx);
}

static EVP_PKEY *wg_credential_contex_load_pkey(char const *filename,
                                                char const *passphrase) {
  OpenSSL_add_all_algorithms();
  FILE *fp = fopen(filename, "rb");
  if (fp == NULL) {
    ERROR("write_gcm: Failed to open private key file %s", filename);
    return NULL;
  }

  PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
  fclose(fp);
  char err_buf[1024];
  if (p12 == NULL) {
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof (err_buf));
    ERROR("write_gcm: Reading private key %s failed: %s", filename, err_buf);
    return NULL;
  }

  EVP_PKEY *pkey = NULL;
  X509 *cert = NULL;
  STACK_OF(X509) *ca = NULL;
  int result = PKCS12_parse(p12, passphrase, &pkey, &cert, &ca); // 0 is failure
  if (result == 0) {
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof (err_buf));
    ERROR("write_gcm: Parsing private key %s failed: %s", filename, err_buf);
    PKCS12_free(p12);
    return NULL;
  }

  sk_X509_pop_free(ca, X509_free);
  X509_free(cert);
  PKCS12_free(p12);
  return pkey;
}

//==============================================================================
//==============================================================================
//==============================================================================
// CURL submodule.
//==============================================================================
//==============================================================================
//==============================================================================

// Does an HTTP GET or POST, with optional HTTP headers. The type of request is
// determined by 'body': if 'body' is NULL, does a GET, otherwise does a POST.
static int wg_curl_get_or_post(char *response_buffer,
    size_t response_buffer_size, const char *url, const char *body,
    const char **headers, int num_headers);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
typedef struct {
  char *data;
  size_t size;
} wg_curl_write_ctx_t;

static size_t wg_curl_write_callback(char *ptr, size_t size, size_t nmemb,
                                     void *userdata);

static int wg_curl_get_or_post(char *response_buffer,
    size_t response_buffer_size, const char *url, const char *body,
    const char **headers, int num_headers) {
  const char *get_or_post_tag = body == NULL ? "GET" : "POST";
  DEBUG("write_gcm: Doing %s request: url %s, body %s, num_headers %d",
        get_or_post_tag, url, body, num_headers);
  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    ERROR("write_gcm: curl_easy_init failed");
    return -1;
  }
  const char *collectd_useragent = COLLECTD_USERAGENT;
  struct curl_slist *curl_headers = NULL;
  int i;
  for (i = 0; i < num_headers; ++i) {
    curl_headers = curl_slist_append(curl_headers, headers[i]);
  }
  wg_curl_write_ctx_t write_ctx = {
     .data = response_buffer,
     .size = response_buffer_size
  };

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, collectd_useragent);
  if (curl_headers != NULL) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
  }
  if (body != NULL) {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  }
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &wg_curl_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_ctx);
  // http://stackoverflow.com/questions/9191668/error-longjmp-causes-uninitialized-stack-frame
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

  int result = -1;  // Pessimistically assume error.

  int curl_result = curl_easy_perform(curl);
  if (curl_result != CURLE_OK) {
    WARNING("write_gcm: curl_easy_perform() failed: %s",
            curl_easy_strerror(curl_result));
    goto leave;
  }

  write_ctx.data[0] = 0;
  WARNING("This is the result from curl: %s", response_buffer);
  if (write_ctx.size < 2) {
    WARNING("write_gcm: The buffer overflowed.");
    goto leave;
  }

  result = 0;  // Success!

 leave:
  curl_slist_free_all(curl_headers);
  curl_easy_cleanup(curl);
  return result;
}

static size_t wg_curl_write_callback(char *ptr, size_t size, size_t nmemb,
                                     void *userdata) {
  wg_curl_write_ctx_t *ctx = userdata;
  if (ctx->size == 0) {
    return 0;
  }
  size_t requested_bytes = size * nmemb;
  size_t actual_bytes = requested_bytes;
  if (actual_bytes >= ctx->size) {
    actual_bytes = ctx->size - 1;
  }
  memcpy(ctx->data, ptr, actual_bytes);
  ctx->data += actual_bytes;
  ctx->size -= actual_bytes;

  // We lie about the number of bytes successfully transferred in order to
  // prevent curl from returning an error to our caller. Our caller is keeping
  // track of buffer consumption so it will independently know if the buffer
  // filled up; the only errors it wants to hear about from curl are the more
  // catastrophic ones.
  return requested_bytes;
}

//==============================================================================
//==============================================================================
//==============================================================================
//==============================================================================
// OAuth2 submodule.
//
// The main method in this module is wg_oauth2_get_auth_header(). The job of
// this method is to provide an authorization token for use in API calls.
// The value returned is preformatted for the caller's as an HTTP header in the
// following form:
// Authorization: Bearer ${access_token}
//
// There are two approaches the code takes in order to get ${access_token}.
// The easy route is to just ask the metadata server for a token.
// The harder route is to format and sign a request to the OAuth2 server and get
// a token that way.
// Which approach we take depends on the value of 'cred_ctx'. If it is NULL
// (i.e. if there are no user-supplied credentials), then we try the easy route.
// Otherwise we do the harder route.
//
// The reason we don't always do the easy case unconditionally is that the
// metadata server may not always be able to provide an auth token. Since you
// cannot add scopes to an existing VM, some people may want to go the harder
// route instead.
//
// Following is a detailed explanation of the easy route and the harder route.
//
//
// THE EASY ROUTE
//
// Make a GET request to the metadata server at the following URL:
// http://169.254.169.254/computeMetadata/v1beta1/instance/service-accounts/default/token
//
// If our call is successful, the server will respond with a json object looking
// like this:
// {
//  "access_token" : $THE_ACCESS_TOKEN
//  "token_type" : "Bearer",
//  "expires_in" : 3600
// }
//
// We extract $THE_ACCESS_TOKEN from the JSON response then insert it into an
// HTTP header string for the caller's convenience. That header string looks
// like this:
// Authorization: Bearer $THE_ACCESS_TOKEN
//
// We return this string (owned by caller) on success. Upon failure, we return
// NULL.
//
//
// THE HARDER ROUTE
//
// The algorithm used here is described in
// https://developers.google.com/identity/protocols/OAuth2ServiceAccount
// in the section "Preparing to make an authorized API call", under the tab
// "HTTP/Rest".
//
// There is more detail in the documentation, but what it boils down to is this:
//
// Make a POST request to https://www.googleapis.com/oauth2/v3/token
// with the body
// grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=$JWT_HEADER.$CLAIM_SET.$SIGNATURE
//
// The trailing part of that body has three variables that need to be expanded.
// Namely, $JWT_HEADER, $CLAIM_SET, and $SIGNATURE, separated by periods.
//
// $JWT_HEADER is the base64url encoding of this constant JSON record:
// {"alg":"RS256","typ":"JWT"}
// Because this header is constant, its base64url encoding is also constant,
// and can be hardcoded as:
// eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
//
// $CLAIM_SET is a base64url encoding of a JSON object with five fields:
// iss, scope, aud, exp, and iat.
// iss: Service account email. We get this from user in the config file.
// scope: Basically the requested scope (e.g. "permissions") for the token. For
//   our purposes, this is the constant string
//   "https://www.googleapis.com/auth/monitoring".
// aud: Assertion target. Since we are asking for an access token, this is the
//   constant string "https://www.googleapis.com/oauth2/v3/token". This is the
//   same as the URL we are posting to.
// iat: Time of the assertion (i.e. now) in units of "seconds from Unix epoch".
// exp: Expiration of assertion. For us this is 'iat' + 3600 seconds.
//
// $SIGNATURE is the base64url encoding of the signature of the string
// $JWT_HEADER.$CLAIM_SET
// where $JWT_HEADER and $CLAIM_SET are defined as above. Note that they are
// separated by the period character. The signature algorithm used should be
// SHA-256. The private key used to sign the data comes from the user. The
// private key to use is the one associated with the service account email
// address (i.e. the email address specified in the 'iss' field above).
//
// If our call is successful, the result will be the same as indicated above
// in the section entitled "THE EASY ROUTE".
//
//
// EXAMPLE USAGE
//
// char auth_header[256];
// if (wg_oauth2_get_auth_header(auth_header, sizeof(auth_header),
//                               oauth2_ctx, credential_ctx) != 0) {
//   return -1; // error
// }
// do_a_http_post_with(auth_header);
//
//==============================================================================
//==============================================================================
//==============================================================================

// Opaque to callers.
typedef struct oauth2_ctx_s oauth2_ctx_t;

// Either creates a new "Authorization: Bearer XXX" header or returns a cached
// one. Caller owns the returned string. Returns NULL if there is an error.
static int wg_oauth2_get_auth_header(char *result, size_t result_size,
                                     oauth2_ctx_t *ctx,
                                     const credential_ctx_t *cred_ctx);

// Allocate and construct an oauth2_ctx_t.
static oauth2_ctx_t *wg_oauth2_cxt_create();
// Deallocate and destroy an oauth2_ctx_t.
static void wg_oauth2_ctx_destroy(oauth2_ctx_t *);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
struct oauth2_ctx_s {
  pthread_mutex_t mutex;
  cdtime_t token_expire_time;
  char auth_header[256];
};

static int wg_oauth2_get_auth_header_nolock(oauth2_ctx_t *ctx,
    const credential_ctx_t *cred_ctx);

static int wg_oauth2_sign(unsigned char *signature, size_t sig_capacity,
                          unsigned int *actual_sig_size,
                          const char *buffer, size_t size, EVP_PKEY *pkey);

static void wg_oauth2_base64url_encode(char **buffer, size_t *buffer_size,
                                       const unsigned char *source,
                                       size_t source_size);

static int wg_oauth2_parse_result(char **result_buffer, size_t *result_size,
                                  int *expires_in, const char *json);

static int wg_oauth2_talk_to_server_and_store_result(oauth2_ctx_t *ctx,
    const char *url, const char *body, const char **headers, int num_headers,
    cdtime_t now);

static int wg_oauth2_get_auth_header(char *result, size_t result_size,
    oauth2_ctx_t *ctx, const credential_ctx_t *cred_ctx) {
  // Do the whole operation under lock so that there are no races with regard
  // to the token, we don't spam the server, etc.
  pthread_mutex_lock(&ctx->mutex);
  int error = wg_oauth2_get_auth_header_nolock(ctx, cred_ctx);
  if (error == 0) {
    sstrncpy(result, ctx->auth_header, result_size);
  }
  pthread_mutex_unlock(&ctx->mutex);
  return error;
}

static int wg_oauth2_get_auth_header_nolock(oauth2_ctx_t *ctx,
    const credential_ctx_t *cred_ctx) {
  cdtime_t now = cdtime();
  // Try to reuse an existing token. We build in a minute of slack in order to
  // avoid timing problems (clock skew, races, etc).
  if (ctx->token_expire_time > now + TIME_T_TO_CDTIME_T(60)) {
    // Token still valid!
    return 0;
  }
  // Retire the old token.
  ctx->token_expire_time = 0;
  ctx->auth_header[0] = 0;

  // If there are no user-supplied credentials, try to get the token from the
  // metadata server. This is THE EASY ROUTE as described in the documentation
  // for this method.
  if (cred_ctx == NULL) {
    INFO("write_gcm: Asking metadata server for auth token");
    return wg_oauth2_talk_to_server_and_store_result(ctx,
        metadata_fetch_auth_token, NULL, NULL, 0, now);
  }

  // If there are user-supplied credentials, format and sign a request to the
  // OAuth2 server. This is THE HARDER ROUTE as described in the documentation
  // for this submodule. This involves posting a body to a URL. The URL is
  // constant. The body needs to be constructed as described
  // in the comments for this submodule.
  const char *url = "https://www.googleapis.com/oauth2/v3/token";

  char body[2048];  // Should be big enough.
  char *bptr = body;
  size_t bsize = sizeof(body);

  bufprintf(&bptr, &bsize, "%s",
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
            "&assertion=");

  // Save a pointer to the start of the jwt_header because we will need to
  // sign $JWT_HEADER.$CLAIM_SET shortly.
  const char *jwt_header_begin = bptr;

  // The body has three variables that need to be filled in: jwt_header,
  // claim_set, and signature.

  // 'jwt_header' is easy. It is the base64url encoding of
  // {"alg":"RS256","typ":"JWT"}
  // which is eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
  // In addition, we're going to need a . separator shortly, so we add it now.
  bufprintf(&bptr, &bsize, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.");

  // Build 'claim_set' and append its base64url encoding.
  {
    char claim_set[1024];
    unsigned long long iat = CDTIME_T_TO_TIME_T(now);
    unsigned long long exp = iat + 3600;  // + 1 hour.

    int result = snprintf(
        claim_set, sizeof(claim_set),
        "{"
        "\"iss\": \"%s\","
        "\"scope\": \"https://www.googleapis.com/auth/monitoring\","
        "\"aud\": \"%s\","
        "\"iat\": %llu,"
        "\"exp\": %llu"
        "}",
        cred_ctx->email,
        url,
        iat,
        exp);
    if (result < 0 || result >= sizeof(claim_set)) {
      ERROR("write_gcm: Error building claim_set.");
      return -1;
    }
    wg_oauth2_base64url_encode(&bptr, &bsize,
                               (unsigned char*)claim_set, result);
  }

  // Sign the bytes in the buffer that are in the range [jtw_header_start, bptr)
  // Referring to the above documentation, this refers to the part of the body
  // consisting of $JWT_HEADER.$CLAIM_SET
  {
    unsigned char signature[1024];
    unsigned int actual_sig_size;
    if (wg_oauth2_sign(signature, sizeof(signature), &actual_sig_size,
                       jwt_header_begin, bptr - jwt_header_begin,
                       cred_ctx->private_key) != 0) {
      ERROR("write_gcm: Can't sign.");
      return -1;
    }

    // Now that we have the signature, append a '.' and the base64url encoding
    // of 'signature' to the buffer.
    bufprintf(&bptr, &bsize, ".");
    wg_oauth2_base64url_encode(&bptr, &bsize, signature, actual_sig_size);
  }

  // Before using the buffer, check for overflow or error.
  if (bsize < 2) {
    ERROR("write_gcm: Buffer overflow or error while building oauth2 body");
    return -1;
  }
  return wg_oauth2_talk_to_server_and_store_result(ctx, url, body, NULL, 0,
      now);
}

static int wg_oauth2_talk_to_server_and_store_result(oauth2_ctx_t *ctx,
    const char *url, const char *body, const char **headers, int num_headers,
    cdtime_t now) {
  char response[2048];
  if (wg_curl_get_or_post(response, sizeof(response), url, body,
      headers, num_headers) != 0) {
    return -1;
  }
  DEBUG("I have a response which looks like this: %s", response);

  // Fill ctx->auth_header with the string "Authorization: Bearer $TOKEN"
  char *resultp = ctx->auth_header;
  size_t result_size = sizeof(ctx->auth_header);
  bufprintf(&resultp, &result_size, "Authorization: Bearer ");
  int expires_in;
  if (wg_oauth2_parse_result(&resultp, &result_size, &expires_in,
                             response) != 0) {
    ERROR("write_gcm: wg_oauth2_parse_result failed");
    return -1;
  }

  if (result_size < 2) {
    ERROR("write_gcm: Error or buffer overflow when building auth_header");
    return -1;
  }
  ctx->token_expire_time = now + TIME_T_TO_CDTIME_T(expires_in);
  return 0;
}

static int wg_oauth2_sign(unsigned char *signature, size_t sig_capacity,
                          unsigned int *actual_sig_size,
                          const char *buffer, size_t size, EVP_PKEY *pkey) {
  if (sig_capacity < EVP_PKEY_size(pkey)) {
    ERROR("write_gcm: signature buffer not big enough.");
    return -1;
  }
  EVP_MD_CTX ctx;
  EVP_SignInit(&ctx, EVP_sha256());

  char err_buf[1024];
  if (EVP_SignUpdate(&ctx, buffer, size) == 0) {
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    ERROR("write_gcm: EVP_SignUpdate failed: %s", err_buf);
    EVP_MD_CTX_cleanup(&ctx);
    return -1;
  }

  if (EVP_SignFinal(&ctx, signature, actual_sig_size, pkey) == 0) {
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    ERROR ("write_gcm: EVP_SignFinal failed: %s", err_buf);
    EVP_MD_CTX_cleanup(&ctx);
    return -1;
  }
  if (EVP_MD_CTX_cleanup(&ctx) == 0) {
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    ERROR ("write_gcm: EVP_MD_CTX_cleanup failed: %s", err_buf);
    return -1;
  }
  return 0;
}

static void wg_oauth2_base64url_encode(char **buffer, size_t *buffer_size,
                                       const unsigned char *source,
                                       size_t source_size) {
  const char *codes =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  size_t i;
  unsigned int code_buffer = 0;
  int code_buffer_size = 0;
  for (i = 0; i < source_size; ++i) {
    code_buffer = (code_buffer << 8) | source[i];  // Add 8 bits to the right.
    code_buffer_size += 8;
    do {
      // Remove six bits from the left (there will never be more than 12).
      unsigned int next_code = (code_buffer >> (code_buffer_size - 6)) & 0x3f;
      code_buffer_size -= 6;
      // This is not fast, but we don't care much about performance here.
      bufprintf(buffer, buffer_size, "%c", codes[next_code]);
    } while (code_buffer_size >= 6);
  }
  // Flush code buffer. Our server does not want the trailing = or == characters
  // normally present in base64 encoding.
  if (code_buffer_size != 0) {
    code_buffer = (code_buffer << 8);
    code_buffer_size += 8;
    unsigned int next_code = (code_buffer >> (code_buffer_size - 6)) & 0x3f;
    bufprintf(buffer, buffer_size, "%c", codes[next_code]);
  }
}

static int wg_oauth2_parse_result(char **result_buffer, size_t *result_size,
                                  int *expires_in, const char *json) {
  char errbuf[1024];
  yajl_val root = yajl_tree_parse(json, errbuf, sizeof(errbuf));
  if (root == NULL) {
    ERROR("write_gcm: wg_parse_oauth2_result: parse error %s", errbuf);
    return -1;
  }

  const char *token_path[] = {"access_token", NULL};
  const char *expire_path[] = {"expires_in", NULL};
  yajl_val token_val = yajl_tree_get(root, token_path, yajl_t_string);
  yajl_val expire_val = yajl_tree_get(root, expire_path, yajl_t_number);
  if (token_val == NULL || expire_val == NULL) {
    ERROR("write_gcm: wg_parse_oauth2_result: missing one or both of "
        "'access_token' or 'expires_in' fields in response from server.");
    yajl_tree_free(root);
    return -1;
  }

  bufprintf(result_buffer, result_size, "%s", YAJL_GET_STRING(token_val));
  *expires_in = YAJL_GET_INTEGER(expire_val);
  yajl_tree_free(root);
  return 0;
}

static oauth2_ctx_t *wg_oauth2_cxt_create() {
  oauth2_ctx_t *ctx = calloc(1, sizeof(*ctx));
  if (ctx == NULL) {
    ERROR("write_gcm: wg_oauth2_cxt_create: calloc failed.");
    return NULL;
  }
  pthread_mutex_init(&ctx->mutex, NULL);
  return ctx;
}

static void wg_oauth2_ctx_destroy(oauth2_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  pthread_mutex_destroy(&ctx->mutex);
  sfree(ctx);
}

//==============================================================================
//==============================================================================
//==============================================================================
// Submodule for holding the monitored data while we are waiting to send it
// upstream.
//==============================================================================
//==============================================================================
//==============================================================================

// The element type of the 'values' array of wg_payload_t, defined below.
typedef struct {
  char name[DATA_MAX_NAME_LEN];
  int ds_type;
  value_t val;
} wg_payload_value_t;

// This variable-length structure is our digested version of the collectd
// payload, in a form more suitable for sending to the upstream server. The
// actual number of elements in the 'values' array is stored in num_values.
typedef struct wg_payload_s {
  struct wg_payload_s *next;
  char host[DATA_MAX_NAME_LEN];
  char plugin[DATA_MAX_NAME_LEN];
  char plugin_instance[DATA_MAX_NAME_LEN];
  char type[DATA_MAX_NAME_LEN];
  char type_instance[DATA_MAX_NAME_LEN];
  cdtime_t start_time;
  cdtime_t end_time;

  int num_values;
  wg_payload_value_t values[1];  // Actually, variable-length.
} wg_payload_t;

// For derivative values, we need to remember certain information so that we
// can both properly adjust the 'start_time' field of wg_payload_value_t as well
// as adjusting the value itself. For a given key, the information we keep
// track of is:
// - start_time
// - baseline_value
// - previous_value
//
// Basically the algorithm is the following:
// For a given key, the first time a value is ever seen, it establishes the
// start time, baseline, and previous value. Furthermore, the value is absorbed
// (not sent upstream).
//
// For subsequent values on that key:
// - If the value is >= the previous value, then adjust value by subtracting
//   baseline and set previous value = this value.
// - Otherwise (if the value is less than the previous value), reset start time,
//   set baseline to zero, and set and set previous value to this value.
//   Note that unlike the initial case, this value can be sent upstream (does
//   not need to be absorbed).
typedef struct {
  char host[DATA_MAX_NAME_LEN];
  char plugin[DATA_MAX_NAME_LEN];
  char plugin_instance[DATA_MAX_NAME_LEN];
  char type[DATA_MAX_NAME_LEN];
  char type_instance[DATA_MAX_NAME_LEN];
} deriv_tracker_key_t;

// See the comments above deriv_tracker_key_t.
typedef struct {
  cdtime_t start_time;
  derive_t *baselines;
  derive_t *previous;
} deriv_tracker_value_t;

static wg_payload_t *wg_payload_create(const data_set_t *ds,
    const value_list_t *vl);
static void wg_payload_destroy(wg_payload_t *list);

static deriv_tracker_key_t *wg_deriv_tracker_key_create(const char *host,
    const char *plugin, const char *plugin_instance, const char *type,
    const char *type_instance);
static void wg_deriv_tracker_key_destroy(deriv_tracker_key_t *key);

static deriv_tracker_value_t *wg_deriv_tracker_value_create(int num_values);
static void wg_deriv_tracker_value_destroy(deriv_tracker_value_t *value);

static void wg_deriv_tree_destroy(c_avl_tree_t *tree);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------

static wg_payload_t *wg_payload_create(const data_set_t *ds,
    const value_list_t *vl) {
  size_t size = sizeof(wg_payload_t) +
      (vl->values_len - 1) * sizeof(wg_payload_value_t);
  wg_payload_t *res = calloc(1, size);
  if (res == NULL) {
    ERROR("write_gcm: wg_payload_create: calloc failed");
    return NULL;
  }
  res->next = NULL;
  strncpy(res->host, vl->host, sizeof(res->host));
  strncpy(res->plugin, vl->plugin, sizeof(res->plugin));
  strncpy(res->plugin_instance, vl->plugin_instance,
      sizeof(res->plugin_instance));
  strncpy(res->type, vl->type, sizeof(res->type));
  strncpy(res->type_instance, vl->type_instance, sizeof(res->type_instance));
  res->start_time = vl->time;
  res->end_time = vl->time;
  res->num_values = vl->values_len;

  assert(ds->ds_num == vl->values_len);
  int i;
  for (i = 0; i < ds->ds_num; ++i) {
    data_source_t *src = &ds->ds[i];
    wg_payload_value_t *dst = &res->values[i];
    strncpy(dst->name, src->name, sizeof(dst->name));
    dst->ds_type = src->type;
    dst->val = vl->values[i];
  }
  return res;
}

static void wg_payload_destroy(wg_payload_t *list) {
  while (list != NULL) {
    wg_payload_t *next = list->next;
    sfree(list);
    list = next;
  }
}

static deriv_tracker_key_t *wg_deriv_tracker_key_create(const char *host,
    const char *plugin, const char *plugin_instance, const char *type,
    const char *type_instance) {
  deriv_tracker_key_t *res = calloc(1, sizeof(*res));
  if (res == NULL) {
    ERROR("write_gcm: wg_deriv_tracker_key_create: calloc failed");
    return NULL;
  }
  strncpy(res->host, host, sizeof(res->host));
  strncpy(res->plugin, plugin, sizeof(res->plugin));
  strncpy(res->plugin_instance, plugin_instance, sizeof(res->plugin_instance));
  strncpy(res->type, type, sizeof(res->type));
  strncpy(res->type_instance, type_instance, sizeof(res->type_instance));
  return res;
}

static void wg_deriv_tracker_key_destroy(deriv_tracker_key_t *key) {
  sfree(key);
}

static deriv_tracker_value_t *wg_deriv_tracker_value_create(int num_values) {
  deriv_tracker_value_t *result = calloc(1, sizeof(*result));
  if (result == NULL) {
    ERROR("write_gcm: wg_deriv_tracker_value_create: calloc failed");
    return NULL;
  }
  result->baselines = calloc(num_values, sizeof(derive_t));
  if (result->baselines == NULL) {
    ERROR("write_gcm: wg_deriv_tracker_value_create: calloc failed");
    return NULL;
  }
  result->previous = calloc(num_values, sizeof(derive_t));
  if (result->previous == NULL) {
    ERROR("write_gcm: wg_deriv_tracker_value_create: calloc failed");
    return NULL;
  }
  return result;
}

static void wg_deriv_tracker_value_destroy(deriv_tracker_value_t *value) {
  if (value == NULL) {
    return;
  }
  sfree(value->previous);
  sfree(value->baselines);
  sfree(value);
}

// The comparison function for deriv_tracker_key_t.
static int wg_deriv_tracker_key_compare(const void *lhs, const void *rhs);

static c_avl_tree_t *wg_been_here_tree_create() {
  return c_avl_create(&wg_deriv_tracker_key_compare);
}

static void wg_been_here_tree_destroy(c_avl_tree_t *tree) {
  if (tree == NULL) {
    return;
  }
  void *key;
  void *ignored;
  while (c_avl_pick(tree, &key, &ignored) == 0) {
    wg_deriv_tracker_key_destroy((deriv_tracker_key_t*)key);
    assert(ignored == NULL);
  }
  c_avl_destroy(tree);
}

static c_avl_tree_t *wg_deriv_tree_create() {
  return c_avl_create(&wg_deriv_tracker_key_compare);
}

static void wg_deriv_tree_destroy(c_avl_tree_t *tree) {
  if (tree == NULL) {
    return;
  }
  void *key;
  void *value;
  while (c_avl_pick(tree, &key, &value) == 0) {
    wg_deriv_tracker_key_destroy((deriv_tracker_key_t*)key);
    wg_deriv_tracker_value_destroy((deriv_tracker_value_t*)value);
  }
  c_avl_destroy(tree);
}

static int wg_deriv_tracker_key_compare(const void *lhs, const void *rhs) {
  const deriv_tracker_key_t *l = lhs;
  const deriv_tracker_key_t *r = rhs;
  int difference;
  difference = strcmp(l->host, r->host);
  if (difference != 0) return difference;
  difference = strcmp(l->plugin, r->plugin);
  if (difference != 0) return difference;
  difference = strcmp(l->plugin_instance, r->plugin_instance);
  if (difference != 0) return difference;
  difference = strcmp(l->type, r->type);
  if (difference != 0) return difference;
  difference = strcmp(l->type_instance, r->type_instance);
  return difference;
}


//==============================================================================
//==============================================================================
//==============================================================================
// "Configbuilder" submodule. This holds the info extracted from the config
// file.
//==============================================================================
//==============================================================================
//==============================================================================
typedef struct {
  // "gcp" or "aws".
  // "gcp" expects project_id, instance_id, and zone (or will fetch them from
  // the metadata server.
  // "aws" expects project_id, instance_id, region, and account_id (or will
  // fetch them from the metadata server).
  char *cloud_provider;
  char *project_id;
  char *instance_id;
  char *zone;
  char *region;
  char *account_id;
  char *email;
  char *key_file;
  char *passphrase;
  char *json_log_file;
  char *agent_translation_service_format_string;
  _Bool pretty_print_json;
} wg_configbuilder_t;

// Builds a wg_configbuilder_t out of a config node.
static wg_configbuilder_t *wg_configbuilder_create(oconfig_item_t *ci);
static void wg_configbuilder_destroy(wg_configbuilder_t *cb);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static wg_configbuilder_t *wg_configbuilder_create(oconfig_item_t *ci) {
  // Items to free on error.
  char *pretty_print_json = NULL;
  wg_configbuilder_t *cb = NULL;

  cb = calloc(1, sizeof(*cb));
  if (cb == NULL) {
    ERROR("write_gcm: wg_configbuilder_create. calloc failed.");
    goto error;
  }

  const char *keys[] = {
      "CloudProvider",
      "Project",
      "Instance",
      "Zone",
      "Region",
      "Account",
      "Email",
      "PrivateKeyFile",
      "PrivateKeyPass",
      "JSONLogFile",
      "AgentTranslationServiceFormatString",
      "PrettyPrintJSON"
  };
  char **locations[] = {
      &cb->cloud_provider,
      &cb->project_id,
      &cb->instance_id,
      &cb->zone,
      &cb->region,
      &cb->account_id,
      &cb->email,
      &cb->key_file,
      &cb->passphrase,
      &cb->json_log_file,
      &cb->agent_translation_service_format_string,
      &pretty_print_json
  };

  assert(STATIC_ARRAY_SIZE(keys) == STATIC_ARRAY_SIZE(locations));
  int parse_errors = 0;
  int c, k;
  for (c = 0; c < ci->children_num; ++c) {
    oconfig_item_t *child = &ci->children[c];
    for (k = 0; k < STATIC_ARRAY_SIZE(keys); ++k) {
      if (strcasecmp(child->key, keys[k]) == 0) {
        if (cf_util_get_string(child, locations[k]) != 0) {
          ERROR("write_gcm: cf_util_get_string failed for key %s",
                child->key);
          ++parse_errors;
        }
        break;
      }
    }
    if (k == STATIC_ARRAY_SIZE(keys)) {
      ERROR("write_gcm: Invalid configuration option: %s.", child->key);
      ++parse_errors;
    }
  }

  if (parse_errors > 0) {
    ERROR("write_gcm: There were %d parse errors reading config file.",
          parse_errors);
    goto error;
  }

  if (pretty_print_json != NULL && strcasecmp(pretty_print_json, "yes") == 0) {
    cb->pretty_print_json = 1;
  }

  // Either all or none of 'email', 'key_file', and 'passphrase' must be set.
  int num_set = 0;
  if (cb->email != NULL) {
    ++num_set;
  }
  if (cb->key_file != NULL) {
    ++num_set;
  }
  if (cb->passphrase != NULL) {
    ++num_set;
  }
  if (num_set != 0 && num_set != 3) {
    ERROR("write_gcm: Error reading configuration. "
        "Either all of Email, PrivateKeyFile, and PrivateKeyPass must be set, "
        "or none of them must be set. However, the provided config file "
        "set %d of them.", num_set);
    goto error;
  }

  // Success!
  return cb;

 error:
  sfree(pretty_print_json);
  wg_configbuilder_destroy(cb);
  return NULL;
}

//==============================================================================
//==============================================================================
//==============================================================================
// "Monitored resource" submodule.
//==============================================================================
//==============================================================================
//==============================================================================
typedef struct {
  // e.g. "gce_instance" or "aws_instance".
  char *type;

  char *project_id;

  // The labels that are present depend on 'type'.
  // If 'type' is "gce_instance", then typically the following labels will be
  // present:
  // instance_id - the numeric instance id
  // zone - the zone, e.g. us-central1-a
  //
  // If 'type' is "aws_instance", then typically the following labels will be
  // present:
  // account_id - the GCP account id
  // instance_id - the AWS instance id
  // region - the AWS region
  int num_labels;
  char **keys;
  char **values;
} monitored_resource_t;

static monitored_resource_t *wg_monitored_resource_create(
    const wg_configbuilder_t *cb);
static void wg_monitored_resource_destroy(monitored_resource_t *resource);

static int wg_monitored_resource_populate_for_gcp(
    monitored_resource_t *resource, const wg_configbuilder_t *cb);
static int wg_monitored_resource_populate_for_aws(
    monitored_resource_t *resource, const wg_configbuilder_t *cb);
static char *wg_configbuilder_get_from_gcp_metadata_server(
    const char *resource);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static monitored_resource_t *wg_monitored_resource_create(
    const wg_configbuilder_t *cb) {
  monitored_resource_t *resource = calloc(1, sizeof(*resource));
  if (resource == NULL) {
    ERROR("write_gcm: wg_monitored_resource_create: calloc failed.");
    return NULL;
  }
  const char *cloud_provider_to_use = cb->cloud_provider != NULL ?
      cb->cloud_provider : "gcp";
  int result;
  if (strcmp(cloud_provider_to_use, "gcp") == 0) {
    result = wg_monitored_resource_populate_for_gcp(resource, cb);
  } else if (strcmp(cloud_provider_to_use, "aws") == 0) {
    result = wg_monitored_resource_populate_for_aws(resource, cb);
  } else {
    WARNING("Cloud provider '%s' not recognized.", cloud_provider_to_use);
    result = 0;
  }
  if (result != 0) {
    ERROR("write_gcm: failed to populate cloud provider-specific information");
    wg_monitored_resource_destroy(resource);
    return NULL;
  }
  return resource;
}

static void wg_monitored_resource_destroy(monitored_resource_t *resource) {
  if (resource == NULL) {
    return;
  }
  int i;
  for (i = 0; i < resource->num_labels; ++i) {
    sfree(resource->values[i]);
    sfree(resource->keys[i]);
  }
  sfree(resource->values);
  sfree(resource->keys);
  sfree(resource->project_id);
  sfree(resource->type);
  sfree(resource);
}

static int wg_monitored_resource_populate_for_gcp(
    monitored_resource_t *resource, const wg_configbuilder_t *cb) {
  char *project_id_to_use = sstrdup(cb->project_id);
  char *instance_id_to_use = sstrdup(cb->instance_id);
  char *zone_to_use = sstrdup(cb->zone);

  // For items not specified in the config file, try to get them from the
  // metadata server.
  if (project_id_to_use == NULL) {
    // This gets the string id of the project (not the numeric id).
    project_id_to_use =
        wg_configbuilder_get_from_gcp_metadata_server("project/project-id");
    if (project_id_to_use == NULL) {
      ERROR("write_gcm: Can't get project ID from GCP metadata server "
          " (and not specified in the config file).");
      goto error;
    }
  }

  if (instance_id_to_use == NULL) {
    // This gets the numeric instance id.
    instance_id_to_use =
        wg_configbuilder_get_from_gcp_metadata_server("instance/id");
    if (instance_id_to_use == NULL) {
      ERROR("write_gcm: Can't get instance ID from GCP metadata server "
          " (and not specified in the config file).");
      goto error;
    }
  }

  if (zone_to_use == NULL) {
    // This gets the zone.
    char *verbose_zone =
        wg_configbuilder_get_from_gcp_metadata_server("instance/zone");
    if (verbose_zone == NULL) {
      ERROR("write_gcm: Can't get zone ID from GCP metadata server "
          " (and not specified in the config file).");
      goto error;
    }
    // The zone comes back as projects/${numeric-id}/zones/${zone}
    // where ${zone} is e.g. us-central1-a

    const char *last_slash = strrchr(verbose_zone, '/');
    if (last_slash == NULL) {
      ERROR("write_gcm: Failed to parse zone.");
      sfree(verbose_zone);
      goto error;
    }

    zone_to_use = sstrdup(last_slash + 1);
    if (zone_to_use == NULL) {
      ERROR("write_gcm: wg_monitored_resource_populate_for_gcp: "
          "sstrdup failed.");
      goto error;
    }
  }
  resource->type = sstrdup("gce_instance");
  resource->project_id = project_id_to_use;
  resource->num_labels = 2;
  resource->keys = calloc(2, sizeof(resource->keys[0]));
  resource->values = calloc(2, sizeof(resource->keys[0]));
  resource->keys[0] = sstrdup("instance_id");
  resource->keys[1] = sstrdup("zone");
  resource->values[0] = instance_id_to_use;
  resource->values[1] = zone_to_use;
  return 0;

 error:
  sfree(zone_to_use);
  sfree(instance_id_to_use);
  sfree(project_id_to_use);
  return -1;
}

static int wg_monitored_resource_populate_for_aws(
    monitored_resource_t *resource, const wg_configbuilder_t *cb) {
  ERROR("write_gcm: wg_monitored_resource_populate_for_aws: not implemented.");
  return -1;
}

static char *wg_configbuilder_get_from_gcp_metadata_server(
    const char *resource) {
  char url[256];
  int result = snprintf(url, sizeof(url), "%s%s", gcp_metadata_server,
      resource);
  if (result < 0 || result >= sizeof(url)) {
    ERROR("write_gcm: buffer overflowed while building url");
    return NULL;
  }

  char buffer[2048];
  const char *headers[] = { google_metadata_header };
  if (wg_curl_get_or_post(buffer, sizeof(buffer), url, NULL,
      headers, STATIC_ARRAY_SIZE(headers)) != 0) {
    ERROR("write_gcm: wg_configbuilder_get_from_gcp_metadata_server failed "
        "while fetching %s", url);
    return NULL;
  }
  return sstrdup(buffer);
}

//==============================================================================
//==============================================================================
//==============================================================================
// Context submodule. Defines the master wg_context_t object, which holds the
// context for this plugin.
//==============================================================================
//==============================================================================
//==============================================================================
typedef struct {
  pthread_mutex_t mutex;
  // All of the below are guarded by 'mutex'.
  pthread_cond_t cond;
  wg_payload_t *head;
  wg_payload_t *tail;
  size_t size;
  int request_flush;
  int request_terminate;
} wg_queue_t;

typedef struct {
  monitored_resource_t *resource;
  char *agent_translation_service_url;
  credential_ctx_t *cred_ctx;
  oauth2_ctx_t *oauth2_ctx;
  pthread_t queue_thread;
  wg_queue_t *queue;
  FILE *json_log_file;
  _Bool pretty_print_json;
} wg_context_t;

static wg_context_t *wg_context_create(const wg_configbuilder_t *cb);
static void wg_context_destroy(wg_context_t *context);

static wg_queue_t *wg_queue_create();
static void wg_queue_destroy(wg_queue_t *queue);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static wg_context_t *wg_context_create(const wg_configbuilder_t *cb) {
  wg_context_t *ctx = calloc(1, sizeof(*ctx));
  if (ctx == NULL) {
    ERROR("wg_context_create: calloc failed.");
    return NULL;
  }

  // Create the subcontext holding various pieces of server information.
  ctx->resource = wg_monitored_resource_create(cb);
  if (ctx->resource == NULL) {
    ERROR("write_gcm: wg_monitored_resource_create failed.");
    wg_context_destroy(ctx);
    return NULL;
  }

  const char *format_string_to_use =
      cb->agent_translation_service_format_string != NULL ?
          cb->agent_translation_service_format_string :
          agent_translation_service_default_format_string;

  char url[512];  // Big enough?
  int result = snprintf(url, sizeof(url), format_string_to_use,
      ctx->resource->project_id);
  if (result < 0 || result >= sizeof(url)) {
    ERROR("write_gcm: overflowed url buffer");
    return NULL;
  }
  ctx->agent_translation_service_url = sstrdup(url);

  // Optionally create the subcontext holding the service account credentials.
  if (cb->email != NULL && cb->key_file != NULL && cb->passphrase != NULL) {
    ctx->cred_ctx = wg_credential_ctx_create(cb->email, cb->key_file,
        cb->passphrase);
    if (ctx->cred_ctx == NULL) {
      ERROR("write_gcm: wg_credential_context_create failed.");
      wg_context_destroy(ctx);
      return NULL;
    }
  }

  // Create the subcontext holding the oauth2 state.
  ctx->oauth2_ctx = wg_oauth2_cxt_create();
  if (ctx->oauth2_ctx == NULL) {
    ERROR("write_gcm: wg_oauth2_context_create failed.");
    wg_context_destroy(ctx);
    return NULL;
  }

  // Create the queue context.
  ctx->queue = wg_queue_create();
  if (ctx->queue == NULL) {
    ERROR("write_gcm: wg_queue_create failed.");
    wg_context_destroy(ctx);
    return NULL;
  }

  // Open the JSON log file if requested.
  if (cb->json_log_file != NULL) {
    ctx->json_log_file = fopen(cb->json_log_file, "a");
    if (ctx->json_log_file == NULL) {
      WARNING("write_gcm: Can't open log file %s. errno is %d. Continuing.",
          cb->json_log_file, errno);
    }
  }

  ctx->pretty_print_json = cb->pretty_print_json;
  return ctx;
}

static void wg_context_destroy(wg_context_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  if (ctx->json_log_file != NULL) {
    fclose(ctx->json_log_file);
  }
  wg_queue_destroy(ctx->queue);
  wg_oauth2_ctx_destroy(ctx->oauth2_ctx);
  wg_credential_ctx_destroy(ctx->cred_ctx);
  sfree(ctx->agent_translation_service_url);
  wg_monitored_resource_destroy(ctx->resource);
  sfree(ctx);
}

static wg_queue_t *wg_queue_create() {
  wg_queue_t *queue = calloc(1, sizeof(*queue));
  if (queue == NULL) {
    ERROR("wg_queue_create: calloc failed.");
    return NULL;
  }

  // Create the mutex controlling access to the payload list and deriv tree.
  if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
    ERROR("write_gcm: pthread_mutex_init failed: errno %d", errno);
    wg_queue_destroy(queue);
    return NULL;
  }

  if (pthread_cond_init(&queue->cond, NULL) != 0) {
    ERROR("write_gcm: pthread_cond_init failed: errno %d", errno);
    wg_queue_destroy(queue);
    return NULL;
  }

  queue->head = NULL;
  queue->tail = NULL;
  queue->size = 0;
  queue->request_flush = 0;
  queue->request_terminate = 0;
  return queue;
}

static void wg_queue_destroy(wg_queue_t *queue) {
  wg_payload_destroy(queue->head);
  pthread_cond_destroy(&queue->cond);
  pthread_mutex_destroy(&queue->mutex);
}

//==============================================================================
//==============================================================================
//==============================================================================
// Build submodule for formatting the CreateCollectdTimeseriesPointsRequest.
//==============================================================================
//==============================================================================
//==============================================================================
typedef struct {
  char **buffer;
  size_t *size;
  int error;
  yajl_gen gen;
} json_ctx_t;

// Formats some or all of the data in the payload_list as a
// CreateCollectdTimeseriesPointsRequest.
// 'buffer' and 'size' are as defined in bufprintf.
// JSON_LOW_WATER_MARK is used to signal to this routine to finish things up
// and close out the message. When there are fewer than JSON_LOW_WATER_MARK
// bytes left in the buffer, the method stops adding new items to the
// 'collectdPayloads' part of the JSON message and closes things up. The purpose
// is to try to always make well-formed JSON messages, even if the incoming list
// is large. One consequence of this is that this routine is not guaranteed to
// empty out the list. Callers need to repeatedly call this routine (making
// fresh wg_json_CreateCollectdTimeseriesPointsRequest requests each
// time) until the list is exhausted.
static int wg_json_CreateCollectdTimeseriesPointsRequest(char **buffer,
    size_t *size, _Bool pretty,
    const const monitored_resource_t *monitored_resource,
    const wg_payload_t *head, const wg_payload_t **new_head);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static void wg_json_MonitoredResource(json_ctx_t *jc,
    const monitored_resource_t *resource);
static void wg_json_CollectdPayloads(json_ctx_t *jc,
    const wg_payload_t *head, const wg_payload_t **new_head);
static void wg_json_CollectdValues(json_ctx_t *jc, const wg_payload_t *element);
static void wg_json_Timestamp(json_ctx_t *jc, cdtime_t time_stamp);

static void wg_json_map_open(json_ctx_t *jc);
static void wg_json_map_close(json_ctx_t *jc);
static void wg_json_array_open(json_ctx_t *jc);
static void wg_json_array_close(json_ctx_t *jc);
static void wg_json_string(json_ctx_t *jc, const char *s);
static void wg_json_uint64(json_ctx_t *jc, uint64_t value);

static json_ctx_t *wg_json_ctx_create(char **buffer, size_t *size,
    _Bool pretty);
static void wg_json_ctx_destroy(json_ctx_t *jc);

typedef struct {
  const char *type;
  const char *value_tag;
  char value_text[128];
} fleshed_out_value_t;

static int wg_get_vl_value(int ds_type, value_t value,
    fleshed_out_value_t *fov);

// From google/monitoring/v3/agent_service.proto
// message CreateCollectdTimeSeriesRequest {
//   string name = 5;
//   google.api.MonitoredResource resource = 2;
//   string collectd_version = 3;
//   repeated CollectdPayload collectd_payloads = 4;
// }
static int wg_json_CreateCollectdTimeseriesPointsRequest(char **buffer,
    size_t *size, _Bool pretty, const monitored_resource_t *monitored_resource,
    const wg_payload_t *head, const wg_payload_t **new_head) {
  char name[256];
  int result = snprintf(name, sizeof(name), "project/%s",
      monitored_resource->project_id);
  if (result < 0 || result >= sizeof(name)) {
    ERROR("write_gcm: project_id %s doesn't fit in buffer.",
        monitored_resource->project_id);
    return -1;
  }

  json_ctx_t *jc = wg_json_ctx_create(buffer, size, pretty);
  if (jc == NULL) {
    ERROR("write_gcm: wg_json_ctx_create failed");
    return -1;
  }

  wg_json_map_open(jc);
  wg_json_string(jc, "name");
  wg_json_string(jc, name);

  wg_json_string(jc, "resource");
  wg_json_MonitoredResource(jc, monitored_resource);

  wg_json_string(jc, "collectdVersion");
  wg_json_string(jc, COLLECTD_USERAGENT);

  wg_json_string(jc, "collectdPayloads");
  wg_json_CollectdPayloads(jc, head, new_head);
  wg_json_map_close(jc);

  result = jc->error;
  wg_json_ctx_destroy(jc);
  return result;
}

// From google/api/monitored_resource.proto
// message MonitoredResource {
//   string type = 1;
//   map<string, string> labels = 2;
// }
static void wg_json_MonitoredResource(json_ctx_t *jc,
    const monitored_resource_t *resource) {
  wg_json_map_open(jc);
  // type is hardcoded to "gce_instance" for now.
  wg_json_string(jc, "type");
  wg_json_string(jc, resource->type);

  wg_json_string(jc, "labels");
  {
    wg_json_map_open(jc);
    int i;
    for (i = 0; i < resource->num_labels; ++i) {
      wg_json_string(jc, resource->keys[i]);
      wg_json_string(jc, resource->values[i]);
    }
    wg_json_map_close(jc);
  }
  wg_json_map_close(jc);
}


// Array of CollectdPayload:
// message CollectdPayload {
//   repeated CollectdValue values = 1;
//   google.protobuf.Timestamp start_time = 2;
//   google.protobuf.Timestamp end_time = 3;
//   string plugin = 4;
//   string plugin_instance = 5;
//   string type = 6;
//   string type_instance = 7;
// }
static void wg_json_CollectdPayloads(json_ctx_t *jc,
    const wg_payload_t *head, const wg_payload_t **new_head) {
  wg_json_array_open(jc);
  while (head != NULL && *jc->size >= JSON_LOW_WATER_MARK && jc->error == 0) {
    wg_json_map_open(jc);
    wg_json_string(jc, "startTime");
    wg_json_Timestamp(jc, head->start_time);

    wg_json_string(jc, "endTime");
    wg_json_Timestamp(jc, head->end_time);

    wg_json_string(jc, "plugin");
    wg_json_string(jc, head->plugin);

    wg_json_string(jc, "pluginInstance");
    wg_json_string(jc, head->plugin_instance);

    wg_json_string(jc, "type");
    wg_json_string(jc, head->type);

    wg_json_string(jc, "typeInstance");
    wg_json_string(jc, head->type_instance);

    wg_json_string(jc, "values");
    wg_json_CollectdValues(jc, head);
    wg_json_map_close(jc);

    head = head->next;
  }
  *new_head = head;
  wg_json_array_close(jc);
}

// Array of CollectdValue:
// message CollectdValue {
//   optional CollectdValueType value = 1;
//   optional CollectdDsType dataSourceType = 2;
//   optional string dataSourceName = 3;
// }
// where
// message CollectdValueType {
//   oneof value {
//     bytes unknown = 1;
//     int64 int64_value = 2;
//     uint64 uint64_value = 3;
//     double double_value = 4;
//   }
// }

static void wg_json_CollectdValues(json_ctx_t *jc,
    const wg_payload_t *element) {
  wg_json_array_open(jc);
  int i;
  for (i = 0; i < element->num_values; ++i) {
    const wg_payload_value_t *value = &element->values[i];
    fleshed_out_value_t fov;
    if (wg_get_vl_value(value->ds_type, value->val, &fov) != 0) {
      WARNING("write_gcm: wg_get_vl_value failed! Continuing.");
      continue;
    }
    wg_json_map_open(jc);

    wg_json_string(jc, "dataSourceType");
    wg_json_string(jc, fov.type);

    wg_json_string(jc, "dataSourceName");
    wg_json_string(jc, value->name);

    wg_json_string(jc, "value");
    {
      wg_json_map_open(jc);
      wg_json_string(jc, fov.value_tag);
      wg_json_string(jc, fov.value_text);
      wg_json_map_close(jc);
    }

    wg_json_map_close(jc);
  }
  wg_json_array_close(jc);
}

//message Timestamp {
//  int64 seconds = 1;
//  int32 nanos = 2;
//}
static void wg_json_Timestamp(json_ctx_t *jc, cdtime_t time_stamp) {
  uint64_t sec = CDTIME_T_TO_TIME_T(time_stamp);
  uint64_t ns = CDTIME_T_TO_NS(time_stamp % 1073741824);
  wg_json_map_open(jc);
  wg_json_string(jc, "seconds");
  wg_json_uint64(jc, sec);
  wg_json_string(jc, "nanos");
  wg_json_uint64(jc, ns);
  wg_json_map_close(jc);
}

static void wg_json_map_open(json_ctx_t *jc) {
  if (jc->error != 0) {
    return;
  }
  int result = yajl_gen_map_open(jc->gen);
  if (result != yajl_gen_status_ok) {
    ERROR("yajl_gen_map_open returned %d", result);
    jc->error = -1;
  }
}

static void wg_json_map_close(json_ctx_t *jc) {
  if (jc->error != 0) {
    return;
  }
  int result = yajl_gen_map_close(jc->gen);
  if (result != yajl_gen_status_ok) {
    ERROR("wg_json_map_close returned %d", result);
    jc->error = -1;
  }
}

static void wg_json_array_open(json_ctx_t *jc) {
  if (jc->error != 0) {
    return;
  }
  int result = yajl_gen_array_open(jc->gen);
  if (result != yajl_gen_status_ok) {
    ERROR("wg_json_array_open returned %d", result);
    jc->error = -1;
  }
}

static void wg_json_array_close(json_ctx_t *jc) {
  if (jc->error != 0) {
    return;
  }
  int result = yajl_gen_array_close(jc->gen);
  if (result != yajl_gen_status_ok) {
    ERROR("wg_json_array_close returned %d", result);
    jc->error = -1;
  }
}

static void wg_json_string(json_ctx_t *jc, const char *s) {
  if (jc->error != 0) {
    return;
  }

  if (s == NULL) {
    ERROR("write_gcm: wg_json_string passed NULL.");
    jc->error = -1;
    return;
  }

  int result = yajl_gen_string(jc->gen, (const unsigned char*)s, strlen(s));
  if (result != yajl_gen_status_ok) {
    ERROR("yajl_gen_string returned %d", result);
    jc->error = -1;
  }
}

static void wg_json_uint64(json_ctx_t *jc, uint64_t value) {
  if (jc->error != 0) {
    return;
  }
  char buffer[32];
  snprintf(buffer, sizeof(buffer), "%" PRIu64, value);
  int result = yajl_gen_number(jc->gen, buffer, strlen(buffer));
  if (result != yajl_gen_status_ok) {
    ERROR("yajl_gen_number returned %d", result);
    jc->error = -1;
  }
}

// Based on 'ds_type', extracts a value from 'value' and stringifies it,
// storing the resultant string in fov->value_text. Additionally, stores the
// type of the value as a (statically-allocated) string in fov->type, and the
// value tag as a (statically-allocated) string in fov->value_tag. Appropriate
// values for 'type_static' come from the 'CollectdDsType' enum in
// the proto definition. Appropriate values for 'value_tag_static' come from
// the 'oneof' field names in the 'CollectdValueType' proto.
static int wg_get_vl_value(int ds_type, value_t value,
    fleshed_out_value_t *fov) {
  int result;
  switch (ds_type) {
    case DS_TYPE_GAUGE:
      if (isfinite(value.gauge)) {
        fov->type = "gauge";
        fov->value_tag = "doubleValue";
        result = snprintf(fov->value_text, sizeof(fov->value_text),
            "%f", value.gauge);
        break;
      } else {
        ERROR("write_gcm: can not take infinite value");
        return -1;
      }
    case DS_TYPE_COUNTER:
      fov->type = "counter";
      fov->value_tag = "uint64Value";
      result = snprintf(fov->value_text, sizeof(fov->value_text), "%llu",
          value.counter);
      break;
    case DS_TYPE_DERIVE:
      fov->type = "derive";
      fov->value_tag = "int64Value";
      result = snprintf(fov->value_text, sizeof(fov->value_text), "%" PRIi64,
          value.derive);
      break;
    case DS_TYPE_ABSOLUTE:
      fov->type = "absolute";
      fov->value_tag = "uint64Value";
      result = snprintf(fov->value_text, sizeof(fov->value_text), "%" PRIu64,
          value.absolute);
      break;
    default:
      ERROR("write_gcm: wg_get_vl_value: Unknown ds_type %i", ds_type);
      return -1;
  }
  if (result < 0 || result >= sizeof(fov->value_text)) {
    ERROR("write_gcm: wg_get_vl_value: result exceeded buffer size");
    return -1;
  }
  return 0;
}

static void wg_yajl_dump(void *ctx, const char *str, size_t len) {
  json_ctx_t *jc = (json_ctx_t*)ctx;
  if (*jc->size == 0) {
    return;
  }
  if (len > *jc->size - 1) {
    len = *jc->size - 1;
  }
  memcpy(*jc->buffer, str, len);
  *jc->buffer += len;
  *jc->size -= len;
================================================================================
  // Terminate with NUL here because it's convenient (we don't actually need a
  // terminating NUL until we're done building the whole buffer).
  (*jc->buffer)[0] = 0;
}

static json_ctx_t *wg_json_ctx_create(char **buffer, size_t *size,
    _Bool pretty) {
  json_ctx_t *jc = calloc(1, sizeof(*jc));
  if (jc == NULL) {
    ERROR("write_gcm: can't allocate jcon_ctx_t");
    return NULL;
  }
  jc->buffer = buffer;
  jc->size = size;
  jc->error = 0;
  jc->gen = yajl_gen_alloc(NULL);
  yajl_gen_config(jc->gen, yajl_gen_beautify, pretty);
  yajl_gen_config(jc->gen, yajl_gen_validate_utf8, 1);
  yajl_gen_config(jc->gen, yajl_gen_print_callback, wg_yajl_dump, jc);
  return jc;
}

static void wg_json_ctx_destroy(json_ctx_t *jc) {
  if (jc == NULL) {
    return;
  }
  yajl_gen_free(jc->gen);
  sfree(jc);
}

//==============================================================================
//==============================================================================
//==============================================================================
// The queue processor. A separate thread that consumes the items in the queue.
//==============================================================================
//==============================================================================
//==============================================================================
void *wg_process_queue(void *arg);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
// Gets an "event" from the queue, where an event is composed of:
// - A linked list of payloads to process, and
// - A flag indicating whether the caller wants the processing thread to
//   terminate.
// Returns 0 on success, <0 on error.
int wait_next_queue_event(wg_queue_t *queue, cdtime_t last_flush_time,
    int *want_terminate, wg_payload_t **payloads);

// "Rebases" derivative items in the list against their stored values. If this
// is the first time we've seen a derivative item, store it in the map and
// remove it from the list. If the item is not a derivative item, leave it be.
// Modifies the list in place.
static int wg_rebase_cumulative_values(c_avl_tree_t *deriv_tree,
    wg_payload_t **list);

// If the item is not a derivative item, set *keep to 1 and return. Otherwise,
// if this is the first time we have seen it, set *keep to 0 and make a new
// entry in the deriv_tree. Otherwise, set *keep to 1 and adjust the item by the
// offset in the deriv_tree. Returns 0 on success, <0 on error.
static int wg_rebase_item(c_avl_tree_t *deriv_tree, wg_payload_t *payload,
    int *keep);

// Transmit the items in the list to the upstream server by first breaking them
// up into segments, where all the items in the segments have distinct keys.
// This is necessary because the upstream server rejects submissions with
// duplicate keys/labels. (why?) Returns 0 on success, <0 on error.
int wg_transmit_unique_segments(const wg_context_t *ctx, wg_payload_t *list);

// Transmit a segment of the list, where it is guaranteed that all the items
// in the list have distinct keys. Returns 0 on success, <0 on error.
static int wg_transmit_unique_segment(const wg_context_t *ctx,
    const wg_payload_t *list);

// Finds the longest prefix of the list where all the keys are unique.
// Points '*tail' at the last element of that list. If 'list' is null, *tail
// will be null. Returns 0 on successs, <0 on error.
int wg_find_unique_segment(wg_payload_t *list, wg_payload_t **tail);

// Converts the data in the list into a CreateCollectdTimeseriesPointsRequest
// message (formatted in JSON format). If successful, sets *json to point to
// the resultant buffer (owned by caller), sets *new_list, and returns 0.
// Otherwise, returns <0. If successful, it is guaranteed that at least one
// element of *list has been processed. It is intended that the caller calls
// this method repeatedly until the list has been completely processsed.
// Returns 0 on success, <0 on error.
static int wg_format_some_of_list(
    const monitored_resource_t *monitored_resource, const wg_payload_t *list,
    const wg_payload_t **new_list, char **json, _Bool pretty);

// Look up an existing, or create a new, deriv_tracker_value_t in the treee.
// The key is derived from the payload. *created is set to 0 if the tracker was
// found in the tree; 1 if it was newly-created. Returns 0 on success, <0 on
// error.
static int wg_lookup_or_create_tracker_value(c_avl_tree_t *tree,
    const wg_payload_t *payload, deriv_tracker_value_t **tracker, int *created);


void *wg_process_queue(void *arg) {
  wg_context_t *ctx = arg;
  wg_queue_t *queue = ctx->queue;

  // Keeping track of the base values for derivative values.
  c_avl_tree_t *deriv_tree = wg_deriv_tree_create();
  if (deriv_tree == NULL) {
    ERROR("write_gcm: wg_deriv_tree_create failed");
    goto leave;
  }

  cdtime_t last_flush_time = cdtime();

  while (1) {
    int want_terminate;
    wg_payload_t *payloads;
    if (wait_next_queue_event(queue, last_flush_time, &want_terminate,
        &payloads) != 0) {
      // Fatal.
      ERROR("write_gcm: wait_next_queue_event failed.");
      break;
    }
    last_flush_time = cdtime();
    if (wg_rebase_cumulative_values(deriv_tree, &payloads) != 0) {
      // Also fatal.
      ERROR("write_gcm: wg_rebase_cumulative_values failed.");
      wg_payload_destroy(payloads);
      break;
    }
    if (wg_transmit_unique_segments(ctx, payloads) != 0) {
      // Not fatal. Connectivity problems? Server went away for a while?
      // Just drop the payloads on the floor and make a note of it.
      WARNING("write_gcm: wg_transmit_unique_segments failed. Flushing.");
    }
    wg_payload_destroy(payloads);
    if (want_terminate) {
      break;
    }
  }

 leave:
  WARNING("write_gcm: queue processor thread dying.");
  wg_deriv_tree_destroy(deriv_tree);
  return NULL;
}

static int wg_rebase_cumulative_values(c_avl_tree_t *deriv_tree,
    wg_payload_t **list) {
  wg_payload_t *new_head = NULL;
  wg_payload_t *new_tail = NULL;
  wg_payload_t *item = *list;
  int some_error_occurred = 0;
  while (item != NULL) {
    wg_payload_t *next = item->next;
    item->next = NULL;  // Detach from the list.

    int keep;
    if (wg_rebase_item(deriv_tree, item, &keep) != 0) {
      ERROR("write_gcm: wg_rebase_item failed.");
      // Finish processing the list (so we don't lose anything), but remember
      // that an error occurred.
      some_error_occurred = 1;
      keep = 0;
    }

    if (keep) {
      if (new_head == NULL) {
        new_head = item;
        new_tail = item;
      } else {
        new_tail->next = item;
        new_tail = item;
      }
    } else {
      wg_payload_destroy(item);
    }
    item = next;
  }
  *list = new_head;
  return some_error_occurred ? -1 : 0;
}

static int wg_rebase_item(c_avl_tree_t *deriv_tree, wg_payload_t *payload,
    int *keep) {
  // It is an assumption of our system that either all the types in a value_list
  // are DERIVE, or none of them are.
  int derived_count = 0;
  int i;
  for (i = 0; i < payload->num_values; ++i) {
    if (payload->values[i].ds_type == DS_TYPE_DERIVE) {
      ++derived_count;
    }
  }
  if (derived_count == 0) {
    *keep = 1;
    return 0;  // No DERIVED values, so nothing further to do here.
  }
  if (derived_count != payload->num_values) {
    ERROR("write_gcm: wg_rebase_cumulative_values: values must not have diverse"
        " types.");
    return -1;
  }

  // Get the appropriate tracker for this payload.
  deriv_tracker_value_t *tracker;
  int created;
  if (wg_lookup_or_create_tracker_value(deriv_tree, payload, &tracker, &created)
      != 0) {
    ERROR("write_gcm: wg_lookup_or_create_tracker_value failed.");
    return -1;
  }

  if (created) {
    // Establish a baseline, and then indicate to the caller not to add this
    // to the output list.
    tracker->start_time = payload->start_time;
    for (i = 0; i < payload->num_values; ++i) {
      derive_t d = payload->values[i].val.derive;
      tracker->baselines[i] = d;
      tracker->previous[i] = d;
    }
    *keep = 0;
    return 0;
  }

  // If any of the counters have wrapped, then we need to reset the tracker
  // baseline and start_time.
  int some_counter_wrapped = 0;
  for (i = 0; i < payload->num_values; ++i) {
    if (payload->values[i].val.derive < tracker->previous[i]) {
      some_counter_wrapped = 1;
      break;
    }
  }

  if (some_counter_wrapped) {
    tracker->start_time = payload->start_time;
    for (i = 0; i < payload->num_values; ++i) {
      tracker->baselines[i] = 0;
    }
  }

  // Update the start_time according to the tracker, adjust the value according
  // to the baseline, and remember the previous value.
  payload->start_time = tracker->start_time;
  for (i = 0; i < payload->num_values; ++i) {
    wg_payload_value_t *v = &payload->values[i];
    tracker->previous[i] = v->val.derive;
    v->val.derive -= tracker->baselines[i];
  }
  *keep = 1;
  return 0;
}

// Because we can't send points with the same key and labels in one
// transmission, we need to break 'list_to_process' into segments, where all
// the items in a segment have distinct keys.
int wg_transmit_unique_segments(const wg_context_t *ctx, wg_payload_t *list) {
  while (list != NULL) {
    wg_payload_t *tail;
    if (wg_find_unique_segment(list, &tail) != 0) {
      ERROR("write_gcm: wg_find_unique_segment failed");
      return -1;
    }
    // Temporarily detach the unique segment from the rest of the list.
    wg_payload_t *save = tail->next;
    tail->next = NULL;
    int result = wg_transmit_unique_segment(ctx, list);
    tail->next = save;
    if (result != 0) {
      ERROR("write_gcm: wg_transmit_unique_segment failed.");
      return -1;
    }
    list = save;
  }
  return 0;
}

static void wg_log_json_message(const wg_context_t *ctx, const char *fmt, ...) {
  if (ctx->json_log_file == NULL) {
    return;
  }
  va_list ap;
  va_start(ap, fmt);
  vfprintf(ctx->json_log_file, fmt, ap);
  va_end(ap);
  fflush(ctx->json_log_file);
}

static int wg_transmit_unique_segment(const wg_context_t *ctx,
    const wg_payload_t *list) {
  if (list == NULL) {
    return 0;
  }

  // Variables to clean up at the end.
  char *json = NULL;
  int result = -1;  // Pessimistically assume failure.

  char auth_header[256];
  if (wg_oauth2_get_auth_header(auth_header, sizeof(auth_header),
      ctx->oauth2_ctx, ctx->cred_ctx) != 0) {
    ERROR("write_gcm: wg_oauth2_get_auth_header failed.");
    goto leave;
  }

  while (list != NULL) {
    const wg_payload_t *new_list;
    if (wg_format_some_of_list(ctx->resource, list, &new_list, &json,
        ctx->pretty_print_json) != 0) {
      ERROR("write_gcm: Error formatting list as JSON");
      goto leave;
    }

    wg_log_json_message(ctx, "Sending json:\n%s\n", json);

    // By the way, a successful response is the empty string. An unsuccessful
    // response is a detailed error message from Monarch.
    char response[2048];
    const char *headers[] = { auth_header, json_content_type_header };
    if (wg_curl_get_or_post(response, sizeof(response),
        ctx->agent_translation_service_url, json,
        headers, STATIC_ARRAY_SIZE(headers)) != 0) {
      wg_log_json_message(ctx, "Error contacting server.\n");
      ERROR("write_gcm: Error talking to the endpoint.");
      goto leave;
    }

    wg_log_json_message(ctx, "Server response:\n%s\n", response);

    sfree(json);
    json = NULL;
    list = new_list;
  }

  result = 0;

 leave:
  sfree(json);
  return result;
}

static int wg_format_some_of_list(
    const monitored_resource_t *monitored_resource, const wg_payload_t *list,
    const wg_payload_t **new_list, char **json, _Bool pretty) {
  size_t size = JSON_SOFT_TARGET_SIZE + JSON_LOW_WATER_MARK;
  char *buffer_start = malloc(size);
  if (buffer_start == NULL) {
    ERROR("write_gcm: Couldn't allocate %zd bytes for buffer", size);
    goto error;
  }

  char *buffer = buffer_start;
  if (wg_json_CreateCollectdTimeseriesPointsRequest(
      &buffer, &size, pretty, monitored_resource, list, new_list) != 0) {
    ERROR("write_gcm: wg_json_CreateCollectdTimeseriesPointsRequest"
        " failed.");
    goto error;
  }

  if (size < 2) {
    ERROR("write_gcm: buffer overflow (or other error) while building JSON"
        " message.");
    goto error;
  }

  if (list == *new_list) {
    ERROR("write_gcm: wg_format_some_of_list failed to make progress.");
    goto error;
  }

  *json = buffer_start;
  return 0;

 error:
  sfree(buffer_start);
  return -1;
}

int wg_find_unique_segment(wg_payload_t *list, wg_payload_t **tail) {
  // Items to clean up.
  c_avl_tree_t *been_here_tree = NULL;
  wg_payload_t *prev = NULL;
  int result = -1;  // Pessimistically assume failure.

  been_here_tree = wg_been_here_tree_create();
  if (been_here_tree == NULL) {
    ERROR("write_gcm: been_here_tree_create failed.");
    goto leave;
  }

  while (list != NULL) {
    deriv_tracker_key_t *been_here_key = wg_deriv_tracker_key_create(
        list->host, list->plugin, list->plugin_instance, list->type,
        list->type_instance);
    if (been_here_key == NULL) {
      ERROR("write_gcm: error allocating been_here_key");
      goto leave;
    }

    if (c_avl_get(been_here_tree, been_here_key, NULL) == 0) {
      // Collision with existing key, so stop processing here. Return a
      // successful result with *tail = prev.
      wg_deriv_tracker_key_destroy(been_here_key);
      break;
    }

    if (c_avl_insert(been_here_tree, been_here_key, NULL) != 0) {
      ERROR("write_gcm: c_avl_insert failed");
      wg_deriv_tracker_key_destroy(been_here_key);
      goto leave;
    }

    prev = list;
    list = list->next;
  }

  result = 0;

 leave:
  wg_been_here_tree_destroy(been_here_tree);
  *tail = prev;
  return result;
}

static int wg_lookup_or_create_tracker_value(c_avl_tree_t *tree,
    const wg_payload_t *payload, deriv_tracker_value_t **tracker,
    int *created) {
  // Items to clean up upon exit.
  deriv_tracker_key_t *key = NULL;
  deriv_tracker_value_t *value = NULL;

  key = wg_deriv_tracker_key_create(payload->host, payload->plugin,
      payload->plugin_instance, payload->type, payload->type_instance);
  if (key == NULL) {
    ERROR("write_gcm: deriv_tracker_key_create failed");
    goto error;
  }

  if (c_avl_get(tree, key, (void**)tracker) == 0) {
    // tracker_value found!
    wg_deriv_tracker_key_destroy(key);
    *created = 0;
    return 0;
  }

  // Couldn't find a tracker value. Need to make both a heap-allocated key and
  // a tracker_value.
  value = wg_deriv_tracker_value_create(payload->num_values);
  if (value == NULL) {
    ERROR("write_gcm: deriv_tracker_value_create failed.");
    goto error;
  }

  if (c_avl_insert(tree, key, value) == 0) {
    *tracker = value;
    *created = 1;
    return 0;
  }
  ERROR("write_gcm: Can't insert new entry into tree.");

 error:
  wg_deriv_tracker_value_destroy(value);
  wg_deriv_tracker_key_destroy(key);
  return -1;
}

int wait_next_queue_event(wg_queue_t *queue, cdtime_t last_flush_time,
    int *want_terminate, wg_payload_t **payloads) {
  cdtime_t next_flush_time = last_flush_time + plugin_get_interval();
  pthread_mutex_lock(&queue->mutex);
  while (1) {
    pthread_cond_wait(&queue->cond, &queue->mutex);
    cdtime_t now = cdtime();
    if (queue->request_flush ||
        queue->request_terminate ||
        queue->size > MAX_QUEUE_SIZE ||
        now > next_flush_time) {
      *payloads = queue->head;
      *want_terminate = queue->request_terminate;
      queue->head = NULL;
      queue->tail = NULL;
      queue->size = 0;
      queue->request_flush = 0;
      queue->request_terminate = 0;
      pthread_mutex_unlock(&queue->mutex);
      return 0;
    }
  }
}

//==============================================================================
//==============================================================================
//==============================================================================
// Various collectd entry points.
//==============================================================================
//==============================================================================
//==============================================================================

// Runs those things that need to be initialized from a single-threaded context.
static int wg_init(void) {
  curl_global_init(CURL_GLOBAL_SSL);
  return (0);
}

// Transform incoming value_list into our "payload" format and append it to the
// work queue.
static int wg_write(const data_set_t *ds, const value_list_t *vl,
                    user_data_t *user_data) {
  assert(ds->ds_num > 0);
  wg_queue_t *queue = user_data->data;

  // Allocate the payload.
  wg_payload_t *payload = wg_payload_create(ds, vl);
  if (payload == NULL) {
    ERROR("write_gcm: wg_payload_create failed.");
    return -1;
  }

  // Append to the queue.
  pthread_mutex_lock(&queue->mutex);
  // Backpressure. If queue is backed up then something has gone horribly wrong.
  // Maybe the queue processor died.
  size_t abnormal_limit = 5 * MAX_QUEUE_SIZE;
  if (queue->size > abnormal_limit) {
    wg_payload_destroy(payload);
    pthread_mutex_unlock(&queue->mutex);
    return -1;
  }
  if (queue->head == NULL) {
    queue->head = payload;
    queue->tail = payload;
  } else {
    queue->tail->next = payload;
    queue->tail = payload;
  }
  ++queue->size;
  pthread_cond_signal(&queue->cond);
  pthread_mutex_unlock(&queue->mutex);

  return 0;
}

// Request a flush from the queue processor.
static int wg_flush(cdtime_t timeout,
                    const char *identifier __attribute__((unused)),
                    user_data_t *user_data) {
  wg_queue_t *queue = user_data->data;
  pthread_mutex_lock(&queue->mutex);
  queue->request_flush = 1;
  pthread_cond_signal(&queue->cond);
  pthread_mutex_unlock(&queue->mutex);
  return 0;
}

//==============================================================================
//==============================================================================
//==============================================================================
// Config file parsing submodule. The entry point here is wg_config.
// If successful, it ends up registering a 'write' and 'flush' callback with
// collectd.
//==============================================================================
//==============================================================================
//==============================================================================
static int wg_config(oconfig_item_t *ci);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static int wg_config(oconfig_item_t *ci) {
  // Items to clean up on exit from the function.
  wg_configbuilder_t *cb = NULL;
  wg_context_t *ctx = NULL;
  int result = -1;  // Pessimistically assume failure.

  cb = wg_configbuilder_create(ci);
  if (cb == NULL) {
    ERROR("write_gcm: wg_configbuilder_create failed");
    goto leave;
  }

  ctx = wg_context_create(cb);
  if (ctx == NULL) {
    ERROR("write_gcm: wg_context_create failed.");
    goto leave;
  }

  if (pthread_create(&ctx->queue_thread, NULL, &wg_process_queue, ctx) != 0) {
    ERROR("write_gcm: pthread_create failed");
    goto leave;
  }

  user_data_t user_data = {
      .data = ctx->queue,
      .free_func = NULL
  };
  ctx = NULL;  // Now owned by thread.
  if (plugin_register_flush(this_plugin_name, &wg_flush, &user_data) != 0) {
    goto leave;
  }
  //TODO
  //    user_data.free_func = &wg_queue_free_func;
  result = plugin_register_write(this_plugin_name, &wg_write, &user_data);

 leave:
  wg_context_destroy(ctx);
  wg_configbuilder_destroy(cb);
  return result;
}

static void wg_configbuilder_destroy(wg_configbuilder_t *cb) {
  if (cb == NULL) {
    return;
  }
  sfree(cb->agent_translation_service_format_string);
  sfree(cb->json_log_file);
  sfree(cb->passphrase);
  sfree(cb->key_file);
  sfree(cb->email);
  sfree(cb->account_id);
  sfree(cb->region);
  sfree(cb->zone);
  sfree(cb->instance_id);
  sfree(cb->project_id);
  sfree(cb->cloud_provider);
  sfree(cb);
}

//==============================================================================
//==============================================================================
//==============================================================================
// Collectd module initialization entry point.
//==============================================================================
//==============================================================================
//==============================================================================
void module_register(void) {
  plugin_register_complex_config(this_plugin_name, wg_config);
  plugin_register_init(this_plugin_name, wg_init);
}
