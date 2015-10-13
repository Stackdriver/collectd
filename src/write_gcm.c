#include "collectd.h"
#include "common.h"
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

// The URL of the GCE metadata server.
#define METADATA_SERVER_API "http://169.254.169.254/computeMetadata/v1beta1/"

// The URL of the GCE metadata server which fetches the auth token.
#define METADATA_FETCH_AUTH_TOKEN \
  METADATA_SERVER_API "instance/service-accounts/default/token"

// The URL of the GCE metadata server which fetches the project-id (the string
// id, not the numeric id).
#define METADATA_PROJECT_ID METADATA_SERVER_API "project/project-id"

// The URL of the GCE metadata server which fetches the instance id (numeric).
#define METADATA_INSTANCE_ID METADATA_SERVER_API "instance/id"

// The URL of the GCE metadata server which fetches the zone (which comes back
// as projects/${numeric-id}/zones/${zone} where ${zone} is e.g. us-central1-a
#define METADATA_ZONE METADATA_SERVER_API "instance/zone"

// The special HTTP header that needs to be added to any call to the GCE
// metadata server.
#define GOOGLE_METADATA_HEADER "Metadata-Flavor: Google"

// The application/JSON content header.
#define JSON_CONTENT_TYPE_HEADER "Content-Type: application/json"

// The One Platform endpoint for sending the data. This is in printf format,
// with a single %s placeholder which holds the name of the project.
#define ENDPOINT_FORMAT_STRING "http://localhost:5000/v3/projects/%s/collectd/timeSeries"

// The maximum number of entries we keep in our processing queue before flushing
// it. Ordinarily a tree flush happens every minute or so, but we also flush if
// the list size exceeds a certain value.
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

// If 0, most whitespace is eliminated from the JSON messages. If nonzero,
// indentation and newlines are added.
#define JSON_PRETTY_INDENT 2

// Additional slop so that we have enough space to close out the message.
#define JSON_LOW_WATER_MARK 5000


static void kosatron_dump(const char *fmt, ...) {
  FILE *fp = fopen("/home/kosak/supertemp.dump", "a");
  if (fp == NULL) {
    ERROR("Can't open supertemp.dump file.");
    return;
  }
  va_list ap;
  va_start(ap, fmt);
  vfprintf(fp, fmt, ap);
  va_end(ap);
  fclose(fp);
}

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
// Server info submodule.
//==============================================================================
//==============================================================================
//==============================================================================
typedef struct {
  char project_id[128];
  char instance_id[128];
  char zone[128];
} gce_instance_ctx_t;

static gce_instance_ctx_t *wg_gce_instance_ctx_create(const char *project_id,
    const char *instance_id, const char *zone);
static void wg_gce_instance_ctx_destroy(gce_instance_ctx_t *ctx);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static gce_instance_ctx_t *wg_gce_instance_ctx_create(const char *project_id,
    const char *instance_id, const char *zone) {
  gce_instance_ctx_t *ctx = calloc(1, sizeof(*ctx));
  if (ctx == NULL) {
    ERROR("write_gcm: wg_gce_instance_ctx_create: calloc failed.");
    return NULL;
  }
  sstrncpy(ctx->project_id, project_id, sizeof(ctx->project_id));
  sstrncpy(ctx->instance_id, instance_id, sizeof(ctx->instance_id));
  sstrncpy(ctx->zone, zone, sizeof(ctx->zone));
  return ctx;
}

static void wg_gce_instance_ctx_destroy(gce_instance_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  sfree(ctx);
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
  INFO("write_gcm: Doing %s request: url %s, body %s, num_headers %d",
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
    ERROR("write_gcm: Asking metadata server for auth token");
    return wg_oauth2_talk_to_server_and_store_result(ctx,
        METADATA_FETCH_AUTH_TOKEN, NULL, NULL, 0, now);
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
  INFO("I have a response which looks like this: %s", response);

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
// JSON submodule for formatting JSON messages.
//==============================================================================
//==============================================================================
//==============================================================================
typedef struct {
  char **buffer;
  size_t *size;
  // Used when pretty-printing. Invariant: all bytes are ' ' except
  // indent_buf[indent_level], which is NUL.
  char indent_buf[80];
  // strlen(indent_buf).
  int indent_level;
} json_ctx_t;

// Initializes a json_ctx_t structure.
static void wg_json_ctx_init(json_ctx_t *ctx, char **buffer, size_t *size);

// Writes a json_record. Takes triplets of the form [field_name, json_handler,
// payload], terminated by NULL.

// Example:
// unsigned long longVal = 12345;
// wg_json_write_record(ctx,
//                      "myKey", &json_write_string, "myValue",
//                      "myUlong", &json_write_unsigned_long, &longVal,
//                      "moreStuff", &writeComplexData, &moreStuffPayload,
//                      NULL);
//
// This would result in a JSON record that looks like
// {
//   "myKey": "myValue",
//   "myULong": 12345,
//   "moreStuff": { etc }
// }
static int wg_json_write_record(json_ctx_t *ctx, ...);

// A 'json_handler_t' is a function called by 'json_write_record' whose job is
// to write the 'value' part of a key/value pair in a record. It takes a
// json_ctx_t* and a callee-defined payload. Returns 0 on success and <0 on
// error.
typedef int (*json_handler_t)(json_ctx_t *ctx, void *payload);

// These two functions are used to iterate over a sequence.
// The job of a 'json_has_next_t' handler is to return 0 if there is more data
// in the sequence, >0 if there is NO more data in the sequence, and <0 if there
// is an error.
// The job of a 'json_write_next_t' is to write the next item in the sequence.
// It returns 0 on success or <0 on error.
// The caller promises to only caller the write_next handler if the immediately
// previous has_next has succeeded.
typedef int (*json_has_next_t)(json_ctx_t *ctx, void *payload);
typedef int (*json_write_next_t)(json_ctx_t *ctx, void *payload);

// A handler to write a quoted string. Does not handle JSON escapes (yet?)
static int wg_json_quoted_string_handler(json_ctx_t *ctx, void *payload);

// A handler to write an unquoted string.
static int wg_json_unquoted_string_handler(json_ctx_t *ctx, void *payload);

// A handler to write a uint64_t.
static int wg_json_uint64_handler(json_ctx_t *ctx, void *payload);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static void wg_json_indent(json_ctx_t *ctx, int offset);

static void wg_json_ctx_init(json_ctx_t *ctx, char **buffer, size_t *size) {
  ctx->buffer = buffer;
  ctx->size = size;
  memset(ctx->indent_buf, ' ', sizeof(ctx->indent_buf));
  ctx->indent_buf[0] = 0;
  ctx->indent_level = 0;
}

static int wg_json_write_record(json_ctx_t *ctx, ...) {
  bufprintf(ctx->buffer, ctx->size, "{");
  wg_json_indent(ctx, +JSON_PRETTY_INDENT);

  // Invariant: output "cursor" is positioned at the end of the previous line.

  char *sep = "\n";  // First separator is newline.
  va_list ap;
  va_start(ap, ctx);
  const char *key = va_arg(ap, const char*);
  while (key != NULL) {
    json_handler_t handler = va_arg(ap, json_handler_t);
    void *data = va_arg(ap, void*);

    bufprintf(ctx->buffer, ctx-> size, "%s%s\"%s\": ",
              sep, ctx->indent_buf, key);
    if ((*handler)(ctx, data) != 0) {
      return -1;
    }

    key = va_arg(ap, const char*);
    sep = ",\n";  // Next separator is comma-newline.
  }
  va_end(ap);
  wg_json_indent(ctx, -JSON_PRETTY_INDENT);
  bufprintf(ctx->buffer, ctx->size, "\n%s}", ctx->indent_buf);
  return 0;
}

static int wg_json_write_array(json_ctx_t *ctx, json_has_next_t has_next,
    json_write_next_t write_next, void *payload) {
  bufprintf(ctx->buffer, ctx->size, "[");
  wg_json_indent(ctx, +JSON_PRETTY_INDENT);

  // Invariant: output "cursor" is positioned at the end of the previous line.
  char *sep = "\n";  // First separator is newline.
  int result = (*has_next)(ctx, payload);  // Any data in data structure?
  if (result < 0) {
    return result;
  }
  while (result == 0) {  // 0 result from has_next means "more data exists".
    // Print previous separator, some indentation, then the next item.
    bufprintf(ctx->buffer, ctx->size, "%s%s", sep, ctx->indent_buf);
    result = (*write_next)(ctx, payload);
    if (result < 0) {
      return result;
    }
    result = (*has_next)(ctx, payload);  // Any data in data structure?
    if (result < 0) {
      return result;
    }
    // Next separator is comma-newline.
    sep = ",\n";
  }
  wg_json_indent(ctx, -JSON_PRETTY_INDENT);
  bufprintf(ctx->buffer, ctx->size, "\n%s]", ctx->indent_buf);
  return 0;
}

static int wg_json_quoted_string_handler(json_ctx_t *ctx, void *payload) {
  bufprintf(ctx->buffer, ctx->size, "\"%s\"", (const char*)payload);
  return 0;
}

static int wg_json_unquoted_string_handler(json_ctx_t *ctx, void *payload) {
  bufprintf(ctx->buffer, ctx->size, "%s", (const char*)payload);
  return 0;
}

static int wg_json_uint64_handler(json_ctx_t *ctx, void *payload) {
  bufprintf(ctx->buffer, ctx->size, "%" PRIu64, *(uint64_t*)payload);
  return 0;
}

static void wg_json_indent(json_ctx_t *ctx, int offset) {
  ctx->indent_buf[ctx->indent_level] = ' ';
  ctx->indent_level += offset;
  assert(ctx->indent_level >= 0 && ctx->indent_level < sizeof(ctx->indent_buf));
  ctx->indent_buf[ctx->indent_level] = 0;
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
  gce_instance_ctx_t *instance_ctx;
  credential_ctx_t *cred_ctx;
  oauth2_ctx_t *oauth2_ctx;
  pthread_t queue_thread;
  wg_queue_t *queue;
} wg_context_t;

static wg_context_t *wg_context_create(const char *project_id,
                                       const char *instance_id,
                                       const char *zone,
                                       const char *email,
                                       const char *key_file,
                                       const char *passphrase);
static void wg_context_destroy(wg_context_t *data);

static wg_queue_t *wg_queue_create();
static void wg_queue_destroy(wg_queue_t *data);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------


static wg_context_t *wg_context_create(const char *project_id,
                                       const char *instance_id,
                                       const char *zone,
                                       const char *email,
                                       const char *key_file,
                                       const char *passphrase) {
  wg_context_t *ctx = calloc(1, sizeof(*ctx));
  if (ctx == NULL) {
    ERROR("wg_context_create: calloc failed.");
    return NULL;
  }

  // Create the subcontext holding various pieces of server information.
  ctx->instance_ctx = wg_gce_instance_ctx_create(project_id, instance_id, zone);
  if (ctx->instance_ctx == NULL) {
    ERROR("write_gcm: wg_server_ctx_create failed.");
    wg_context_destroy(ctx);
    return NULL;
  }

  // Optionally create the subcontext holding the service account credentials.
  if (email != NULL && key_file != NULL && passphrase != NULL) {
    ctx->cred_ctx = wg_credential_ctx_create(email, key_file, passphrase);
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
  return ctx;
}

static void wg_context_destroy(wg_context_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  wg_queue_destroy(ctx->queue);
  wg_oauth2_ctx_destroy(ctx->oauth2_ctx);
  wg_credential_ctx_destroy(ctx->cred_ctx);
  wg_gce_instance_ctx_destroy(ctx->instance_ctx);
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
// entirely new wg_request_CreateCollectdTimeseriesPointsRequest requests each
// time) until the list is exhausted.
static int wg_build_CreateCollectdTimeseriesPointsRequest(char **buffer,
    size_t *size, const gce_instance_ctx_t *instance_ctx,
    const wg_payload_t *list, const wg_payload_t **new_list);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static int wg_request_MonitoredResource_handler(json_ctx_t *json_ctx,
    void *data);
static int wg_request_MonitoredResource_labels_handler(json_ctx_t *json_ctx,
    void *data);
static int wg_request_CollectdPayloads_handler(json_ctx_t *json_ctx,
    void *data);
static int wg_request_CollectdPayload_has_next(json_ctx_t *json_ctx,
    void *data);
static int wg_request_CollectdPayload_dump_next(json_ctx_t *json_ctx,
    void *data);
static int wg_request_CollectdValues_handler(json_ctx_t *json_ctx,
    void *data);
static int wg_request_CollectdValue_has_next(json_ctx_t *json_ctx,
    void *data);
static int wg_request_CollectdValue_dump_next(json_ctx_t *json_ctx,
    void *data);
static int wg_request_CollectdValueType_handler(json_ctx_t *json_ctx,
    void *data);
static int wg_request_Timestamp_handler(json_ctx_t *json_ctx, void *data);

// From google/monitoring/v3/agent_service.proto
// message CreateCollectdTimeSeriesRequest {
//   string name = 5;
//   google.api.MonitoredResource resource = 2;
//   string collectd_version = 3;
//   repeated CollectdPayload collectd_payloads = 4;
// }
static int wg_build_CreateCollectdTimeseriesPointsRequest(char **buffer,
    size_t *size, const gce_instance_ctx_t *instance_ctx,
    const wg_payload_t *list, const wg_payload_t **new_list) {
  json_ctx_t json_ctx;
  wg_json_ctx_init(&json_ctx, buffer, size);

  const char *collectd_useragent = COLLECTD_USERAGENT;

  char name[256];
  int result = snprintf(name, sizeof(name), "project/%s",
      instance_ctx->project_id);
  if (result < 0 || result >= sizeof(name)) {
    ERROR("write_gcm: project_id %s doesn't fit in buffer.",
        instance_ctx->project_id);
    return -1;
  }

  *new_list = list;
  return wg_json_write_record(
      &json_ctx,
      "name", &wg_json_quoted_string_handler, name,
      "resource", &wg_request_MonitoredResource_handler, instance_ctx,
      "collectdVersion", &wg_json_quoted_string_handler, collectd_useragent,
      "collectdPayloads", &wg_request_CollectdPayloads_handler, new_list,
      NULL);
}

// From google/api/monitored_resource.proto
// message MonitoredResource {
//   string type = 1;
//   map<string, string> labels = 2;
// }
static int wg_request_MonitoredResource_handler(json_ctx_t *json_ctx,
    void *data) {
  const gce_instance_ctx_t *server_ctx = (const gce_instance_ctx_t*)data;
  return wg_json_write_record(
      json_ctx,
      "type", &wg_json_quoted_string_handler, "gce_instance",
      "labels", &wg_request_MonitoredResource_labels_handler, server_ctx,
      NULL);
}

static int wg_request_MonitoredResource_labels_handler(json_ctx_t *json_ctx,
    void *data) {
  const gce_instance_ctx_t *server_ctx = (const gce_instance_ctx_t*)data;
  return wg_json_write_record(
      json_ctx,
      "instance_id", &wg_json_quoted_string_handler, server_ctx->instance_id,
      "zone", &wg_json_quoted_string_handler, server_ctx->zone,
      NULL);
}

// Array of CollectdPayload
static int wg_request_CollectdPayloads_handler(json_ctx_t *json_ctx,
    void *data) {
  return wg_json_write_array(json_ctx,
      &wg_request_CollectdPayload_has_next,
      &wg_request_CollectdPayload_dump_next,
      data);
}

// message CollectdPayload {
//   repeated CollectdValue values = 1;
//   google.protobuf.Timestamp start_time = 2;
//   google.protobuf.Timestamp end_time = 3;
//   string plugin = 4;
//   string plugin_instance = 5;
//   string type = 6;
//   string type_instance = 7;
// }
static int wg_request_CollectdPayload_has_next(json_ctx_t *json_ctx,
    void *data) {
  // If we are close to running out of buffer, exit early so we can still
  // try to make a well-formed JSON document. This will leave some data in
  // 'tree' but that's ok, because the caller knows to keep trying until the
  // tree is empty.
  if (*json_ctx->size < JSON_LOW_WATER_MARK) {
    return 1;
  }

  // If no more nodes in the list, we are done.
  wg_payload_t **payload_list = (wg_payload_t**)data;
  return *payload_list == NULL ? 1 : 0;
}

static int wg_request_CollectdPayload_dump_next(json_ctx_t *json_ctx,
    void *data) {
  wg_payload_t **payload_list = (wg_payload_t**)data;
  wg_payload_t *head = *payload_list;
  *payload_list = head->next;

  int result = wg_json_write_record(
      json_ctx,
      "values", &wg_request_CollectdValues_handler, head,
      "startTime", &wg_request_Timestamp_handler, &head->start_time,
      "endTime", &wg_request_Timestamp_handler, &head->end_time,
      "plugin", &wg_json_quoted_string_handler, head->plugin,
      "pluginInstance", &wg_json_quoted_string_handler, head->plugin_instance,
      "type", &wg_json_quoted_string_handler, head->type,
      "typeInstance", &wg_json_quoted_string_handler, head->type_instance,
      NULL);
  return result;
}

typedef struct {
  int size;
  wg_payload_value_t *values;
} payload_values_iterator_t;

static int wg_request_CollectdValues_handler(json_ctx_t *json_ctx,
                                              void *data) {
  wg_payload_t *element = (wg_payload_t*)data;
  payload_values_iterator_t it = {
      .values = element->values,
      .size = element->num_values
  };
  return wg_json_write_array(json_ctx,
      &wg_request_CollectdValue_has_next,
      &wg_request_CollectdValue_dump_next,
      &it);
}

typedef struct {
  const char *type;
  const char *value_tag;
  char value_text[128];
} fleshed_out_value_t;

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

//message CollectdValue {
//  optional CollectdValueType value = 1;
//  optional CollectdDsType dataSourceType = 2;
//  optional string dataSourceName = 3;
//}
static int wg_request_CollectdValue_has_next(json_ctx_t *json_ctx, void *data) {
  payload_values_iterator_t *it = (payload_values_iterator_t*)data;
  return it->size == 0 ? 1 : 0;
}

static int wg_request_CollectdValue_dump_next(json_ctx_t *json_ctx, void *data){
  payload_values_iterator_t *it = (payload_values_iterator_t*)data;
  wg_payload_value_t *value = it->values;
  --it->size;
  ++it->values;

  fleshed_out_value_t fov;
  if (wg_get_vl_value(value->ds_type, value->val, &fov) != 0) {
    return -1;
  }

  return wg_json_write_record(json_ctx,
      "dataSourceType", &wg_json_quoted_string_handler, fov.type,
      "dataSourceName", &wg_json_quoted_string_handler, value->name,
      "value", &wg_request_CollectdValueType_handler, &fov,
      NULL);
}

//message CollectdValueType {
//  oneof value {
//    bytes unknown = 1;
//    int64 int64_value = 2;
//    uint64 uint64_value = 3;
//    double double_value = 4;
//  }
//}
static int wg_request_CollectdValueType_handler(json_ctx_t *json_ctx,
    void *data) {
  fleshed_out_value_t *fov = (fleshed_out_value_t*)data;
  return wg_json_write_record(json_ctx,
      fov->value_tag, &wg_json_unquoted_string_handler, fov->value_text,
      NULL);
}

//message Timestamp {
//  int64 seconds = 1;
//  int32 nanos = 2;
//}
static int wg_request_Timestamp_handler(json_ctx_t *json_ctx, void *payload) {
  cdtime_t *time_stamp = (cdtime_t*)payload;
  uint64_t sec = CDTIME_T_TO_TIME_T (*time_stamp);
  uint64_t ns = CDTIME_T_TO_NS (*time_stamp % 1073741824);
  return wg_json_write_record(
      json_ctx,
      "seconds", &wg_json_uint64_handler, &sec,
      "nanos", &wg_json_uint64_handler, &ns,
      NULL);
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
static int wg_format_some_of_list(const gce_instance_ctx_t *instance_ctx,
    const wg_payload_t *list, const wg_payload_t **new_list, char **json);

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

static int wg_transmit_unique_segment(const wg_context_t *ctx,
    const wg_payload_t *list) {
  if (list == NULL) {
    return 0;
  }

  // Variables to clean up at the end.
  char *json = NULL;
  int result = -1;  // Pessimistically assume failure.

  char url[512];
  result = snprintf(url, sizeof(url), ENDPOINT_FORMAT_STRING,
      ctx->instance_ctx->project_id);
  if (result < 0 || result >= sizeof(url)) {
    ERROR("write_gcm: Can't build endpoint URL.");
    goto leave;
  }
  INFO("write_gcm: Endpoint URL is %s", url);

  char auth_header[256];
  if (wg_oauth2_get_auth_header(auth_header, sizeof(auth_header),
      ctx->oauth2_ctx, ctx->cred_ctx) != 0) {
    ERROR("write_gcm: wg_oauth2_get_auth_header failed.");
    goto leave;
  }

  while (list != NULL) {
    const wg_payload_t *new_list;
    if (wg_format_some_of_list(ctx->instance_ctx, list, &new_list, &json)
        != 0) {
      ERROR("write_gcm: Error formatting list as JSON");
      goto leave;
    }
    kosatron_dump("auth header is %s\njson is %s\n", auth_header, json);

    // By the way, a successful response is the empty string. An unsuccessful
    // response is a detailed error message from Monarch.
    char response[2048];
    const char *headers[] = { auth_header, JSON_CONTENT_TYPE_HEADER };
    if (wg_curl_get_or_post(response, sizeof(response), url, json,
        headers, STATIC_ARRAY_SIZE(headers)) != 0) {
      ERROR("write_gcm: Error talking to the endpoint.");
      goto leave;
    }
    kosatron_dump("write_gcm: response from endpoint was %s\n", response);
    sfree(json);
    json = NULL;
    list = new_list;
  }

  result = 0;

 leave:
  sfree(json);
  return result;
}

static int wg_format_some_of_list(const gce_instance_ctx_t *instance_ctx,
    const wg_payload_t *list, const wg_payload_t **new_list, char **json) {
  size_t size = JSON_SOFT_TARGET_SIZE + JSON_LOW_WATER_MARK;
  char *buffer_start = malloc(size);
  if (buffer_start == NULL) {
    ERROR("write_gcm: Couldn't allocate %zd bytes for buffer", size);
    goto error;
  }

  char *buffer = buffer_start;
  if (wg_build_CreateCollectdTimeseriesPointsRequest(
      &buffer, &size, instance_ctx, list, new_list) != 0) {
    ERROR("write_gcm: wg_build_CreateCollectdTimeseriesPointsRequest failed.");
    goto error;
  }

  if (size < 2) {
    ERROR("write_gcm: buffer overflow (or other error) while building JSON"
        " message.");
    goto error;
  }

  if (list == *new_list) {
    ERROR("write_gcm: wg_formatSomeOfListAsJSON failed to make progress.");
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

// Hack for now to limit traffic to a whitelisted set of plugin types.
static int superhack_validate_value(const value_list_t *vl) {
#if 0
  static const char *whitelist[] = {
      "interface",
      "tcpconns",
      "df",
      "cpu",
      "memory",
      "processes"
  };
  size_t i;
  for (i = 0; i < STATIC_ARRAY_SIZE(whitelist); ++i) {
    if (strcmp(vl->plugin, whitelist[i]) == 0) {
      return 0;
    }
  }
  return -1;
#else
  return 0;
#endif
}

// Transform incoming value_list into our "payload" format and append it to the
// work queue.
static int wg_write(const data_set_t *ds, const value_list_t *vl,
                    user_data_t *user_data) {
  assert(ds->ds_num > 0);

  if (superhack_validate_value(vl) != 0) {
    // Nothing to do.
    return 0;
  }
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
typedef struct wg_configbuilder_s {
  char *project_id;
  char *instance_id;
  char *zone;
  char *email;
  char *key_file;
  char *passphrase;
} wg_configbuilder_t;

static wg_configbuilder_t *wg_configbuilder_create(oconfig_item_t *ci);
static void wg_configbuilder_destroy(wg_configbuilder_t *cb);
static char *wg_configbuilder_get_from_metadata_server(const char *url);

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

  ctx = wg_context_create(cb->project_id, cb->instance_id, cb->zone, cb->email,
      cb->key_file, cb->passphrase);
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

static wg_configbuilder_t *wg_configbuilder_create(oconfig_item_t *ci) {
  // Items to free on success or error.
  char *long_zone = NULL;
  // Items to free on error.
  wg_configbuilder_t *cb = NULL;

  cb = calloc(1, sizeof(*cb));
  if (cb == NULL) {
    ERROR("write_gcm: wg_configbuilder_create. calloc failed.");
    goto error;
  }

  const char *keys[] = {
      "Project",
      "Instance",
      "Email",
      "PrivateKeyFile",
      "PrivateKeyPass"
  };
  char **locations[] = {
      &cb->project_id,
      &cb->instance_id,
      &cb->email,
      &cb->key_file,
      &cb->passphrase
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
      ERROR ("write_gcm: Invalid configuration option: %s.",
          child->key);
      ++parse_errors;
    }
  }

  if (parse_errors > 0) {
    ERROR("write_gcm: There were %d parse errors reading config file.",
          parse_errors);
    goto error;
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
    ERROR("write_gcm: Error reading configuration."
        " Either all of Email, PrivateKeyFile, and PrivateKeyPass "
        " must be set, or none of them must be set. The provided config file"
        " set %d of them.", num_set);
    goto error;
  }

  // For items not specified in the config file, try to get them from the
  // metadata server.
  if (cb->project_id == NULL) {
    cb->project_id =
        wg_configbuilder_get_from_metadata_server(METADATA_PROJECT_ID);
    if (cb->project_id == NULL) {
      ERROR("write_gcm: Can't get project_id from metadata server "
          " (and not specified in the config file).");
      goto error;
    }
  }
  if (cb->instance_id == NULL) {
    cb->instance_id =
        wg_configbuilder_get_from_metadata_server(METADATA_INSTANCE_ID);
    if (cb->instance_id == NULL) {
      ERROR("write_gcm: Can't get instance_id from metadata server "
          " (and not specified in the config file).");
      goto error;
    }
  }
  long_zone = wg_configbuilder_get_from_metadata_server(METADATA_ZONE);
  if (long_zone == NULL) {
    ERROR("write_gcm: Can't get zone from metadata server");
    goto error;
  }

  // Returned zone is of the form
  // projects/$PROJECT_ID/zones/$ZONE
  // Use the below to hackily extract $ZONE
  const char *last_slash = strrchr(long_zone, '/');
  if (last_slash == NULL) {
    ERROR("write_gcm: Failed to parse zone.");
    goto error;
  }

  cb->zone = sstrdup(last_slash + 1);
  if (cb->zone == NULL) {
    ERROR("write_gcm: wg_configbuilder_create: sstrdup failed");
    goto error;
  }
  sfree(long_zone);

  // Success!
  return cb;

 error:
  sfree(long_zone);
  wg_configbuilder_destroy(cb);
  return NULL;
}

static void wg_configbuilder_destroy(wg_configbuilder_t *cb) {
  if (cb == NULL) {
    return;
  }
  sfree(cb->passphrase);
  sfree(cb->key_file);
  sfree(cb->email);
  sfree(cb->zone);
  sfree(cb->instance_id);
  sfree(cb->project_id);
  sfree(cb);
}

static char *wg_configbuilder_get_from_metadata_server(const char *url) {
  char buffer[2048];
  const char *headers[] = { GOOGLE_METADATA_HEADER };
  if (wg_curl_get_or_post(buffer, sizeof(buffer), url, NULL,
      headers, STATIC_ARRAY_SIZE(headers)) != 0) {
    return NULL;
  }
  return sstrdup(buffer);
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
