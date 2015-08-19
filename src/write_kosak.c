#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "configfile.h"
#include "utils_avltree.h"

#include <errno.h>
#include <stdarg.h>
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

// The URL of the metadata server
#define METADATA_SERVER_API "http://169.254.169.254/computeMetadata/v1beta1/"

// The metadata server URL which fetches the auth token.
#define METADATA_FETCH_AUTH_TOKEN \
  METADATA_SERVER_API "instance/service-accounts/default/token"

// The metadata server URL which fetches the project-id (the string id, not the
// numeric id).
#define METADATA_PROJECT_ID METADATA_SERVER_API "project/project-id"

#define METADATA_INSTANCE_ID METADATA_SERVER_API "instance/id"
#define METADATA_ZONE METADATA_SERVER_API "instance/zone"

// The special HTTP header that needs to be added to any call to the metadata
// server.
#define GOOGLE_METADATA_HEADER "Metadata-Flavor: Google"

// The application/JSON content header.
#define JSON_CONTENT_TYPE_HEADER "Content-Type: application/json"

// The One Platform endpoint for sending the data. This is in printf format,
// with a single %s placeholder which holds the name of the project.
#define ENDPOINT_FORMAT_STRING "http://localhost:5000/v3/projects/%s/collectd/timeSeries"

// The maximum number of nodes allowed over all the leaves of the tree. The
// tree is a map with key mykey_t and value mylist_t. Ordinarily a tree flush
// happens every minute or so (or whenever a new data point with the same key
// as an existing data point arrives). But if the tree exceeds this number of
// nodes there will be an early flush.
#define TREE_NODE_LIMIT 500

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

static void kosatron_temp_dump(const char *auth_header, const char *json) {
  FILE *fp = fopen("/home/kosak/supertemp.dump", "a");
  if (fp == NULL) {
    ERROR("Can't open supertemp.dump file.");
    return;
  }
  fprintf(fp, "%s\n%s\n", auth_header, json);
  fclose(fp);
}

//==============================================================================
//==============================================================================
//==============================================================================
// Misc utility functions.
//==============================================================================
//==============================================================================
//==============================================================================

const char this_plugin_name[] = "write_kosak";

// Allocates and zeroes memory.
static void *malloc_zero(size_t size) {
  void *result = malloc(size);
  if (result != NULL) {
    memset(result, 0, size);
  }
  return result;
}

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
} server_ctx_t;

static server_ctx_t *wg_server_ctx_create(const char *project_id,
                                          const char *instance_id,
                                          const char *zone);
static void wg_server_ctx_destroy(server_ctx_t *ctx);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static server_ctx_t *wg_server_ctx_create(const char *project_id,
                                          const char *instance_id,
                                          const char *zone) {
  server_ctx_t *ctx = malloc_zero(sizeof(*ctx));
  if (ctx == NULL) {
    ERROR("write_kosak: can't allocate server_ctx_t");
    return NULL;
  }
  sstrncpy(ctx->project_id, project_id, sizeof(ctx->project_id));
  sstrncpy(ctx->instance_id, instance_id, sizeof(ctx->instance_id));
  sstrncpy(ctx->zone, zone, sizeof(ctx->zone));
  return ctx;
}

static void wg_server_ctx_destroy(server_ctx_t *ctx) {
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
  credential_ctx_t *result = malloc_zero(sizeof(*result));
  if (result == NULL) {
    ERROR("write_kosak: can't allocate credential_context_t");
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
    ERROR("write_kosak: Failed to open private key file %s", filename);
    return NULL;
  }

  PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
  fclose(fp);
  char err_buf[1024];
  if (p12 == NULL) {
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof (err_buf));
    ERROR("write_kosak: Reading private key %s failed: %s", filename, err_buf);
    return NULL;
  }

  EVP_PKEY *pkey = NULL;
  X509 *cert = NULL;
  STACK_OF(X509) *ca = NULL;
  int result = PKCS12_parse(p12, passphrase, &pkey, &cert, &ca); // 0 is failure
  if (result == 0) {
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof (err_buf));
    ERROR("write_kosak: Parsing private key %s failed: %s", filename, err_buf);
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

// Does an HTTP GET or POST, with up to two optional HTTP headers. If body is
// NULL, does a GET, otherwise does a POST.
static int wg_curl_get_or_post(
    char *response_buffer, size_t response_buffer_size,
    const char *url, const char *header0, const char *header1,
    const char *body);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
typedef struct {
  char *data;
  size_t size;
} wg_curl_write_ctx_t;

static size_t wg_curl_write_callback(char *ptr, size_t size, size_t nmemb,
                                     void *userdata);

static int wg_curl_get_or_post(
    char *response_buffer, size_t response_buffer_size,
    const char *url, const char *header0, const char *header1,
    const char *body) {
  const char *get_or_post_tag = body == NULL ? "GET" : "POST";
  ERROR("Doing: %s request: url %s, header0 %s, header1 %s, body %s",
        get_or_post_tag, url, header0, header1, body);
  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    ERROR("write_kosak: curl_easy_init failed");
  }
  const char *collectd_useragent = COLLECTD_USERAGENT;
  struct curl_slist *headers = NULL;
  if (header0 != NULL) {
    headers = curl_slist_append(headers, header0);
  }
  if (header1 != NULL) {
    headers = curl_slist_append(headers, header1);
  }
  wg_curl_write_ctx_t write_ctx = {
     .data = response_buffer,
     .size = response_buffer_size
  };

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, collectd_useragent);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  if (body != NULL) {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
  }
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &wg_curl_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_ctx);

  int result = curl_easy_perform(curl);
  if (result != CURLE_OK) {
    WARNING("write_kosak: curl_easy_perform() failed: %s",
            curl_easy_strerror(result));
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return -1;
  }
  write_ctx.data[0] = 0;
  WARNING("This is the result from curl: %s", response_buffer);
  if (write_ctx.size < 2) {
    WARNING("write_kosak: The buffer overflowed.");
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return -1;
  }
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  return 0;
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

  // We lie about the number of bytes successfully transferred so that curl
  // doesn't freak out and return an error to our caller. Our caller is keeping
  // track of buffer consumption so it will independently know if the buffer
  // filled up.
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

static int wg_oauth2_sign(unsigned char *signature, size_t sig_capacity,
                          unsigned int *actual_sig_size,
                          const char *buffer, size_t size, EVP_PKEY *pkey);

static void wg_oauth2_base64url_encode(char **buffer, size_t *buffer_size,
                                       const unsigned char *source,
                                       size_t source_size);

static int wg_oauth2_parse_result(char **result_buffer, size_t *result_size,
                                  int *expires_in, const char *json);

static int wg_oauth2_get_auth_header_nolock(oauth2_ctx_t *ctx,
                                            const credential_ctx_t *cred_ctx);

static int wg_oauth2_talk_to_server_and_store_result(
    oauth2_ctx_t *ctx,
    const char *url, const char *header0, const char *header1, const char *body,
    cdtime_t now);

static int wg_oauth2_get_auth_header(char *result, size_t result_size,
                                     oauth2_ctx_t *ctx,
                                     const credential_ctx_t *cred_ctx) {
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
    ERROR("write_kosak: Asking metadata server for auth token");
    return wg_oauth2_talk_to_server_and_store_result(
        ctx,
        METADATA_FETCH_AUTH_TOKEN, GOOGLE_METADATA_HEADER, NULL, NULL,
        now);
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
      ERROR("write_kosak: Error building claim_set.");
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
      ERROR("write_kosak: Can't sign.");
      return -1;
    }

    // Now that we have the signature, append a '.' and the base64url encoding
    // of 'signature' to the buffer.
    bufprintf(&bptr, &bsize, ".");
    wg_oauth2_base64url_encode(&bptr, &bsize, signature, actual_sig_size);
  }

  // Before using the buffer, check for overflow or error.
  if (bsize < 2) {
    ERROR("write_kosak: Buffer overflow or error while building oauth2 body");
    return -1;
  }
  return wg_oauth2_talk_to_server_and_store_result(ctx,
                                                   url, NULL, NULL, body,
                                                   now);
}

static int wg_oauth2_talk_to_server_and_store_result(
    oauth2_ctx_t *ctx,
    const char *url, const char *header0, const char *header1, const char *body,
    cdtime_t now) {
  char response[2048];
  if (wg_curl_get_or_post(response, sizeof(response),
                          url, header0, header1, body) != 0) {
    return -1;
  }
  ERROR("I have a response which looks like this: %s", response);

  // Fill ctx->auth_header with the string "Authorization: Bearer $TOKEN"
  char *resultp = ctx->auth_header;
  size_t result_size = sizeof(ctx->auth_header);
  bufprintf(&resultp, &result_size, "Authorization: Bearer ");
  int expires_in;
  if (wg_oauth2_parse_result(&resultp, &result_size, &expires_in,
                             response) != 0) {
    ERROR("write_kosak: wg_oauth2_parse_result failed");
    return -1;
  }

  if (result_size < 2) {
    ERROR("write_kosak: Error or buffer overflow when building auth_header");
    return -1;
  }
  ctx->token_expire_time = now + TIME_T_TO_CDTIME_T(expires_in);
  return 0;
}

static int wg_oauth2_sign(unsigned char *signature, size_t sig_capacity,
                          unsigned int *actual_sig_size,
                          const char *buffer, size_t size, EVP_PKEY *pkey) {
  if (sig_capacity < EVP_PKEY_size(pkey)) {
    ERROR("write_kosak: signature buffer not big enough.");
    return -1;
  }
  EVP_MD_CTX ctx;
  EVP_SignInit(&ctx, EVP_sha256());

  char err_buf[1024];
  if (EVP_SignUpdate(&ctx, buffer, size) == 0) {
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    ERROR("write_kosak: EVP_SignUpdate failed: %s", err_buf);
    EVP_MD_CTX_cleanup(&ctx);
    return -1;
  }

  if (EVP_SignFinal(&ctx, signature, actual_sig_size, pkey) == 0) {
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    ERROR ("write_kosak: EVP_SignFinal failed: %s", err_buf);
    EVP_MD_CTX_cleanup(&ctx);
    return -1;
  }
  if (EVP_MD_CTX_cleanup(&ctx) == 0) {
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    ERROR ("write_kosak: EVP_MD_CTX_cleanup failed: %s", err_buf);
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
    ERROR("write_kosak: wg_parse_oauth2_result: parse error %s", errbuf);
    return -1;
  }

  const char *token_path[] = {"access_token", NULL};
  const char *expire_path[] = {"expires_in", NULL};
  yajl_val token_val = yajl_tree_get(root, token_path, yajl_t_string);
  yajl_val expire_val = yajl_tree_get(root, expire_path, yajl_t_number);
  if (token_val == NULL || expire_val == NULL) {
    ERROR("write_kosak: wg_parse_oauth2_result: missing one or both of "
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
  oauth2_ctx_t *ctx = malloc_zero(sizeof(*ctx));
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
// Tree submodule for holding the monitored data in a c_avl_tree.
//
// Conceptually the tree is a map: mykey_t -> myentry_t -> NULL.
// The comparison function for myentry_t just looks at its 'name' field only.
// The data structure is represented this way so we can group points and also
// flush at periodic intervals. In particular, we group points by mykey_t. But
// when a myentry_t comes in with the same 'dsname' as one we already have, we
// flush the tree.
//==============================================================================
//==============================================================================
//==============================================================================
typedef struct {
  char host[DATA_MAX_NAME_LEN];
  char plugin[DATA_MAX_NAME_LEN];
  char plugin_instance[DATA_MAX_NAME_LEN];
  char type[DATA_MAX_NAME_LEN];
  char type_instance[DATA_MAX_NAME_LEN];
} mykey_t;

typedef struct {
  char name[DATA_MAX_NAME_LEN];
  const char *type_static;
  const char *value_tag_static;
  char value[64];
  cdtime_t time;
} myentry_t;

// The outer tree which represents the map mykey_t -> innertree_t;
typedef struct {
  c_avl_tree_t *tree;
  size_t nodes_in_use;
  size_t node_limit;
} tree_ctx_t;

// The "entry set" - a tree which represents the map myentry_t -> NULL, with
// a comparator that only looks at myentry_t.name
typedef struct {
  c_avl_tree_t *entry_tree;
} entry_set_t;

static tree_ctx_t *wg_tree_ctx_create();
static void wg_tree_ctx_destroy(tree_ctx_t *ctx);
// A thin wrapper around c_avl_tree_get.
static int wg_tree_get(tree_ctx_t *ctx, const mykey_t *mykey,
                       entry_set_t **entry_set);
// A thin wrapper around c_avl_tree_insert.
static int wg_tree_insert(tree_ctx_t *ctx, mykey_t *mykey,
                          entry_set_t *entry_set);
// A thin wrapper around c_avl_tree_pick.
static int wg_tree_pick(tree_ctx_t *ctx,
                        mykey_t **key, entry_set_t **entry_set);

static mykey_t *wg_mykey_create(const char *host, const char *plugin,
                                const char *plugin_instance, const char *type,
                                const char *type_instance);
static void wg_mykey_destroy(mykey_t *p);

static myentry_t *wg_myentry_create(
    const char* name, const char *type_static,
    const char *value_tag_static, const char* value,
    cdtime_t time);
void wg_myentry_destroy(myentry_t *entry);

static entry_set_t *wg_entry_set_create();
static void wg_entry_set_destroy(entry_set_t *entry_set);
// A thin wrapper aaroudn c_avl_tree_insert.
static int wg_entry_set_insert(entry_set_t *entry_set, myentry_t *entry);
// A thin wrapper around c_avl_tree_pick.
static int wg_entry_set_pick(entry_set_t *entry_set, myentry_t **entry);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
// The comparison function for mykey_t.
static int wg_mykey_compare(const void *lhs, const void *rhs);
// The comparison function for myentry_t.
static int wg_myentry_compare(const void *lhs, const void *rhs);

static tree_ctx_t *wg_tree_ctx_create() {
  tree_ctx_t *ctx = malloc_zero(sizeof(*ctx));
  ctx->tree = c_avl_create(&wg_mykey_compare);
  if (ctx->tree == NULL) {
    ERROR("write_kosak: c_avl_create failed");
    wg_tree_ctx_destroy(ctx);
    return NULL;
  }
  ctx->nodes_in_use = 0;
  ctx->node_limit = TREE_NODE_LIMIT;
  return ctx;
}

static void wg_tree_ctx_destroy(tree_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  mykey_t *key;
  entry_set_t *entry_set;
  while (wg_tree_pick(ctx, &key, &entry_set) == 0) {
    wg_mykey_destroy(key);
    wg_entry_set_destroy(entry_set);
  }
  c_avl_destroy(ctx->tree);
  sfree(ctx);
}

// A thin wrapper around c_avl_tree_insert.
static int wg_tree_insert(tree_ctx_t *ctx, mykey_t *mykey,
                          entry_set_t *entry_set) {
  return c_avl_insert(ctx->tree, mykey, entry_set);
}

static int wg_tree_get(tree_ctx_t *ctx, const mykey_t *mykey,
                       entry_set_t **entry_set) {
  return c_avl_get(ctx->tree, mykey, (void**)entry_set);
}

static int wg_tree_pick(tree_ctx_t *ctx,
                        mykey_t **key, entry_set_t **entry_set) {
  void *key_arg;
  void *entry_arg;
  int result = c_avl_pick(ctx->tree, &key_arg, &entry_arg);
  if (result != 0) {
    return result;
  }
  *key = (mykey_t*)key_arg;
  *entry_set = (entry_set_t*)entry_arg;
  return 0;
}

static mykey_t *wg_mykey_create(const char *host, const char *plugin,
                             const char *plugin_instance, const char *type,
                             const char *type_instance) {
  mykey_t *k = malloc_zero(sizeof(*k));
  if (k == NULL) {
    ERROR("write_kosak: wg_mykey_create: out of memory");
    return NULL;
  }
  sstrncpy(k->host, host, sizeof(k->host));
  sstrncpy(k->plugin, plugin, sizeof(k->plugin));
  sstrncpy(k->plugin_instance, plugin_instance, sizeof(k->plugin_instance));
  sstrncpy(k->type, type, sizeof(k->type));
  sstrncpy(k->type_instance, type_instance, sizeof(k->type_instance));
  return k;
}

static void wg_mykey_destroy(mykey_t *p) {
  sfree(p);
}

static int wg_mykey_compare(const void *lhs, const void *rhs) {
  const mykey_t *l = lhs;
  const mykey_t *r = rhs;
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

static myentry_t *wg_myentry_create(
    const char* name, const char *type_static,
    const char *value_tag_static, const char* value,
    cdtime_t time) {
  myentry_t *result = malloc_zero(sizeof(*result));
  if (result == NULL) {
    ERROR("write_kosak: wg_myentry_create: Could not allocate");
    return NULL;
  }
  sstrncpy(result->name, name, sizeof(result->name));
  result->type_static = type_static;
  result->value_tag_static = value_tag_static;
  sstrncpy(result->value, value, sizeof(result->value));
  result->time = time;
  return result;
}

void wg_myentry_destroy(myentry_t *entry) {
  sfree(entry);
}

static int wg_myentry_compare(const void *lhs, const void *rhs) {
  const myentry_t *l = lhs;
  const myentry_t *r = rhs;
  return strcmp(l->name, r->name);
}

static entry_set_t *wg_entry_set_create() {
  entry_set_t *es = malloc_zero(sizeof(*es));
  es->entry_tree = c_avl_create(&wg_myentry_compare);
  if (es->entry_tree == NULL) {
    ERROR("write_kosak: wg_entry_set_create: c_avl_create failed");
    wg_entry_set_destroy(es);
    return NULL;
  }
  return es;
}

static void wg_entry_set_destroy(entry_set_t *entry_set) {
  if (entry_set == NULL) {
    return;
  }
  myentry_t *entry;
  while (wg_entry_set_pick(entry_set, &entry) == 0) {
    wg_myentry_destroy(entry);
  }
  c_avl_destroy(entry_set->entry_tree);
  sfree(entry_set);
}

static int wg_entry_set_insert(entry_set_t *entry_set, myentry_t *entry) {
  return c_avl_insert(entry_set->entry_tree, entry, NULL);
}

static int wg_entry_set_pick(entry_set_t *entry_set, myentry_t **entry) {
  void *key_arg;
  void *value_arg;
  int result = c_avl_pick(entry_set->entry_tree, &key_arg, &value_arg);
  if (result != 0) {
    return result;
  }
  *entry = (myentry_t*)key_arg;
  assert(value_arg == NULL);
  return 0;
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
  size_t low_water_mark;
  // Used when pretty-printing. Invariant: all bytes are ' ' except
  // indent_buf[indent_level], which is NUL.
  char indent_buf[80];
  // strlen(indent_buf).
  int indent_level;
  // Amount to add to indent_level when opening a new scope. Typically 2.
  int indent_offset;
} json_ctx_t;

// Initializes a json_ctx_t structure.
static void wg_json_ctx_init(json_ctx_t *ctx, char **buffer, size_t *size,
                             size_t low_water_mark, int indent_offset);

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
static void wg_json_write_record(json_ctx_t *ctx, ...);

// A 'json_handler_t' is a function called by 'json_write_record' whose job is
// to write the 'value' part of a key/value pair in a record. It takes a
// json_ctx_t* and a callee-defined payload.
typedef void (*json_handler_t)(json_ctx_t *ctx, void *payload);

// A 'json_iterator_t' is a function whose job is to:
// 1. Optionally, print the next element and advance the data structure.
// 2. Then, return a value indicating whether there is more data to come.
// Whether step 1 is performed is controlled by 'print_and_advance'. If "true",
// (aka nonzero) then it is performed. Typically the caller will initially call
// the function with 'print_and_advance' set to "false" (zero) in order to see
// if there is any data at all. Once it knows there is data, it will repeatedly
// call it with 'print_and_advance' set to "true" (one).
// Returns 0 if there is more data to come, >0 if there is no more data to come,
// or <0 if there is an error.
typedef int (*json_iterator_t)(json_ctx_t *ctx, void *payload,
    int print_and_advance);

// A handler to write a quoted string. Does not handle JSON escapes (yet?)
static void wg_json_quoted_string_handler(json_ctx_t *ctx, void *payload);

// A handler to write an unquoted string.
static void wg_json_unquoted_string_handler(json_ctx_t *ctx, void *payload);

// A handler to write a uint64_t.
static void wg_json_uint64_handler(json_ctx_t *ctx, void *payload);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static void wg_json_indent(json_ctx_t *ctx, int direction);

static void wg_json_ctx_init(json_ctx_t *ctx, char **buffer, size_t *size,
                             size_t low_water_mark, int indent_offset) {
  ctx->buffer = buffer;
  ctx->size = size;
  ctx->low_water_mark = low_water_mark;
  memset(ctx->indent_buf, ' ', sizeof(ctx->indent_buf));
  ctx->indent_buf[0] = 0;
  ctx->indent_level = 0;
  ctx->indent_offset = indent_offset;
}

static void wg_json_write_record(json_ctx_t *ctx, ...) {
  bufprintf(ctx->buffer, ctx->size, "{");
  wg_json_indent(ctx, +1);

  // Invariant: output "cursor" is positioned at the end of the previous line.

  char *sep = "\n";  // First separator is newline.
  va_list ap;
  va_start(ap, ctx);
  const char *key = va_arg(ap, const char*);
  while (key != NULL) {
    json_handler_t handler = va_arg(ap, json_handler_t);
    void *payload = va_arg(ap, void*);

    bufprintf(ctx->buffer, ctx-> size, "%s%s\"%s\": ",
              sep, ctx->indent_buf, key);
    (*handler)(ctx, payload);

    key = va_arg(ap, const char*);
    sep = ",\n";  // Next separator is comma-newline.
  }
  va_end(ap);
  wg_json_indent(ctx, -1);
  bufprintf(ctx->buffer, ctx->size, "\n%s}", ctx->indent_buf);
}

static void wg_json_write_array(json_ctx_t *ctx,
                                json_iterator_t iterator,
                                void *payload) {
  bufprintf(ctx->buffer, ctx->size, "[");
  wg_json_indent(ctx, +1);

  // Invariant: output "cursor" is positioned at the end of the previous line.
  char *sep = "\n";  // First separator is newline.
  int result = (*iterator)(ctx, payload, 0);  // Any data in data structure?
  while (result == 0) {
    // Print previous separator, some indentation, then the next item.
    bufprintf(ctx->buffer, ctx->size, "%s%s", sep, ctx->indent_buf);
    result = (*iterator)(ctx, payload, 1);
    // Next separator is comma-newline.
    sep = ",\n";
  }
  wg_json_indent(ctx, -1);
  bufprintf(ctx->buffer, ctx->size, "\n%s]", ctx->indent_buf);
}

static void wg_json_quoted_string_handler(json_ctx_t *ctx, void *payload) {
  bufprintf(ctx->buffer, ctx->size, "\"%s\"", (const char*)payload);
}

static void wg_json_unquoted_string_handler(json_ctx_t *ctx, void *payload) {
  bufprintf(ctx->buffer, ctx->size, "%s", (const char*)payload);
}

static void wg_json_uint64_handler(json_ctx_t *ctx, void *payload) {
  bufprintf(ctx->buffer, ctx->size, "%" PRIu64, *(uint64_t*)payload);
}

static void wg_json_indent(json_ctx_t *ctx, int direction) {
  int old_indent_level = ctx->indent_level;
  ctx->indent_level += direction * ctx->indent_offset;
  if (old_indent_level >= 0 && old_indent_level < sizeof(ctx->indent_buf) &&
      ctx->indent_level >= 0 && ctx->indent_level < sizeof(ctx->indent_buf)) {
    ctx->indent_buf[old_indent_level] = ' ';
    ctx->indent_buf[ctx->indent_level] = 0;
  }
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
  server_ctx_t *server_ctx;
  credential_ctx_t *cred_ctx;
  oauth2_ctx_t *oauth2_ctx;
  tree_ctx_t *tree_ctx;
  pthread_mutex_t tree_mutex;
} wg_context_t;

static wg_context_t *wg_context_create(const char *project_id,
                                       const char *instance_id,
                                       const char *zone,
                                       const char *email,
                                       const char *key_file,
                                       const char *passphrase);
static void wg_context_destroy(wg_context_t *data);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------


static wg_context_t *wg_context_create(const char *project_id,
                                       const char *instance_id,
                                       const char *zone,
                                       const char *email,
                                       const char *key_file,
                                       const char *passphrase) {
  wg_context_t *ctx = malloc_zero(sizeof(*ctx));
  if (ctx == NULL) {
    ERROR("wg_context_create: malloc_zero failed");
    return NULL;
  }

  // Create the subcontext holding various pieces of server information.
  ctx->server_ctx = wg_server_ctx_create(project_id, instance_id, zone);
  if (ctx->server_ctx == NULL) {
    ERROR("write_kosak: wg_server_ctx_create failed.");
    wg_context_destroy(ctx);
    return NULL;
  }

  // Optionally create the subcontext holding the service account credentials.
  if (email != NULL && key_file != NULL && passphrase != NULL) {
    ctx->cred_ctx = wg_credential_ctx_create(email, key_file, passphrase);
    if (ctx->cred_ctx == NULL) {
      ERROR("write_kosak: wg_credential_context_create failed.");
      wg_context_destroy(ctx);
      return NULL;
    }
  }

  // Create the subcontext holding the oauth2 state.
  ctx->oauth2_ctx = wg_oauth2_cxt_create();
  if (ctx->oauth2_ctx == NULL) {
    ERROR("write_kosak: wg_oauth2_context_create failed.");
    wg_context_destroy(ctx);
    return NULL;
  }

  // Create the subcontext holding the value tree.
  ctx->tree_ctx = wg_tree_ctx_create();
  if (ctx->tree_ctx == NULL) {
    ERROR("write_kosak: tree_ctx_create failed.");
    wg_context_destroy(ctx);
    return NULL;
  }

  // Create the mutex controlling access to the value tree.
  if (pthread_mutex_init(&ctx->tree_mutex, NULL)) {
    ERROR("write_kosak: pthread_mutex_init failed: errno %d", errno);
    wg_context_destroy(ctx);
    return NULL;
  }
  return ctx;
}

static void wg_context_destroy(wg_context_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  pthread_mutex_destroy(&ctx->tree_mutex);
  wg_tree_ctx_destroy(ctx->tree_ctx);
  wg_oauth2_ctx_destroy(ctx->oauth2_ctx);
  wg_credential_ctx_destroy(ctx->cred_ctx);
  wg_server_ctx_destroy(ctx->server_ctx);
  sfree(ctx);
}

//==============================================================================
//==============================================================================
//==============================================================================
// Request submodule for formatting the InsertCollectdTimeseriesPointsRequest
//==============================================================================
//==============================================================================
//==============================================================================

// Formats some or all of the data in the tree as an
// InsertCollectdTimeseriesPointsRequest.
// 'buffer' and 'size' are as defined in bufprintf.
// 'low_water_mark' is used to signal to this routine to finish things up
// and close out the message. When there are 'low_water_mark' bytes left in the
// buffer, the method stops adding new items to the 'collectdPayloads' array
// and closes things up. The purpose is to try to always make well-formed
// JSON messages, even if the tree is large. One consequence of this is that
// this routine is not guaranteed to empty out the tree. Callers need to
// repeatedly call this routine (making entirely new
// InsertCollectdTimeseriesPointsRequest requests each time) until the tree
// is exhausted.
static void wg_request_CreateCollectdTimeseriesPointsRequest(
    char **buffer, size_t *size, size_t low_water_mark,
    const server_ctx_t *server_ctx, tree_ctx_t *tree_ctx);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static void wg_request_MonitoredResource_handler(json_ctx_t *json_ctx,
                                                 void *payload);
static void wg_request_MonitoredResource_labels_handler(json_ctx_t *json_ctx,
                                                        void *payload);
static void wg_request_CollectdPayloads_handler(json_ctx_t *json_ctx,
                                                void *payload);
static int wg_request_CollectdPayload_iterator(json_ctx_t *json_ctx,
                                               void *payload,
                                               int print_and_advance);
static void wg_request_CollectdValues_handler(json_ctx_t *json_ctx,
                                              void *payload);
static int wg_request_CollectdValue_iterator(json_ctx_t *json_ctx,
                                             void *payload,
                                             int print_and_advance);
static void wg_request_CollectdValueType_handler(json_ctx_t *json_ctx,
                                                 void *payload);
static void wg_request_Timestamp_handler(json_ctx_t *json_ctx, void *payload);
static void wg_request_Duration_handler(json_ctx_t *json_ctx, void *payload);

// From google/monitoring/v3/agent_service.proto
// message CreateCollectdTimeSeriesRequest {
//   string project_id = 1;
//   google.api.MonitoredResource resource = 2;
//   string collectd_version = 3;
//   repeated CollectdPayload collectd_payloads = 4;
// }
static void wg_request_CreateCollectdTimeseriesPointsRequest(
    char **buffer, size_t *size, size_t low_water_mark,
    const server_ctx_t *server_ctx, tree_ctx_t *tree_ctx) {
  json_ctx_t json_ctx;
  wg_json_ctx_init(&json_ctx, buffer, size, low_water_mark, JSON_PRETTY_INDENT);

  const char *collectd_useragent = COLLECTD_USERAGENT;
  wg_json_write_record(
      &json_ctx,
      "projectId", &wg_json_quoted_string_handler, server_ctx->project_id,
      "resource", &wg_request_MonitoredResource_handler, server_ctx,
      "collectdVersion", &wg_json_quoted_string_handler, collectd_useragent,
      "collectdPayloads", &wg_request_CollectdPayloads_handler, tree_ctx,
      NULL);
}

// From google/api/monitored_resource.proto
// message MonitoredResource {
//   string type = 1;
//   map<string, string> labels = 2;
// }
static void wg_request_MonitoredResource_handler(json_ctx_t *json_ctx,
                                                 void *payload) {
  const server_ctx_t *server_ctx = (const server_ctx_t*)payload;
  wg_json_write_record(
      json_ctx,
      "type", &wg_json_quoted_string_handler, "gce_instance",
      "labels", &wg_request_MonitoredResource_labels_handler, server_ctx,
      NULL);
}

static void wg_request_MonitoredResource_labels_handler(json_ctx_t *json_ctx,
                                                        void *payload) {
  const server_ctx_t *server_ctx = (const server_ctx_t*)payload;
  wg_json_write_record(
      json_ctx,
      "instance_id", &wg_json_quoted_string_handler, server_ctx->instance_id,
      "zone", &wg_json_quoted_string_handler, server_ctx->zone,
      NULL);
}

// Array of CollectdPayload
static void wg_request_CollectdPayloads_handler(json_ctx_t *json_ctx,
                                                void *payload) {
  tree_ctx_t *tree_ctx = (tree_ctx_t*)payload;
  wg_json_write_array(json_ctx,
                      &wg_request_CollectdPayload_iterator,
                      tree_ctx);
}

typedef struct {
  entry_set_t *entry_set;
  cdtime_t min_time;
} entry_set_and_min_time_t;

// message CollectdPayload {
//   repeated CollectdValue values = 1;
//   google.protobuf.Timestamp time = 2;
//   protobuf.Duration interval = 3;
//   string plugin = 4;
//   string plugin_instance = 5;
//   string type = 6;
//  string type_instance = 7;
// }
static int wg_request_CollectdPayload_iterator(json_ctx_t *json_ctx,
                                               void *payload,
                                               int print_and_advance) {
  tree_ctx_t *tree_ctx = (tree_ctx_t*)payload;
  if (print_and_advance) {
    mykey_t *key;
    entry_set_t *entry_set;
    if (wg_tree_pick(tree_ctx, &key, &entry_set) != 0) {
      return -1;
    }
    tree_ctx->nodes_in_use -= c_avl_size(entry_set->entry_tree);

    // wg_request_CollectdValues_handler has a side effect: as it processes the
    // entries in the tree, it updates 'min_time' in this struct.
    entry_set_and_min_time_t esmt = {
        .entry_set = entry_set,
        .min_time = 0
    };

    wg_json_write_record(
        json_ctx,
        "values", &wg_request_CollectdValues_handler, &esmt,
        "time", &wg_request_Timestamp_handler, &esmt.min_time,
        "interval", &wg_request_Duration_handler, &interval_g,
        "plugin", &wg_json_quoted_string_handler, key->plugin,
        "pluginInstance", &wg_json_quoted_string_handler, key->plugin_instance,
        "type", &wg_json_quoted_string_handler, key->type,
        "typeInstance", &wg_json_quoted_string_handler, key->type_instance,
        NULL);
    wg_mykey_destroy(key);
    wg_entry_set_destroy(entry_set);
  }
  // If we are close to running out of buffer, exit early so we can still
  // try to make a well-formed JSON document. This will leave some data in
  // 'tree' but that's ok, because the caller knows to keep trying until the
  // tree is empty.
  if (*json_ctx->size < json_ctx->low_water_mark) {
    return 1;
  }

  // If no more nodes in the tree, we are done.
  if (c_avl_size(tree_ctx->tree) == 0) {
    return 1;
  }
  return 0;
}

static void wg_request_CollectdValues_handler(json_ctx_t *json_ctx,
                                              void *payload) {
  entry_set_and_min_time_t *esmt = (entry_set_and_min_time_t*)payload;
  wg_json_write_array(json_ctx,
                      &wg_request_CollectdValue_iterator,
                      esmt);
}

//message CollectdValue {
//  optional CollectdValueType value = 1;
//  optional CollectdDsType dstype = 2;
//  optional string dsname = 3;
//}
static int wg_request_CollectdValue_iterator(json_ctx_t *json_ctx,
                                             void *payload,
                                             int print_and_advance) {
  entry_set_and_min_time_t *esmt = (entry_set_and_min_time_t*)payload;
  if (print_and_advance) {
    myentry_t *entry;
    if (wg_entry_set_pick(esmt->entry_set, &entry) != 0) {
      ERROR("write_kosak: wg_entry_set_pick failed");
      return -1;
    }
    if (esmt->min_time == 0 || entry->time < esmt->min_time) {
      esmt->min_time = entry->time;
    }
    wg_json_write_record(
        json_ctx,
        "dstype", &wg_json_quoted_string_handler, entry->type_static,
        "dsname", &wg_json_quoted_string_handler, entry->name,
        "value", &wg_request_CollectdValueType_handler, entry,
        NULL);
  }
  // If no more nodes in the tree, we are done.
  if (c_avl_size(esmt->entry_set->entry_tree) == 0) {
    return 1;
  }
  return 0;
}


//message CollectdValueType {
//  oneof value {
//    bytes unknown = 1;
//    int64 int64_value = 2;
//    uint64 uint64_value = 3;
//    double double_value = 4;
//  }
//}
static void wg_request_CollectdValueType_handler(json_ctx_t *json_ctx,
                                                 void *payload) {
  myentry_t *entry = (myentry_t*)payload;
  wg_json_write_record(
      json_ctx,
      entry->value_tag_static, &wg_json_unquoted_string_handler, entry->value,
      NULL);
}

//message Timestamp {
//  int64 seconds = 1;
//  int32 nanos = 2;
//}
static void wg_request_Timestamp_handler(json_ctx_t *json_ctx, void *payload) {
  cdtime_t *time_stamp = (cdtime_t*)payload;
  uint64_t sec = CDTIME_T_TO_TIME_T (*time_stamp);
  uint64_t ns = CDTIME_T_TO_NS (*time_stamp % 1073741824);
  wg_json_write_record(
      json_ctx,
      "seconds", &wg_json_uint64_handler, &sec,
      "nanos", &wg_json_uint64_handler, &ns,
      NULL);
}

//message Duration {
//  int64 seconds = 1;
//  int32 nanos = 2;
//}
static void wg_request_Duration_handler(json_ctx_t *json_ctx, void *payload) {
  // Duration happens to have the same structure as Timestamp, so just delegate
  // to json_dump_Timestamp.
  wg_request_Timestamp_handler(json_ctx, payload);
}

//==============================================================================
//==============================================================================
//==============================================================================
// Initialization module. Runs those things that need to be initialized from a
// single-threaded context.
//==============================================================================
//==============================================================================
//==============================================================================
static int wg_init(void) {
  curl_global_init(CURL_GLOBAL_SSL);
  return (0);
}

//==============================================================================
//==============================================================================
//==============================================================================
// Flush submodule. Flushes data collected in the tree to the server.
//==============================================================================
//==============================================================================
//==============================================================================
static int wg_flush(cdtime_t timeout,
                    const char *identifier __attribute__((unused)),
                    user_data_t *user_data);
static int wg_flush_tree(const server_ctx_t *server_ctx,
                         oauth2_ctx_t *oauth2_ctx,
                         const credential_ctx_t *cred_ctx,
                         tree_ctx_t *tree_to_flush);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
static char *wg_flush_formatSomeOfTreeAsJSON(const server_ctx_t *server_ctx,
                                             tree_ctx_t *tree_ctx);

static int wg_flush(cdtime_t timeout,
                    const char *identifier __attribute__((unused)),
                    user_data_t *user_data) {
  ERROR("Hi, what's the deal? Are we flushing?");
  wg_context_t *ctx = user_data->data;

  tree_ctx_t *new_tree = wg_tree_ctx_create();
  if (new_tree == NULL) {
    WARNING("write_kosak: wg_tree_ctx_create failed.");
    return -1;
  }

  pthread_mutex_lock(&ctx->tree_mutex);
  tree_ctx_t *tree_to_flush = ctx->tree_ctx;
  ctx->tree_ctx = new_tree;
  pthread_mutex_unlock(&ctx->tree_mutex);

  return wg_flush_tree(ctx->server_ctx,
                       ctx->oauth2_ctx,
                       ctx->cred_ctx,
                       tree_to_flush);
}

static int wg_flush_tree(const server_ctx_t *server_ctx,
                         oauth2_ctx_t *oauth2_ctx,
                         const credential_ctx_t *cred_ctx,
                         tree_ctx_t *tree_to_flush) {
  if (tree_to_flush == NULL) {
    return 0;
  }

  char url[256];
  int result = snprintf(url, sizeof(url),
                        ENDPOINT_FORMAT_STRING, server_ctx->project_id);
  if (result < 0 || result >= sizeof(url)) {
    ERROR("write_kosak: Can't build endpoint URL.");
    return -1;
  }
  ERROR("write_kosak: Endpoint URL is %s", url);

  char auth_header[256];
  if (wg_oauth2_get_auth_header(auth_header, sizeof(auth_header),
                                oauth2_ctx, cred_ctx) != 0) {
    ERROR("write_kosak: wg_oauth2_get_auth_header failed.");
    return -1;
  }
  size_t current_size = c_avl_size(tree_to_flush->tree);
  while (current_size > 0) {
    char *json = wg_flush_formatSomeOfTreeAsJSON(server_ctx, tree_to_flush);
    if (json == NULL) {
      ERROR("write_kosak: Error formatting tree as JSON");
      return -1;
    }
    kosatron_temp_dump(auth_header, json);
    // A successful response is the empty string. An unsuccessful response is
    // a detailed error message from Monarch.
    char response[2048];
    if (wg_curl_get_or_post(
        response, sizeof(response),
        url, auth_header, JSON_CONTENT_TYPE_HEADER, json) != 0) {
      ERROR("write_kosak: Error talking to the endpoint");
      return -1;
    }
    ERROR("write_kosak: response from endpoint was %s", response);
    sfree(json);
    size_t new_size = c_avl_size(tree_to_flush->tree);
    if (new_size == current_size) {
      ERROR("write_kosak: Failed to make progress flushing tree.");
      return -1;
    }
    current_size = new_size;
  }
  return 0;
}

// Converts the data in the tree into a InsertCollectdTimeseriesPointsRequest
// message (formatted in JSON format). Returns the result in a buffer owned by
// the caller. In the event of an error, returns NULL. This method is not
// guaranteed to empty the tree. The caller should call the method multiple
// times until the tree is empty. Caller owns the tree.
static char *wg_flush_formatSomeOfTreeAsJSON(const server_ctx_t *server_ctx,
                                             tree_ctx_t *tree_ctx) {
  size_t size = JSON_SOFT_TARGET_SIZE + JSON_LOW_WATER_MARK;
  char *buffer_start = malloc(size);
  if (buffer_start == NULL) {
    ERROR("write_kosak: Couldn't allocate %zd bytes for buffer", size);
    return NULL;
  }

  char *buffer = buffer_start;
  wg_request_CreateCollectdTimeseriesPointsRequest(
      &buffer, &size, JSON_LOW_WATER_MARK, server_ctx, tree_ctx);

  if (size < 2) {
    ERROR("write_kosak: buffer overflow (or other error) while building JSON"
        " message");
    sfree(buffer_start);
    return NULL;
  }
  return buffer_start;
}

//==============================================================================
//==============================================================================
//==============================================================================
// Write submodule. Takes data provided by collectd and stores it in an
// intermediate form (grouped by key). When the tree is large enough, flushes
// it to the server.
//==============================================================================
//==============================================================================
//==============================================================================
static int wg_write(const data_set_t *ds, const value_list_t *vl,
                    user_data_t *user_data);

//------------------------------------------------------------------------------
// Private implementation starts here.
//------------------------------------------------------------------------------
// Based on the schema 's', extracts a value from 'v' and stringifies it,
// storing the resultant string in the buffer defined by 'buffer' and
// 'buffer_size'. Additionally, stores the type of the value as a (statically-
// allocated) string in 'type_static', and the value tag as a (statically-
// allocated) string in 'value_tag_static'.
// Appropriate values for 'type_static' come from the 'CollectdDsType' enum in
// the proto definition. Appropriate values for 'value_tag_static' come from
// the 'oneof' field names in the 'CollectdValueType' proto.
static int wg_get_vl_value(const char **type_static,
                           const char **value_tag_static,
                           char *buffer, size_t buffer_size,
                           const data_source_t *s, const value_t *v);

static entry_set_t *wg_tree_lookup_or_create_entry_set(tree_ctx_t *tree_ctx,
                                                       const value_list_t *vl);

// Hack for now to get Monarch to work.
static int superhack_validate_value(const value_list_t *vl) {
  if (strcmp(vl->plugin, "interface") != 0) {
    return -1;  // Let's not even bother with non-interface stuff for now.
  }
  if (strcmp(vl->type, "if_octets") != 0) {
    return -1;
  }
  return 0;
}

// Hack for now to get Monarch to work.
static void superhack_fix_value(const value_list_t *vl,
                                const char **type_static,
                                const char **value_tag_static,
                                const data_source_t *s, const value_t *v) {
  if (strcmp(vl->plugin, "interface") == 0) {
    // normally it's int64Value
    *value_tag_static = "doubleValue";
  }
}

static int wg_write(const data_set_t *ds, const value_list_t *vl,
                    user_data_t *user_data) {
  if (ds->ds_num == 0) {
    // Nothing to do.
    return 0;
  }

  // A hack so that we avoid sending duplicate keys to Monarch.
  if (superhack_validate_value(vl) != 0) {
    // Nothing to do.
    return 0;
  }

  wg_context_t *ctx = user_data->data;

  // Declare these variables here so that we can have orderly cleanup on both
  // successful and error exits.
  myentry_t **my_entries = NULL;
  tree_ctx_t *overflow_tree = NULL;
  tree_ctx_t *tree_to_flush = NULL;
  int lock_held = 0;
  int result = -1;  // Pessimistically assume error.

  // Transform the value_list_t into an array of myentry_t so we can use it
  // conveniently.
  assert(ds->ds_num == vl->values_len);
  my_entries = malloc_zero(sizeof(*my_entries) * ds->ds_num);
  if (my_entries == NULL) {
    ERROR("write_kosak: allocating my_entries failed");
    goto leave;
  }
  int i;
  for (i = 0; i < ds->ds_num; ++i) {
    data_source_t *s = &ds->ds[i];
    value_t *v = &vl->values[i];
    char value_as_string[128];
    const char *type_as_static_string;
    const char *value_tag_as_static_string;
    if (wg_get_vl_value(&type_as_static_string,
                        &value_tag_as_static_string,
                        value_as_string, sizeof(value_as_string),
                        s, v) != 0) {
      WARNING("write_kosak: failed to wg_get_vl_value");
      goto leave;
    }
    superhack_fix_value(vl,
                        &type_as_static_string,
                        &value_tag_as_static_string,
                        s, v);

    my_entries[i] = wg_myentry_create(
        s->name,
        type_as_static_string, value_tag_as_static_string,
        value_as_string, vl->time);
    if (my_entries[i] == NULL) {
      WARNING("write_kosak: wg_myentry_create failed");
      goto leave;
    }
  }

  // For a given entry, we attempt to insert it into the entry set at
  // ctx->tree_ctx[mykey]. If that would lead to a collision, we instead insert
  // the entry into an "overflow" entry set at overflow_tree[mykey].
  // If there is a collision even with the "overflow" entry_set (doesn't happen
  // in practice), we drop the entry.
  //
  // After all the entries in the list are processed, if the "overflow"
  // entry_set has any entries in it, then it's time to flush the tree. We
  // 1. let flush_tree = save ctx->tree_ctx
  // 2. let ctx->tree_ctx = overflow tree

  overflow_tree = wg_tree_ctx_create();
  if (overflow_tree == NULL) {
    ERROR("write_kosak: error creating overflow tree");
    goto leave;
  }

  pthread_mutex_lock(&ctx->tree_mutex);
  lock_held = 1;

  entry_set_t *current_set =
      wg_tree_lookup_or_create_entry_set(ctx->tree_ctx, vl);
  entry_set_t *overflow_set =
      wg_tree_lookup_or_create_entry_set(overflow_tree, vl);
  if (current_set == NULL || overflow_set == NULL) {
    ERROR("write_kosak: wg_tree_lookup_or_create_entry_set failed");
    goto leave;
  }

  for (i = 0; i < ds->ds_num; ++i) {
    if (wg_entry_set_insert(current_set, my_entries[i]) == 0) {
      ++ctx->tree_ctx->nodes_in_use;
    } else if (wg_entry_set_insert(overflow_set, my_entries[i]) == 0) {
      ++overflow_tree->nodes_in_use;
    } else {
      ERROR("write_kosak: Couldn't insert entry into either current or"
          " overflow entry set");
      continue;  // Not fatal.
    }
    my_entries[i] = NULL;  // Now owned by one of {this,next}_gen_entry_set.
  }

  if (c_avl_size(overflow_set->entry_tree) != 0) {
    tree_to_flush = ctx->tree_ctx;
    ctx->tree_ctx = overflow_tree;
    overflow_tree = NULL;  // Now owned by ctx.
  }
  lock_held = 0;
  pthread_mutex_unlock(&ctx->tree_mutex);

  result = wg_flush_tree(ctx->server_ctx,
                         ctx->oauth2_ctx,
                         ctx->cred_ctx,
                         tree_to_flush);

 leave:
  if (lock_held) {
    pthread_mutex_unlock(&ctx->tree_mutex);
  }

  wg_tree_ctx_destroy(tree_to_flush);
  wg_tree_ctx_destroy(overflow_tree);
  for (i = 0; i < ds->ds_num; ++i) {
    wg_myentry_destroy(my_entries[i]);
  }
  sfree(my_entries);
  return result;
}

static entry_set_t *wg_tree_lookup_or_create_entry_set(tree_ctx_t *tree_ctx,
                                                       const value_list_t *vl) {
  mykey_t *new_key = NULL;
  entry_set_t *entry_set = NULL;
  entry_set_t *result = NULL;

  new_key = wg_mykey_create(vl->host, vl->plugin, vl->plugin_instance,
                            vl->type, vl->type_instance);
  if (new_key == NULL) {
    ERROR("write_kosak: error in wg_mykey_create");
    goto leave;
  }
  if (wg_tree_get(tree_ctx, new_key, &entry_set) == 0) {
    // Tree already has a key and and entry_set. Deallocate new_key and return
    // the existing entry_set.
    result = entry_set;
    entry_set = NULL;
    goto leave;
  }

  entry_set = wg_entry_set_create();
  if (entry_set == NULL) {
    ERROR("write_kosak: wg_tree_lookup_or_create_entry_set: "
        "wg_entry_set_create failed");
    goto leave;
  }

  if (wg_tree_insert(tree_ctx, new_key, entry_set) != 0) {
    ERROR("write_kosak: failure to wg_tree_insert.");
    goto leave;
  }
  new_key = NULL;  // Tree now owns new_key and entry_set.
  result = entry_set;
  entry_set = NULL;

 leave:
  wg_entry_set_destroy(entry_set);
  wg_mykey_destroy(new_key);
  return result;
}

static int wg_get_vl_value(const char **type_static,
                           const char **value_tag_static,
                           char *buffer, size_t buffer_size,
                           const data_source_t *s, const value_t *v) {
  if (buffer_size == 0) {
    return -1;
  }
  buffer[buffer_size] = 0;
  switch (s->type) {
    case DS_TYPE_GAUGE:
      if (isfinite(v->gauge)) {
        *type_static = "gauge";
        *value_tag_static = "doubleValue";
        snprintf(buffer, buffer_size, "%f", v->gauge);
        return 0;
      } else {
        ERROR("write_kosak: can not take infinite value");
        return (-1);
      }
    case DS_TYPE_COUNTER:
      *type_static = "counter";
      *value_tag_static = "uint64Value";
      snprintf(buffer, buffer_size, "%llu", v->counter);
      return 0;
    case DS_TYPE_DERIVE:
      *type_static = "derive";
      *value_tag_static = "int64Value";
      snprintf(buffer, buffer_size, "%" PRIi64, v->derive);
      return 0;
    case DS_TYPE_ABSOLUTE:
      *type_static = "absolute";
      *value_tag_static = "uint64Value";
      snprintf(buffer, buffer_size, "%" PRIu64, v->absolute);
      return 0;
    default:
      ERROR("write_kosak: Unknown data source type: %i", s->type);
      return (-1);
  }
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
static void wg_context_destroy_void(void *ctx);


static int wg_config(oconfig_item_t *ci) {
  wg_configbuilder_t *cb = wg_configbuilder_create(ci);
  if (cb == NULL) {
    ERROR("write_kosak: wg_configbuilder_create failed");
    return -1;
  }

  wg_context_t *ctx = wg_context_create(cb->project_id,
                                        cb->instance_id,
                                        cb->zone,
                                        cb->email,
                                        cb->key_file,
                                        cb->passphrase);
  wg_configbuilder_destroy(cb);
  cb = NULL;

  if (ctx == NULL) {
    ERROR("write_kosak: wg_context_create failed.");
    return -1;
  }

  user_data_t user_data = {
      .data = ctx,
      .free_func = NULL
  };
  plugin_register_flush(this_plugin_name, &wg_flush, &user_data);
  user_data.free_func = &wg_context_destroy_void;
  plugin_register_write(this_plugin_name, &wg_write, &user_data);

  return 0;
}

static wg_configbuilder_t *wg_configbuilder_create(oconfig_item_t *ci) {
  wg_configbuilder_t *cb = NULL;
  char *long_zone = NULL;
  wg_configbuilder_t *result = NULL;  // Assume error.

  cb = malloc_zero(sizeof(*cb));
  if (cb == NULL) {
    ERROR("write_kosak: Can't allocate wg_configbuilder_t");
    goto leave;
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

#define ARRAYSIZE(a) sizeof(a)/sizeof((a)[0])
  assert(ARRAYSIZE(keys) == ARRAYSIZE(locations));
  int parse_errors = 0;
  int c, k;
  for (c = 0; c < ci->children_num; ++c) {
    oconfig_item_t *child = &ci->children[c];
    for (k = 0; k < ARRAYSIZE(keys); ++k) {
      if (strcasecmp(child->key, keys[k]) == 0) {
        if (cf_util_get_string(child, locations[k]) != 0) {
          ERROR("write_kosak: cf_util_get_string failed for key %s",
                child->key);
          ++parse_errors;
        }
        break;
      }
    }
    if (k == ARRAYSIZE(keys)) {
      ERROR ("write_kosak: Invalid configuration option: %s.",
          child->key);
      ++parse_errors;
    }
  }
#undef ARRAYSIZE

  if (parse_errors > 0) {
    ERROR("write_kosak: There were %d parse errors reading config file.",
          parse_errors);
    goto leave;
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
    ERROR("write_kosak: Error reading configuration."
        " Either all of Email, PrivateKeyFile, and PrivateKeyPass "
        " must be set, or none of them must be set. The provided config file"
        " set %d of them.", num_set);
    goto leave;
  }

  // For items not specified in the config file, try to get them from the
  // metadata server.
  if (cb->project_id == NULL) {
    cb->project_id =
        wg_configbuilder_get_from_metadata_server(METADATA_PROJECT_ID);
    if (cb->project_id == NULL) {
      ERROR("write_kosak: Can't get project_id from metadata server "
          " (and not specified in the config file).");
      goto leave;
    }
  }
  if (cb->instance_id == NULL) {
    cb->instance_id =
        wg_configbuilder_get_from_metadata_server(METADATA_INSTANCE_ID);
    if (cb->instance_id == NULL) {
      ERROR("write_kosak: Can't get instance_id from metadata server "
          " (and not specified in the config file).");
      goto leave;
    }
  }
  long_zone = wg_configbuilder_get_from_metadata_server(METADATA_ZONE);
  if (long_zone == NULL) {
    ERROR("write_kosak: Can't get zone from metadata server");
    goto leave;
  }

  // Returned zone is of the form
  // projects/$PROJECT_ID/zones/$ZONE
  // Use the below to hackily extract $ZONE
  const char *last_slash = strrchr(long_zone, '/');
  if (last_slash == NULL) {
    ERROR("write_kosak: Failed to parse zone.");
    goto leave;
  }

  cb->zone = sstrdup(last_slash + 1);
  if (cb->zone == NULL) {
    ERROR("write_kosak: wg_configbuilder_create: sstrdup failed");
    goto leave;
  }

  result = cb;  // Success!
  cb = NULL;

 leave:
  sfree(long_zone);
  wg_configbuilder_destroy(cb);
  return result;
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
  if (wg_curl_get_or_post(
      buffer, sizeof(buffer), url, GOOGLE_METADATA_HEADER, NULL, NULL) != 0) {
    return NULL;
  }
  return sstrdup(buffer);
}

static void wg_context_destroy_void(void *ctx) {
  return wg_context_destroy((wg_context_t*)ctx);
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
