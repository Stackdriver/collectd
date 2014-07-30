/**
 * collectd - src/write_gcm.c
 * Copyright (C) 2014  Zhihua Wen
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
 *   Zhihua Wen <wenzhihua@gmail.com>
 **/

#include <curl/curl.h>
#include "collectd.h"
#include "common.h"
#include "configfile.h"
#include "libyajl/src/api/yajl_tree.h"
#include "plugin.h"
#include "utils_avltree.h"

#if HAVE_LIBSSL
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

#if HAVE_PTHREAD_H
#include <pthread.h>
#endif

/*
 * Private variables
 */
/* Max send buffer size, since there will be only one writer thread and
 * monitoring api supports up to 100K bytes in one request, 64K is reasonable
 */
#define MAX_BUFFER_SIZE 65536
#define MAX_TOKEN_REQUEST_SIZE 4096
#define MAX_ENCODE_SIZE 2048
#define MAX_TIMESTAMP_SIZE 128

#define PLUGIN_INSTANCE_LABEL "plugin_instance"
#define TYPE_INSTANCE_LABEL "type_instance"
#define SERVICE_LABEL "cloud.googleapis.com/service"
#define RESOURCE_ID_LABEL "compute.googleapis.com/resource_id"
#define METRIC_LABEL_PREFIX "custom.cloudmonitoring.googleapis.com"
#define DEFAULT_SERVICE "compute.googleapis.com"

#define MONITORING_URL \
  "https://www.googleapis.com/cloudmonitoring/v2beta2"
#define MONITORING_SCOPE "https://www.googleapis.com/auth/monitoring"
#define GCE_METADATA_FLAVOR "Metadata-Flavor: Google"
#define METADATA_PREFIX "http://169.254.169.254/"
//#define METADATA_PREFIX "http://127.0.0.1:4090/"
#define METADATA_HEADER "X-Google-Metadata-Request: True"
#define META_DATA_TOKEN_URL \
  METADATA_PREFIX "computeMetadata/v1/instance/service-accounts/default/token"
#define META_DATA_SCOPE_URL                                   \
  METADATA_PREFIX                                             \
      "computeMetadata/v1/instance/service-accounts/default/" \
      "scopes"
#define METADATA_PROJECT_URL \
  METADATA_PREFIX "computeMetadata/v1/project/numeric-project-id"
#define METADATA_RESOURCE_ID_URL \
  METADATA_PREFIX "computeMetadata/v1/instance/id"

struct wg_metric_cache_s {
  cdtime_t vl_time;
  cdtime_t start_time;
};
typedef struct wg_metric_cache_s wg_metric_cache_t;

struct wg_callback_s {
  int timeseries_count;
  char *token;
  char *project;
  char *resource_id;
  char *service;
  char *url;
  char *token_url;
  char *report_this_plugin;
  char *report_this_plugin_instance;
  CURL *curl;
  struct curl_slist *headers;
  char curl_errbuf[CURL_ERROR_SIZE];
  char send_buffer[MAX_BUFFER_SIZE];
  size_t send_buffer_free;
  size_t send_buffer_fill;
  cdtime_t send_buffer_init_time;
  c_avl_tree_t *metric_name_tree;
  c_avl_tree_t *metric_buffer_tree;
  c_avl_tree_t *stream_key_tree;
  char str_init_time[MAX_TIMESTAMP_SIZE];
  cdtime_t token_expire_time;
  pthread_mutex_t send_lock;
#if HAVE_LIBSSL
  EVP_PKEY *pkey;
  char *email;
#endif
};
typedef struct wg_callback_s wg_callback_t;

struct wg_memory_s {
  char *memory;
  size_t size;
};
typedef struct wg_memory_s wg_memory_t;

#if HAVE_LIBSSL
/*base64 encoding of {"alg":"RS256","typ":"JWT"}  */
static const char header64[] = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
static const char jwt_claim_fmt[] =
    "{\
\"iss\":\"%s\",\
\"scope\":\"https://www.googleapis.com/auth/monitoring.readonly\",\
\"aud\":\"https://accounts.google.com/o/oauth2/token\",\
\"exp\":%ld,\"iat\":%ld\
}";
#endif

#define BUFFER_ADD(...)                                                     \
  do {                                                                      \
    int status;                                                             \
    status = ssnprintf(buffer + offset, buffer_size - offset, __VA_ARGS__); \
    if (status < 1) {                                                       \
      return (-1);                                                          \
    } else if (((size_t)status) >= (buffer_size - offset)) {                \
      return (-ENOMEM);                                                     \
    } else                                                                  \
      offset += ((size_t)status);                                           \
  } while (0)

static size_t wg_write_memory_cb(void *contents, size_t size, size_t nmemb,
                                 void *userp) {
  size_t realsize = size * nmemb;
  wg_memory_t *mem = (wg_memory_t *)userp;

  if (0x7FFFFFF0 < mem->size || 0x7FFFFFF0 - mem->size < realsize) {
    ERROR("integer overflow");
    return 0;
  }

  mem->memory = (char *)realloc((void *)mem->memory, mem->size + realsize + 1);
  if (mem->memory == NULL) {
    /* out of memory! */
    ERROR("wg_write_memory_cb: not enough memory (realloc returned NULL)");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
  return realsize;
} /* }}} size_t wg_write_memory_cb */

static int wg_get_vl_value(char *buffer, size_t buffer_size, /* {{{ */
                           const data_set_t *ds, const value_list_t *vl,
                           int i) {
  size_t offset = 0;
  memset(buffer, 0, buffer_size);

  if (ds->ds[i].type == DS_TYPE_GAUGE) {
    if (isfinite(vl->values[i].gauge))
      BUFFER_ADD("%f", vl->values[i].gauge);
    else {
      ERROR("write_gcm: can not take infinite value");
      return (-1);
    }
  } else if (ds->ds[i].type == DS_TYPE_COUNTER)
    BUFFER_ADD("%llu", vl->values[i].counter);
  else if (ds->ds[i].type == DS_TYPE_DERIVE)
    BUFFER_ADD("%" PRIi64, vl->values[i].derive);
  else if (ds->ds[i].type == DS_TYPE_ABSOLUTE)
    BUFFER_ADD("%" PRIu64, vl->values[i].absolute);
  else {
    ERROR("write_gcm: Unknown data source type: %i", ds->ds[i].type);
    return (-1);
  }
  return (0);
} /* }}} int get_vl_value */

static int wg_post_url(const char *url, const char *header,
                       const char *body) /* {{{ */
{
  CURL *curl;
  int status = 0;
  long http_code = 0;
  char curl_errbuf[CURL_ERROR_SIZE];
  struct curl_slist *curl_header = NULL;

  curl = curl_easy_init();
  if (!curl) {
    ERROR("wg_post_url: curl_easy_init failed.");
    status = -1;
    goto bailout;
  }

  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

  /*set the header if it's not null*/
  if (header) {
    curl_header = curl_slist_append(curl_header, "Accept:  */*");
    curl_header = curl_slist_append(curl_header, header);
    curl_header = curl_slist_append(curl_header, "Expect:");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_header);
  }

#if defined(COLLECT_DEBUG) && COLLECT_DEBUG
  wg_memory_t data;
  data.size = 0;
  data.memory = NULL;
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wg_write_memory_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
#endif

  status = curl_easy_perform(curl);
  if (status != CURLE_OK) {
    ERROR("wg_post_url: curl_easy_perform failed with status %i: %s", status,
          curl_errbuf);
    status = -1;
    goto bailout;
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
      ERROR("wg_post_url: http code: %ld", http_code);
#if defined(COLLECT_DEBUG) && COLLECT_DEBUG
      ERROR("wg_post_url: request:\n %s", body);
      ERROR("wg_post_url: error_msg: %s", data.memory);
#endif
      status = -1;
      goto bailout;
    }
    status = 0;
  }

bailout:
#if defined(COLLECT_DEBUG) && COLLECT_DEBUG
  sfree(data.memory);
#endif
  if (curl) {
    curl_easy_cleanup(curl);
  }
  if (curl_header) {
    curl_slist_free_all(curl_header);
  }
  return status;
} /* }}} int wg_read_url */

static int wg_create_metric(const char *metric_name, /* {{{ */
                            const data_set_t *ds, int i, const value_list_t *vl,
                            wg_callback_t *cb) {
  char buffer[2048];
  char url[256];
  size_t offset = 0;
  int status;
  int buffer_size = sizeof(buffer);
  BUFFER_ADD("{\n");                              /* body */
  BUFFER_ADD("\"name\": \"%s\",\n", metric_name); /* metric_name */
  BUFFER_ADD("\"typeDescriptor\": {\n");          /* typeDescriptor */
  BUFFER_ADD("\"metricType\": \"%s\",\n",
             ds->ds[i].type == DS_TYPE_GAUGE ? "gauge" : "cumulative");
  BUFFER_ADD("\"valueType\" : \"double\"\n");
  BUFFER_ADD("},\n"); /* typeDescriptor */
  BUFFER_ADD(
      " \"labels\": [\n"
      "  {\"key\": \"" SERVICE_LABEL
      "\"},"
      "  {\"key\": \"" RESOURCE_ID_LABEL
      "\"},"
      "  {\"key\": \"" METRIC_LABEL_PREFIX "/" TYPE_INSTANCE_LABEL
      "\"},"
      "  {\"key\": \"" METRIC_LABEL_PREFIX "/" PLUGIN_INSTANCE_LABEL
      "\"}"
      " ]\n");       // labels
  BUFFER_ADD("}\n"); /* body */

  status = ssnprintf(url, sizeof(url),
                     "%s/projects/%s/metricDescriptors?access_token=%s",
                     cb->url, cb->project, cb->token);
  if (status < 1) {
    return (-1);
  } else if ((size_t)status >= sizeof(url)) {
    return (-ENOMEM);
  }
  status = wg_post_url(url, "Content-Type: application/json", buffer);
  if (status != 0) {
    ERROR("wg_create_metric %s failed", metric_name);
  } else {
    DEBUG("wg_create_metric %s successful", metric_name);
  }
  return status;
} /* }}} int create_metric */

static int value_to_timeseries(char *buffer, size_t buffer_size, /* {{{ */
                               const data_set_t *ds, const value_list_t *vl,
                               wg_callback_t *cb, int i,
                               wg_metric_cache_t *mb) {
  char temp[512];
  char init_time[512];
  char metric_name[256];
  size_t offset = 0;
  int status;
  int len;
  memset(buffer, 0, buffer_size);

  BUFFER_ADD("{\n");                     /* timeseries */
  BUFFER_ADD("\"timeseriesDesc\": {\n"); /* timeseriesDesc */
  /* project id */
  BUFFER_ADD("\"project\":%s,\n", cb->project);

  /* metric_name */
  if (ds->ds[i].name && strcasecmp(ds->ds[i].name, "value") != 0) {
    /* METRIC_LABEL_PREFIX/plugin/type_dsnames */
    status = ssnprintf(metric_name, sizeof(metric_name),
                       METRIC_LABEL_PREFIX "/%s/%s_%s", vl->plugin, vl->type,
                       ds->ds[i].name);
  } else {
    /* METRIC_LABEL_PREFIX/plugin/type */
    status = ssnprintf(metric_name, sizeof(metric_name),
                       METRIC_LABEL_PREFIX "/%s/%s", vl->plugin, vl->type);
  }
  if ((status < 1) || (status >= sizeof(metric_name))) {
    ERROR("value_to_timeseries: construct metric_name failed.");
    return (-1);
  }
  BUFFER_ADD("\"metric\":\"%s\",\n", metric_name); /* metric_name */

  /* if the metric name is not found in the cache, create this metric and add
   * the metric name to the cache */
  if (c_avl_get(cb->metric_name_tree, metric_name, NULL) != 0) {
    c_avl_insert(cb->metric_name_tree, strdup(metric_name), NULL);
    wg_create_metric(metric_name, ds, i, vl, cb);
  }

  BUFFER_ADD("\"labels\":{\n"); /* labels */

  if (vl->type_instance && vl->type_instance[0] != '\0') {
    BUFFER_ADD("\"" METRIC_LABEL_PREFIX "/" TYPE_INSTANCE_LABEL "\":\"%s\"",
               vl->type_instance);
  }

  if (vl->plugin_instance && vl->plugin_instance[0] != '\0') {
    if (vl->type_instance && vl->type_instance[0] != '\0') {
      BUFFER_ADD(",");
    }
    BUFFER_ADD("\"" METRIC_LABEL_PREFIX "/" PLUGIN_INSTANCE_LABEL "\":\"%s\"",
               vl->plugin_instance);
  }
  BUFFER_ADD("}\n");  /* labels */
  BUFFER_ADD("},\n"); /* timeseriesDesc */

  BUFFER_ADD("\"point\": [\n"); /* points */
  BUFFER_ADD("{\n");
  /* start and end time, for gauge metric, start = end, otherwise it's
   * cumulative metric,  end the current time and start = call back init time
   * - interval */
  len = cdtime_to_iso8601(temp, sizeof(temp), mb->vl_time);
  if (len == 0) {
    ERROR(
        "write_gcm value_to_timeseries: Failed to convert time to ISO 8601 "
        "format");
    return -1;
  }
  if (ds->ds[i].type == DS_TYPE_GAUGE) {
    BUFFER_ADD("\"start\":\"%s\",\n", temp);
  } else {
    if (mb->start_time == 0) {
      mb->start_time = mb->vl_time;
    }
    len = cdtime_to_iso8601(init_time, sizeof(init_time), mb->start_time);
    if (len == 0) {
      ERROR(
          "write_gcm value_to_timeseries: Failed to convert time to ISO 8601 "
          "format");
      return -1;
    }
    BUFFER_ADD("\"start\":\"%s\",\n", init_time);
  };
  BUFFER_ADD("\"end\":\"%s\",\n", temp);

  /* value in the point */
  status = wg_get_vl_value(temp, sizeof(temp), ds, vl, i);
  if (status != 0) return (status);
  BUFFER_ADD("\"doubleValue\":%s", temp);
  BUFFER_ADD("}\n");
  BUFFER_ADD("]\n"); /* points */
  BUFFER_ADD("},");  /* timeseries */
  return (0);
} /* }}} int value_to_timeseries */

static int value_list_to_timeseries(char *buffer, size_t buffer_size, /* {{{ */
                                    const data_set_t *ds,
                                    const value_list_t *vl, wg_callback_t *cb) {
  char temp[2048];
  char metric_key[256];
  wg_metric_cache_t *mb;
  size_t offset = 0;
  int status;
  int i;

  memset(buffer, 0, buffer_size);

  if (cb->report_this_plugin &&
      strncasecmp(vl->plugin, cb->report_this_plugin, sizeof(vl->plugin)) != 0)
    /* Ignore this timeseries */
    return (0);
  if (cb->report_this_plugin_instance &&
      strncasecmp(vl->plugin_instance, cb->report_this_plugin_instance,
                  sizeof(vl->plugin_instance)) != 0)
    /* Ignore this timeseries */
    return (0);

  memset(buffer, 0, buffer_size);

  if (FORMAT_VL(metric_key, sizeof(metric_key), vl) != 0) {
    ERROR("value_to_timeseries: FORMAT_VL failed.");
    return (-1);
  }

  if (c_avl_get(cb->metric_buffer_tree, metric_key, (void *)&mb) != 0) {
    mb = (wg_metric_cache_t *)malloc(sizeof(wg_metric_cache_t));
    mb->vl_time = 0;
    mb->start_time = 0;
    c_avl_insert(cb->metric_buffer_tree, strdup(metric_key), mb);
  }
  cdtime_t vl_time = vl->time - vl->time % vl->interval;

  mb->vl_time = mb->vl_time < vl_time ? vl_time : mb->vl_time + vl->interval;

  for (i = 0; i < ds->ds_num; i++) {
    status = value_to_timeseries(temp, sizeof(temp), ds, vl, cb, i, mb);
    if (status == 0) {
      BUFFER_ADD("%s", temp);
    } else {
      return status;
    }
  }
  DEBUG("write_gcm: value_list_to_timeseries: buffer = %s;", buffer);
  return (0);
} /* }}} int value_list_to_timeseries */

/* the caller of this function must make sure *ret_buffer_free >= 3 */
static int format_timeseries_nocheck(char *buffer, /* {{{ */
                                     size_t *ret_buffer_fill,
                                     size_t *ret_buffer_free,
                                     const data_set_t *ds,
                                     const value_list_t *vl,
                                     wg_callback_t *cb) {
  char temp[(*ret_buffer_free) > 2 ? (*ret_buffer_free) - 2 : 100];
  size_t temp_size;
  int status;

  if (*ret_buffer_free < 3) return (-ENOMEM);
  status = value_list_to_timeseries(temp, sizeof(temp), ds, vl, cb);
  if (status != 0) return (status);
  temp_size = strlen(temp);

  memcpy(buffer + (*ret_buffer_fill), temp, temp_size + 1);
  (*ret_buffer_fill) += temp_size;
  (*ret_buffer_free) -= temp_size;
  cb->timeseries_count++;
  return (0);
} /* }}} int format_timeseries_nocheck */

int format_timeseries(char *buffer, /* {{{ */
                      size_t *ret_buffer_fill, size_t *ret_buffer_free,
                      const data_set_t *ds, const value_list_t *vl,
                      wg_callback_t *cb) {
  if ((buffer == NULL) || (ret_buffer_fill == NULL) ||
      (ret_buffer_free == NULL) || (ds == NULL) || (vl == NULL))
    return (-EINVAL);

  if (*ret_buffer_free < 3) return (-ENOMEM);

  return (format_timeseries_nocheck(buffer, ret_buffer_fill, ret_buffer_free,
                                    ds, vl, cb));
} /* }}} int format_timeseries */

static int format_timeseries_initialize(char *buffer, /* {{{ */
                                        size_t *ret_buffer_fill,
                                        size_t *ret_buffer_free,
                                        wg_callback_t *cb) {
  size_t ret;
  size_t buffer_fill;
  size_t buffer_free;

  if ((buffer == NULL) || (ret_buffer_fill == NULL) ||
      (ret_buffer_free == NULL))
    return (-EINVAL);

  buffer_fill = *ret_buffer_fill;
  buffer_free = *ret_buffer_free;

  buffer_free = buffer_fill + buffer_free;
  buffer_fill = 0;

  if (buffer_free < 3) return (-ENOMEM);

  memset(buffer, 0, buffer_free);

  /* add the initial bracket and the common labels and the begining of
   * timeseries
   */

  ret = ssnprintf(buffer, buffer_free,
                  "{\"commonLabels\": {"
                  "\"" SERVICE_LABEL
                  "\": \"%s\","
                  "\"" RESOURCE_ID_LABEL
                  "\": \"%s\"},"
                  "\"timeseries\":[",
                  cb->service, cb->resource_id);

  if (ret < 1) {
    return (-1);
  } else if (ret >= buffer_free) {
    return (-ENOMEM);
  } else {
    buffer_fill += ret;
    buffer_free -= ret;
  }

  *ret_buffer_fill = buffer_fill;
  *ret_buffer_free = buffer_free;

  return (0);
} /* }}} int format_timeseries_initialize */

static int format_timeseries_finalize(char *buffer, /* {{{ */
                                      size_t *ret_buffer_fill,
                                      size_t *ret_buffer_free) {
  size_t pos;

  if ((buffer == NULL) || (ret_buffer_fill == NULL) ||
      (ret_buffer_free == NULL)) {
    return (-EINVAL);
  }

  if (*ret_buffer_free < 2) return (-ENOMEM);

  /* add ending square and curly bracket */
  pos = *ret_buffer_fill;
  if (pos <= 0) {
    return (-EINVAL);
  }

  // replace the last comma with ']'
  buffer[pos - 1] = ']';
  buffer[pos] = '}';
  buffer[pos + 1] = 0;

  (*ret_buffer_fill) += 1;
  (*ret_buffer_free) -= 1;

  return (0);
} /* }}} int format_timeseries_finalize */

static void wg_reset_buffer(wg_callback_t *cb) /* {{{ */
{
  memset(cb->send_buffer, 0, sizeof(cb->send_buffer));
  cb->timeseries_count = 0;
  cb->send_buffer_free = sizeof(cb->send_buffer);
  cb->send_buffer_fill = 0;
  cb->send_buffer_init_time = cdtime();

  format_timeseries_initialize(cb->send_buffer, &cb->send_buffer_fill,
                               &cb->send_buffer_free, cb);
} /* }}} wg_reset_buffer */

#if HAVE_LIBSSL
static EVP_PKEY *wg_load_pkey_internal(/* {{{ */
                                       const char *pkcs12_key_path,
                                       const char *pass) {
  X509 *cert = NULL;
  STACK_OF(X509) *ca = NULL;
  PKCS12 *p12 = NULL;
  EVP_PKEY *pkey = NULL;

  OpenSSL_add_all_algorithms();
  FILE *fp = fopen(pkcs12_key_path, "rb");
  if (fp == NULL) {
    ERROR("wg_load_pkey: open privatekey file on (%s) failed, errno(%d)\n",
          pkcs12_key_path, errno);
    goto bailout;
  }

  p12 = d2i_PKCS12_fp(fp, NULL);
  fclose(fp);
  if (!p12) {
    ERROR("wg_load_pkey: OpenSSL failed reading PKCS#12 error=%lu",
          ERR_get_error());
    goto bailout;
  }

  if (PKCS12_parse(p12, pass, &pkey, &cert, &ca) == 0) {
    ERROR("wg_load_pkey: PKCS12_parse failed error= %lu\n", ERR_get_error());
    goto bailout;
  }

bailout:
  if (p12) {
    PKCS12_free(p12);
  }
  if (cert) {
    X509_free(cert);
  }
  if (ca) {
    sk_X509_pop_free(ca, X509_free);
  }
  return pkey;
} /* }}} EVP_PKEY *wg_load_pkey_internal */

static EVP_PKEY *wg_load_pkey(/* {{{ */
                              const oconfig_item_t *label_pkey_config,
                              const oconfig_item_t *label_pkey_pass_config) {
  EVP_PKEY *pkey = NULL;
  int status = 0;
  char *pkcs12_key_path = NULL;
  char *pass = NULL;

  status = cf_util_get_string(label_pkey_config, &pkcs12_key_path);
  if (status != 0) {
    goto bailout;
  }
  status = cf_util_get_string(label_pkey_pass_config, &pass);
  if (status != 0) {
    goto bailout;
  }
  pkey = wg_load_pkey_internal(pkcs12_key_path, pass);

bailout:
  sfree(pkcs12_key_path);
  sfree(pass);
  return pkey;
} /* }}} EVP_PKEY *wg_load_pkey */

static int wg_b64_encode(const char *buffer, size_t buffer_size, char *dest,
                         size_t szdest) {
  BIO *bmem, *b64;
  BUF_MEM *bptr;
  size_t ret = 0;

  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, (uint8_t *)buffer, buffer_size);
  if (BIO_flush(b64)) {
    BIO_get_mem_ptr(b64, &bptr);
  }

  if (szdest <= bptr->length) {
    goto bailout;
  }

  memcpy(dest, bptr->data, bptr->length);
  // replace + with -, / with _ and remove padding = at the end
  for (ret = 0; ret < bptr->length; ret++) {
    if (dest[ret] == '+') {
      dest[ret] = '-';
    } else if (dest[ret] == '/') {
      dest[ret] = '_';
    } else if (dest[ret] == '=') {
      break;
    }
  }
  dest[ret] = '\0';

bailout:
  BIO_free_all(b64);
  return ret;
}

static int wg_get_claim(char *email, char *claim64, size_t max_claim_len) {
  int len;
  char claim_str[1024];
  time_t iat = time(NULL);

  // create the claim set
  len = ssnprintf(claim_str, sizeof(claim_str), jwt_claim_fmt, email,
                  iat + 3600, iat);
  if (len < 1) {
    return (-1);
  } else if ((size_t)len >= sizeof(claim_str)) {
    return (-ENOMEM);
  }
  DEBUG("claim_str=%s", claim_str);

  // base64 encode the claim set
  len = wg_b64_encode(claim_str, len, claim64, max_claim_len);
  if (len < 1) {
    return (-1);
  } else if ((size_t)len >= sizeof(claim_str)) {
    return (-ENOMEM);
  }

  DEBUG("claim64=%s", claim64);
  return len;
}

static int wg_get_jwt(const char *claim64, EVP_PKEY *pkey, char *jwt,
                      size_t max_jwt_len) {
  EVP_MD_CTX ctx;
  char signature[1024];
  char signature64[MAX_ENCODE_SIZE];
  char str_to_sign[2048];
  unsigned int buffer_size = 0;
  size_t len = 0;
  int ret = 0;

  // make the string to sign
  memset(str_to_sign, 0, sizeof(str_to_sign));
  len = ssnprintf(str_to_sign, sizeof(str_to_sign), "%s.%s", header64, claim64);
  if (len < 1) {
    return (-1);
  } else if (len >= sizeof(str_to_sign)) {
    return (-ENOMEM);
  }
  DEBUG("wg_get_jwt: strToSign=%s", str_to_sign);

  if (EVP_SignInit(&ctx, EVP_sha256()) == 1) {
    if (EVP_SignUpdate(&ctx, str_to_sign, len) == 1) {
      buffer_size = EVP_PKEY_size(pkey);
      if (buffer_size <= sizeof(signature)) {
        ret = (EVP_SignFinal(&ctx, (unsigned char *)signature, &buffer_size,
                             pkey) == 1);
      }
    }
  }

  EVP_MD_CTX_cleanup(&ctx);
  if (!ret) {
    ERROR("wg_get_jwt: EVP_SignFinal failed");
    return 0;
  }

  // base64 encode the signature
  len = wg_b64_encode(signature, (size_t)buffer_size, signature64,
                      MAX_ENCODE_SIZE);
  DEBUG("wg_get_jwt: signatureb64=%s", signature64);

  len = ssnprintf(jwt, max_jwt_len, "%s.%s", str_to_sign, signature64);
  if (len < 1) {
    return (-1);
  } else if (len >= max_jwt_len) {
    return (-ENOMEM);
  }
  DEBUG("wg_get_jwt: jwt=%s", jwt);
  return len;
}

static int wg_get_token_request_body(wg_callback_t *cb, char *buffer,
                                     size_t buffer_size) { /* {{{ */
  char claim64[MAX_ENCODE_SIZE];
  char jwt[MAX_ENCODE_SIZE];
  int status;

  status = wg_get_claim(cb->email, claim64, sizeof(claim64));
  if (status < 1) {
    return (-1);
  }

  status = wg_get_jwt(claim64, cb->pkey, jwt, sizeof(jwt));
  if (status < 1) {
    return (-1);
  }

  status = ssnprintf(
      buffer, buffer_size,
      "assertion=%s&grant_type=urn%%3Aietf%%3Aparams%%3Aoauth%%3Agrant-"
      "type%%3Ajwt-bearer",
      jwt);
  if (status < 1) {
    return (-1);
  } else if ((size_t)status >= buffer_size) {
    return (-ENOMEM);
  }
  DEBUG("wg_get_token_request_url: url=%s", buffer);
  return status;
}
#endif

static int wg_parse_token(const char *const input, char *buffer, /* {{{ */
                          const size_t buffer_size, cdtime_t *expire_time,
                          cdtime_t current_time) {
  int status = -1;
  int expire_in_seconds = 0;
  yajl_val root;
  yajl_val token_val;
  yajl_val expire_val;
  char errbuf[1024];
  const char *token_path[] = {"access_token", NULL};
  const char *expire_path[] = {"expires_in", NULL};

  root = yajl_tree_parse(input, errbuf, sizeof(errbuf));
  if (root == NULL) {
    ERROR("wg_parse_token: parse error %s", errbuf);
    status = -1;
    goto bailout;
  }

  token_val = yajl_tree_get(root, token_path, yajl_t_string);
  if (token_val == NULL) {
    ERROR("wg_parse_token: access token field not found");
    status = -1;
    goto bailout;
  }
  sstrncpy(buffer, YAJL_GET_STRING(token_val), buffer_size);
  DEBUG("wg_parse_token: access_token %s", buffer);

  expire_val = yajl_tree_get(root, expire_path, yajl_t_number);
  if (expire_val == NULL) {
    ERROR("wg_parse_token: expire field found");
    status = -1;
    goto bailout;
  }
  expire_in_seconds = YAJL_GET_INTEGER(expire_val);
  DEBUG("wg_parse_token: expires_in %d", expire_in_seconds);

  *expire_time = current_time + DOUBLE_TO_CDTIME_T(expire_in_seconds) -
                 DOUBLE_TO_CDTIME_T(60);
  status = 0;
bailout:
  if (root) {
    yajl_tree_free(root);
  }
  return status;
} /* }}} int wg_parse_token */

static int wg_get_token(wg_callback_t *cb) { /* {{{ */
  CURL *curl;
  char *temp;
  char temp_buf[100];
  int status = 0;
  long http_code = 0;
  wg_memory_t data;
  char access_token[100];
#if HAVE_LIBSSL
  char token_request_body[MAX_TOKEN_REQUEST_SIZE];
#endif
  cdtime_t expire_time = 0;
  struct curl_slist *header = NULL;
  data.size = 0;
  data.memory = NULL;

  curl = curl_easy_init();
  if (!curl) {
    ERROR("wg_get_token: curl_easy_init failed.");
    status = -1;
    goto bailout;
  }

  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, cb->curl_errbuf);

  /* get the access token from the metadata first */
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wg_write_memory_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

  /* if token url is defined, try the token url first */
  if (cb->token_url) {
    curl_easy_setopt(curl, CURLOPT_URL, cb->token_url);
    header = curl_slist_append(header, METADATA_HEADER);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
  }
#if HAVE_LIBSSL
  else if (cb->email && cb->pkey) {
    if (wg_get_token_request_body(cb, token_request_body,
                                  sizeof(token_request_body)) < 1) {
      ERROR("wg_get_token: failed to get token using the service account");
      status = -1;
      goto bailout;
    }
    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://accounts.google.com/o/oauth2/token");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_request_body);
  }
#endif
  else {
    ERROR("wg_get_token: neither token url or service account is defined");
    status = -1;
    goto bailout;
  }

  status = curl_easy_perform(curl);
  if (status != CURLE_OK) {
    ERROR(
        "wg_get_token: curl_easy_perform failed with "
        "status %i: %s",
        status, cb->curl_errbuf);
    status = -1;
    goto bailout;
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
      ERROR("wg_get_token: http code: %ld", http_code);
      status = -1;
      goto bailout;
    }
  }

  status = wg_parse_token(data.memory, access_token, sizeof(access_token),
                          &expire_time, cdtime());
  if (status == 0) {
    temp = strdup(access_token);
    if (temp == NULL) {
      ERROR("wg_get_token: strdup failed.");
      status = -1;
      goto bailout;
    }
    sfree(cb->token);
    cb->token = temp;
    /* refresh the token 1 minute before it really expires */
    cb->token_expire_time = expire_time;

    if (cdtime_to_iso8601(temp_buf, sizeof(temp_buf), cb->token_expire_time) ==
        0) {
      ERROR("wg_get_token: Failed to convert time to ISO 8601 format");
      status = -1;
      goto bailout;
    }
    DEBUG("wg_get_token: expire_time: %s\n", temp_buf);
  }
bailout:
  sfree(data.memory);
  if (curl) {
    curl_easy_cleanup(curl);
  }
  if (header) {
    curl_slist_free_all(header);
  }
  return status;
} /* }}} int wg_get_token */

static int wg_send_buffer(wg_callback_t *cb) /* {{{ */
{
  int status = 0;
  long http_code = 0;
  char final_url[1024];
  curl_easy_setopt(cb->curl, CURLOPT_POSTFIELDS, cb->send_buffer);

  status = ssnprintf(final_url, sizeof(final_url),
                     "%s/projects/%s/timeseries:write?access_token=%s", cb->url,
                     cb->project, cb->token);
  if (status < 1) {
    return (-1);
  } else if ((size_t)status >= sizeof(final_url)) {
    return (-ENOMEM);
  }
  curl_easy_setopt(cb->curl, CURLOPT_URL, final_url);

#if defined(COLLECT_DEBUG) && COLLECT_DEBUG
  wg_memory_t data;
  data.size = 0;
  data.memory = NULL;
  curl_easy_setopt(cb->curl, CURLOPT_WRITEFUNCTION, wg_write_memory_cb);
  curl_easy_setopt(cb->curl, CURLOPT_WRITEDATA, &data);
#endif

  status = curl_easy_perform(cb->curl);
  if (status != CURLE_OK) {
    ERROR(
        "write_gcm plugin: curl_easy_perform failed with "
        "status %i: %s",
        status, cb->curl_errbuf);
  } else {
    curl_easy_getinfo(cb->curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
      ERROR("write_gcm plugin: wg_send_buffer: http code: %ld", http_code);
#if defined(COLLECT_DEBUG) && COLLECT_DEBUG
      ERROR("write_gcm plugin: wg_send_buffer: error_msg: %s", data.memory);
#endif
      status = http_code;
    }
  }
#if defined(COLLECT_DEBUG) && COLLECT_DEBUG
  sfree(data.memory);
#endif
  return (status);
} /* }}} wg_send_buffer */

static int wg_callback_init(wg_callback_t *cb) /* {{{ */
{
  int status;
  if (cb->curl != NULL) return (0);

  status = wg_get_token(cb);
  if (status != CURLE_OK) {
    ERROR(
        "write_gcm plugin: failed to get the access token "
        "status %i: %s",
        status, cb->curl_errbuf);
    return status;
  }

  cb->curl = curl_easy_init();
  if (cb->curl == NULL) {
    ERROR("wg_callback_init: curl_easy_init failed.");
    return (-1);
  }

  curl_easy_setopt(cb->curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(cb->curl, CURLOPT_USERAGENT,
                   PACKAGE_NAME "/" PACKAGE_VERSION);

  cb->headers = NULL;
  cb->headers = curl_slist_append(cb->headers, "Accept:  */*");
  cb->headers =
      curl_slist_append(cb->headers, "Content-Type: application/json");
  cb->headers = curl_slist_append(cb->headers, "Expect:");
  curl_easy_setopt(cb->curl, CURLOPT_HTTPHEADER, cb->headers);
  curl_easy_setopt(cb->curl, CURLOPT_ERRORBUFFER, cb->curl_errbuf);
  wg_reset_buffer(cb);

  return (0);
} /* }}} int wg_callback_init */

static int wg_flush_nolock(cdtime_t timeout, wg_callback_t *cb) /* {{{ */
{
  int status;
  cdtime_t now;
  void *value;
  char *name;

  DEBUG(
      "write_gcm plugin: wg_flush_nolock: timeout = %.3f; "
      "send_buffer_fill = %zu;",
      CDTIME_T_TO_DOUBLE(timeout), cb->send_buffer_fill);

  status = 0;

  if (cb->stream_key_tree) {
    while (c_avl_pick(cb->stream_key_tree, (void *)&name, &value) == 0) {
      sfree(name);
    }
    c_avl_destroy(cb->stream_key_tree);
    cb->stream_key_tree = NULL;
  }
  now = cdtime();
  /* timeout == 0  => flush unconditionally */
  if (timeout > 0) {
    if ((cb->send_buffer_init_time + timeout) > now) {
      goto bailout;
    }
  }

  if (cb->send_buffer_fill <= 2 || cb->timeseries_count == 0) {
    cb->send_buffer_init_time = cdtime();
    goto bailout;
  }

  if (cb->token_expire_time < now) {
    status = wg_get_token(cb);
    if (status != CURLE_OK) {
      ERROR(
          "write_gcm plugin: failed to get the access token "
          "status %i: %s",
          status, cb->curl_errbuf);
      goto bailout;
    }
  }

  status = format_timeseries_finalize(cb->send_buffer, &cb->send_buffer_fill,
                                      &cb->send_buffer_free);
  if (status != 0) {
    ERROR(
        "write_gcm: wg_flush_nolock: "
        "format_timeseries_finalize failed.");
    goto bailout;
  }

  status = wg_send_buffer(cb);
  /* get the access token again if wg_send_buffer failed because of the access
   * token expiration */
  if (status == 401) {
    status = wg_get_token(cb);
    if (status != CURLE_OK) {
      ERROR(
          "write_gcm plugin: failed to get the access token "
          "status %i: %s",
          status, cb->curl_errbuf);
    } else {
      status = wg_send_buffer(cb);
    }
  }

bailout:
  wg_reset_buffer(cb);
  return (status);
} /* }}} wg_flush_nolock */

static int wg_flush(cdtime_t timeout, /* {{{ */
                    const char *identifier __attribute__((unused)),
                    user_data_t *user_data) {
  wg_callback_t *cb;
  int status;

  if (user_data == NULL) return (-EINVAL);

  cb = user_data->data;

  pthread_mutex_lock(&cb->send_lock);

  if (cb->curl == NULL) {
    status = wg_callback_init(cb);
    if (status != 0) {
      ERROR("write_gcm plugin: wg_callback_init failed.");
      pthread_mutex_unlock(&cb->send_lock);
      return (-1);
    }
  }

  status = wg_flush_nolock(timeout, cb);
  pthread_mutex_unlock(&cb->send_lock);

  return (status);
} /* }}} int wg_flush */

static void wg_cache_tree_free(c_avl_tree_t *tree) /* {{{ */
{
  char *name;
  wg_metric_cache_t *value;
  if (tree == NULL) {
    return;
  }

  while (c_avl_pick(tree, (void *)&name, (void *)&value) == 0) {
    sfree(name);
    sfree(value);
  }
  c_avl_destroy(tree);
} /* }}} void wg_cache_tree_free */

static void wg_callback_free(void *data) /* {{{ */
{
  wg_callback_t *cb;
  void *value;
  char *name;

  if (data == NULL) return;

  cb = data;

  wg_flush_nolock(/* timeout = */ 0, cb);

  if (cb->curl) {
    curl_easy_cleanup(cb->curl);
  }

  if (cb->headers) {
    curl_slist_free_all(cb->headers);
  }

#if HAVE_LIBSSL
  if (cb->pkey) {
    EVP_PKEY_free(cb->pkey);
  }
  sfree(cb->email);
#endif

  sfree(cb->project);
  sfree(cb->resource_id);
  sfree(cb->service);
  sfree(cb->url);
  sfree(cb->token_url);
  sfree(cb->token);
  sfree(cb->report_this_plugin);
  sfree(cb->report_this_plugin_instance);
  wg_cache_tree_free(cb->metric_buffer_tree);

  if (cb->metric_name_tree) {
    while (c_avl_pick(cb->metric_name_tree, (void *)&name, &value) == 0) {
      sfree(name);
    }
    c_avl_destroy(cb->metric_name_tree);
    cb->metric_name_tree = NULL;
  }

  sfree(cb);

} /* }}} void wg_callback_free */

static int wg_write(const data_set_t *ds, const value_list_t *vl, /* {{{ */
                    user_data_t *user_data) {
  wg_callback_t *cb;
  int status;
  int flush;
  cdtime_t now;
  char stream_key[256];

  if (user_data == NULL) return (-EINVAL);
  flush = 0;
  cb = user_data->data;

  pthread_mutex_lock(&cb->send_lock);

  if (cb->curl == NULL) {
    status = wg_callback_init(cb);
    if (status != 0) {
      ERROR("write_gcm plugin: wg_callback_init failed.");
      pthread_mutex_unlock(&cb->send_lock);
      return (-1);
    }
  }

  /*flush under the following conditions
   * 1. more than 15 seconds passed since send_buffer_init_time
   * 2. stream_key can't be generated, it's safe to flush
   * 3. the stream_key_tree cache already have the same stream stored,
   * we must flush since monarch can not take more than 1 points from
   * the same stream
   * 4. out of memory while trying to add the current vl to the buffer
   * in function format_timeseries
   */

  now = cdtime();
  if (now > cb->send_buffer_init_time + MS_TO_CDTIME_T(15000)) {
    flush = 1;
  } else if (FORMAT_VL(stream_key, sizeof(stream_key), vl) != 0) {
    ERROR("value_to_timeseries: FORMAT_VL failed.");
    flush = 1;
  } else if (cb->stream_key_tree &&
             c_avl_get(cb->stream_key_tree, stream_key, NULL) == 0) {
    flush = 1;
  } else {
    if (cb->stream_key_tree == NULL) {
      cb->stream_key_tree =
          c_avl_create((int (*)(const void *, const void *))strcmp);
    };
    c_avl_insert(cb->stream_key_tree, strdup(stream_key), NULL);
    status = format_timeseries(cb->send_buffer, &cb->send_buffer_fill,
                               &cb->send_buffer_free, ds, vl, cb);
    if (status == (-ENOMEM)) {
      flush = 1;
    }
  }

  if (flush) {
    status = wg_flush_nolock(/* timeout = */ 0, cb);
    status = format_timeseries(cb->send_buffer, &cb->send_buffer_fill,
                               &cb->send_buffer_free, ds, vl, cb);
  }

  pthread_mutex_unlock(&cb->send_lock);
  return (0);
} /* }}} int wg_write */

static int wg_read_url(const char *url, const char *header, char **ret_body,
                       char **ret_header) /* {{{ */
{
  CURL *curl;
  int status = 0;
  long http_code = 0;
  char curl_errbuf[CURL_ERROR_SIZE];
  char *body_string;
  char *header_string;
  wg_memory_t output_body;
  wg_memory_t output_header;
  struct curl_slist *curl_header = NULL;

  curl = curl_easy_init();
  if (!curl) {
    ERROR("wg_read_url: curl_easy_init failed.");
    status = -1;
    goto bailout;
  }

  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);
  output_body.size = 0;
  output_body.memory = NULL;
  output_header.size = 0;
  output_header.memory = NULL;

  /* set up the write function and write buffer  for both body and header*/
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  if (ret_body != NULL) {
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wg_write_memory_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output_body);
  }
  if (ret_header != NULL) {
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, wg_write_memory_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEHEADER, &output_header);
  }

  /*set the header if it's not null*/
  if (header) {
    curl_header = curl_slist_append(curl_header, METADATA_HEADER);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_header);
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  status = curl_easy_perform(curl);
  if (status != CURLE_OK) {
    ERROR("wg_read_url: curl_easy_perform failed with status %i: %s", status,
          curl_errbuf);
    status = -1;
    goto bailout;
  } else {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code != 200) {
      ERROR("wg_read_url: http code: %ld", http_code);
#if defined(COLLECT_DEBUG) && COLLECT_DEBUG
      ERROR("wg_read_url: error_msg: %s", output_body.memory);
#endif
      status = -1;
      goto bailout;
    }
  }

  if (ret_body != NULL) {
    body_string = strdup(output_body.memory);
    if (body_string == NULL) {
      status = -1;
      goto bailout;
    }
    sfree(*ret_body);
    *ret_body = body_string;
  }

  if (ret_header != NULL) {
    header_string = strdup(output_header.memory);
    if (header_string == NULL) {
      status = -1;
      goto bailout;
    }
    sfree(*ret_header);
    *ret_header = header_string;
  }

bailout:
  sfree(output_body.memory);
  sfree(output_header.memory);
  if (curl) {
    curl_easy_cleanup(curl);
  }
  if (curl_header) {
    curl_slist_free_all(curl_header);
  }
  return status;
} /* }}} int wg_read_url */

static int wg_read_gce_meta_data(wg_callback_t *cb) { /* {{{ */
  int status = 0;
  char *scope = NULL;
  char *temp = NULL;

  DEBUG("wg_read_gce_meta_data: url %s", cb->url);

  if (wg_read_url(METADATA_PROJECT_URL, METADATA_HEADER,
                  &cb->project, NULL)) {
    DEBUG("wg_read_gce_meta_data: fail to read project id");
    status = -1;
    goto bailout;
  }
  DEBUG("wg_read_gce_meta_data: project %s", cb->project);

  if (wg_read_url(METADATA_RESOURCE_ID_URL, METADATA_HEADER,
                  &cb->resource_id, NULL)) {
    DEBUG("wg_read_gce_meta_data: fail to read resource_id");
    status = -1;
    goto bailout;
  }
  DEBUG("wg_read_gce_meta_data: resource_id %s", cb->resource_id);

  scope = NULL;
  if (wg_read_url(META_DATA_SCOPE_URL, METADATA_HEADER, &scope,
                  NULL)) {
    DEBUG("wg_read_gce_meta_data: fail to read scope");
    status = -1;
    goto bailout;
  } else {
    if (strstr(scope, MONITORING_SCOPE)) {
      sfree(cb->token_url);
      cb->token_url = strdup(META_DATA_TOKEN_URL);
      DEBUG("wg_read_gce_meta_data: token_url %s", cb->token_url);
    } else {
      ERROR("wg_read_meta_data: default scope doesn't contain monitoring");
      status = -1;
      goto bailout;
    }
  }
bailout:
  sfree(temp);
  sfree(scope);
  return status;
} /* }}} int wg_read_gce_meta_data */

static int wg_read_meta_data(wg_callback_t *cb) { /* {{{ */
  int status;
  char *header = NULL;

  if (wg_read_url(METADATA_PREFIX, NULL, NULL, &header) == 0 &&
      strstr(header, GCE_METADATA_FLAVOR)) {
    status = wg_read_gce_meta_data(cb);
  } else {
    // TODO(zhihuawen): add function for aws
  }
  sfree(header);
  return status;
} /* }}} int wg_read_meta_data */

static int wg_config(oconfig_item_t *ci) /* {{{ */
{
  wg_callback_t *cb;
  user_data_t user_data;
#if HAVE_LIBSSL
  oconfig_item_t *label_pkey_config = NULL;
  oconfig_item_t *label_pkey_pass_config = NULL;
#endif
  cdtime_t now = cdtime();
  int i;
  int len;

  if (ci == NULL) {
    return (-1);
  }

  cb = malloc(sizeof(*cb));
  if (cb == NULL) {
    ERROR("write_gcm plugin: malloc failed.");
    return (-1);
  }
  memset(cb, 0, sizeof(*cb));
  cb->url = strdup(MONITORING_URL);
  cb->service = strdup(DEFAULT_SERVICE);

  cb->project = NULL;
  cb->token = NULL;
  cb->token_url = NULL;
  cb->curl = NULL;
  cb->resource_id = NULL;
  cb->report_this_plugin = NULL;          /* NULL is ALL plugins */
  cb->report_this_plugin_instance = NULL; /* NULL is ALL instances */

#if HAVE_LIBSSL
  cb->pkey = NULL;
  cb->email = NULL;
#endif

  cb->metric_buffer_tree =
      c_avl_create((int (*)(const void *, const void *))strcmp);
  cb->metric_name_tree =
      c_avl_create((int (*)(const void *, const void *))strcmp);
  len = cdtime_to_iso8601(
      cb->str_init_time, sizeof(cb->str_init_time),
      now - now % cf_get_default_interval() - cf_get_default_interval());
  if (len == 0) {
    ERROR(
        "write_gcm wg_config: Failed to convert time to ISO 8601 "
        "format");
    return -1;
  }

  pthread_mutex_init(&cb->send_lock, /* attr = */ NULL);

  wg_read_meta_data(cb);

  for (i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;
    if (strcasecmp("Project", child->key) == 0)
      cf_util_get_string(child, &cb->project);
    else if (strcasecmp("Url", child->key) == 0)
      cf_util_get_string(child, &cb->url);
    else if (strcasecmp("TokenUrl", child->key) == 0)
      cf_util_get_string(child, &cb->token_url);
    else if (strcasecmp("ResourceId", child->key) == 0)
      cf_util_get_string(child, &cb->resource_id);
    else if (strcasecmp("Service", child->key) == 0)
      cf_util_get_string(child, &cb->service);
    else if (strcasecmp("ReportPlugin", child->key) == 0)
      cf_util_get_string(child, &cb->report_this_plugin);
    else if (strcasecmp("ReportPluginInstance", child->key) == 0)
      cf_util_get_string(child, &cb->report_this_plugin_instance);
#if HAVE_LIBSSL
    else if (strcasecmp("Email", child->key) == 0)
      cf_util_get_string(child, &cb->email);
    else if (strcasecmp("PrivateKeyFile", child->key) == 0)
      label_pkey_config = child;
    else if (strcasecmp("PrivateKeyPass", child->key) == 0)
      label_pkey_pass_config = child;
#endif
    //ignore the noconfig
    else if (strcasecmp("Noconfig", child->key) != 0){
      ERROR(
          "write_gcm plugin: Invalid configuration "
          "option: %s.",
          child->key);
      return -1;
    }
  }

#if HAVE_LIBSSL
  /* load private key if the token url is not specified */
  if (cb->token_url == NULL && cb->email && label_pkey_config &&
      label_pkey_pass_config) {
    if ((cb->pkey = wg_load_pkey(label_pkey_config, label_pkey_pass_config)) ==
        NULL) {
      ERROR("write_gcm plugin: fail to load private key from key file");
      return -1;
    }
  }
#endif

#if HAVE_LIBSSL
  if ((cb->email == NULL || cb->pkey == NULL) && cb->token_url == NULL) {
    ERROR(
        "write_gcm plugin: Invalid configuration, either service account or "
        "token url must be configured");
    return -1;
  }
#else /* if !HAVE_LIBSSL */
  if (cb->token_url == NULL) {
    ERROR(
        "write_gcm plugin: Invalid configuration,token url must be "
        "configured");
    return -1;
  }
#endif

  if (cb->project == NULL || cb->url == NULL || cb->resource_id == NULL) {
    ERROR(
        "write_gcm plugin: Invalid configuration, some fields are "
        "missing ");
    return -1;
  }

  DEBUG("write_gcm: Registering write callback with URL %s", cb->url);

  memset(&user_data, 0, sizeof(user_data));
  user_data.data = cb;
  user_data.free_func = NULL;
  plugin_register_flush("write_gcm", wg_flush, &user_data);

  user_data.free_func = wg_callback_free;
  plugin_register_write("write_gcm", wg_write, &user_data);

  return (0);
} /* }}} int wg_config */

static int wg_init(void) /* {{{ */
{
  /* Call this while collectd is still single-threaded to avoid
   * initialization issues in libgcrypt. */
  curl_global_init(CURL_GLOBAL_SSL);
  return (0);
} /* }}} int wg_init */

/*only un-comment it for unit testing */
//#define TEST_WRITE_GCM_ONLY 1

#ifdef TEST_WRITE_GCM_ONLY
int test_wg_get_location_internal(const char *buffer,
                                  const char *expected_output) { /* {{{ */
  int ret = 0;
  char *locaiton = NULL;
  ret = wg_get_location(buffer, &locaiton);
  if (ret != 0) {
    ret = -1;
    printf("test_wg_get_location_internal failed\n");
    goto bailout;
  } else {
    ret = (strlen(locaiton) == strlen(expected_output) &&
           strncmp(locaiton, expected_output, strlen(expected_output)) == 0);
    if (ret) {
      printf("test_wg_get_location_internal passed\n");
    }
    return ret;
  }
bailout:
  sfree(locaiton);
  return ret;
} /* }}} int test_wg_get_location_internal */

void test_wg_get_location() { /* {{{ */
  // test normal case
  assert(test_wg_get_location_internal(
      "projects/67861005568/zones/us-central1-a", "us-central1-a"));
  // test NULL input
  assert(test_wg_get_location_internal(NULL, "us-central1-a") != 1);

  // test too short
  assert(test_wg_get_location_internal("projects/67861005568/zones",
                                       "us-central1-a") != 1);
  // test too long
  assert(test_wg_get_location_internal(
      "projects/67861005568/zones/us-central1-a/extra", "us-central1-a"));

  printf("test_wg_get_location passed\n");
} /* }}} void test_wg_get_location */

int test_wg_b64_encode_internal(const char *buffer,
                                const char *expected_output) { /* {{{ */
  char dest[1024];
  int len;
  int ret = 0;
  len = wg_b64_encode(buffer, strlen(buffer), dest, sizeof(dest));

  if (len < 1) {
    printf("Zero length string returned");
    return -1;
  } else if ((size_t)len >= sizeof(dest)) {
    printf("out of memory");
    return -1;
  }

  printf("expected_len %zu, expected_string=%s\n", strlen(expected_output),
         expected_output);
  printf("actual_len %d, actual_string=%s\n", len, dest);

  ret = (len == strlen(expected_output) &&
         strncmp(dest, expected_output, strlen(expected_output)) == 0);
  if (ret) {
    printf("test_wg_b64_encode passed\n");
  }
  return ret;
} /* }}} void unit_test */

void test_wg_b64_encode() {
  assert(test_wg_b64_encode_internal("{\"alg\":\"RS256\",\"typ\":\"JWT\"}",
                                     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"));
  assert(test_wg_b64_encode_internal(
      "{\"iss\":\"124118192014@developer.gserviceaccount.com\",\"scope\":"
      "\"https://www.googleapis.com/auth/"
      "monitoring.readonly\",\"aud\":\"https://accounts.google.com/o/oauth2/"
      "token\",\"exp\":1402441454,\"iat\":1402437854}",
      "eyJpc3MiOiIxMjQxMTgxOTIwMTRAZGV2ZWxvcGVyLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJz"
      "Y29wZSI6Imh0dHBzOi8vd3d3Lmdvb2dsZWFwaXMuY29tL2F1dGgvbW9uaXRvcmluZy5yZWFk"
      "b25seSIsImF1ZCI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbS9vL29hdXRoMi90b2tl"
      "biIsImV4cCI6MTQwMjQ0MTQ1NCwiaWF0IjoxNDAyNDM3ODU0fQ"));
}

int test_wg_load_pkey_internal(/* {{{ */
                               const char *pkcs12_key_path, const char *pass) {
  EVP_PKEY *pkey = NULL;
  pkey = wg_load_pkey_internal(pkcs12_key_path, pass);
  if (pkey != NULL) {
    printf("test_wg_load_pkey_internal for %s and %s passed\n", pkcs12_key_path,
           pass);
  } else {
    printf("test_wg_load_pkey_internal for %s and %s failed\n", pkcs12_key_path,
           pass);
  }
  return (pkey != NULL);
} /* }}} wg_load_pkey_internal */

void test_wg_load_key() { /* {{{ */
  /* this test case is very fragile, please make sure that each parameter points
   * to the intended file path and password, i.e., correct_file points to a
   * valid private key file and permission_denied_file points to a file the
   *current user doesn't have access to, etc.
   *
   */
  char *correct_file = "privatekey.p12";
  char *correct_pass = "notasecret";
  char *corrupted_file = "corrupted_privatekey.p12";
  char *permission_denied_file = "not_allowed_privatekey.p12";

  // test for correct file and correct password
  assert(test_wg_load_pkey_internal(correct_file, correct_pass));

  // test for correct file and wrong password
  assert(!test_wg_load_pkey_internal("privatekey.p12", "wrong_pass_word"));

  // test for none exist file
  assert(
      !test_wg_load_pkey_internal("none_exist_privatekey.p12", correct_pass));

  // test for exist file without permission
  assert(!test_wg_load_pkey_internal(permission_denied_file, correct_pass));

  // test for exist but corrupted private key file
  assert(!test_wg_load_pkey_internal(corrupted_file, correct_pass));
} /* }}} void test_wg_load_key*/

int test_wg_parse_token_internal(const char *input,
                                 const char *expected_access_token,
                                 const int expire_in_seconds) {
  int status = 0;
  cdtime_t current_time = 0;
  cdtime_t expected_expire_time = current_time +
                                  DOUBLE_TO_CDTIME_T(expire_in_seconds) -
                                  DOUBLE_TO_CDTIME_T(60);
  char access_token[100];
  cdtime_t expire_time = 0;

  status = wg_parse_token(input, access_token, sizeof(access_token),
                          &expire_time, current_time);
  assert(status == 0);
  assert(expected_expire_time == expire_time);
  assert(strlen(expected_access_token) == strlen(access_token) &&
         strncmp(access_token, expected_access_token,
                 strlen(expected_access_token)) == 0);
  printf("test_wg_parse_token_internal passed");
  return 0;
}

void test_wg_parse_token() {
  assert(
      test_wg_parse_token_internal(
          "{\n  \"access_token\" : "
          "\"ya29.LgB1nDeqQb-nBRwAAACv1H4-HFEt_GSFDE3IcQivEg-"
          "SwXsj4Y7k0waRLqjqQQ\","
          "\n  \"token_type\" : \"Bearer\",\n  \"expires_in\" : 3600\n}",
          "ya29.LgB1nDeqQb-nBRwAAACv1H4-HFEt_GSFDE3IcQivEg-SwXsj4Y7k0waRLqjqQQ",
          3600) == 0);
  printf("test_wg_pase_token passed");
}

#if HAVE_LIBSSL
void test_wg_get_token() {
  wg_callback_t *cb = NULL;
  char *privatekey_file = "privatekey.p12";
  char *privatekey_pass = "notasecret";
  char *service_account_email = "124118192014@developer.gserviceaccount.com";
  int i = 0;
  cb = malloc(sizeof(*cb));
  assert(cb);

  memset(cb, 0, sizeof(*cb));
  cb->project = NULL;
  cb->url = NULL;
  cb->token = NULL;
  cb->token_url = NULL;
  cb->curl = NULL;
  cb->resource_id = NULL;
  cb->pkey = NULL;
  cb->email = NULL;
  cb->timeseries_count = 0;

  cb->pkey = wg_load_pkey_internal(privatekey_file, privatekey_pass);
  cb->email = strdup(service_account_email);
  cb->url = strdup(MONITORING_URL);

  assert(wg_callback_init(cb) == 0);

  for (i = 0; i < 10; i++) {
    assert(wg_get_token(cb) == 0);
    printf("token: %s\n", cb->token);
    printf("test_wg_get_token passed %d\n", i);
  }

  wg_callback_free((void *)cb);
}
#endif

void unit_test() { /* {{{ */
  wg_init();
  wg_config((oconfig_item_t *)NULL);
#if HAVE_LIBSSL
  test_wg_get_token();
  test_wg_load_key();
  test_wg_b64_encode();
#endif

  // test_wg_get_location();
  // test_wg_parse_token();

} /* }}} void unit_test */
#endif

void module_register(void) /* {{{ */
{
#ifdef TEST_WRITE_GCM_ONLY
  unit_test();
#else
  plugin_register_complex_config("write_gcm", wg_config);
  plugin_register_init("write_gcm", wg_init);
#endif
} /* }}} void module_register */
