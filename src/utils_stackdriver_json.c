/**
 * collectd - src/utils_format_json.c
 * Copyright (C) 2019  Google Inc.
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
 **/

#include "collectd.h"

#include "utils_stackdriver_json.h"
#include "daemon/plugin.h"

#include <yajl/yajl_common.h>
#include <yajl/yajl_parse.h>
#if HAVE_YAJL_YAJL_VERSION_H
#include <yajl/yajl_version.h>
#endif
#if YAJL_MAJOR > 1
#define HAVE_YAJL_V2 1
#endif

#if HAVE_YAJL_V2
typedef long long wg_yajl_integer_t;
typedef size_t wg_yajl_size_t;
#else
typedef long wg_yajl_integer_t;
typedef unsigned int wg_yajl_size_t;
#endif

#define TYPE_SUMMARY "type.googleapis.com/google.monitoring.v3.CreateTimeSeriesSummary"

static void handle_yajl_status(yajl_status status, yajl_handle handle,
                               char *buffer, size_t length) {
  if (status == yajl_status_ok) {
    return;
  }

  unsigned char *message = yajl_get_error(handle, 1, (unsigned char *)buffer, length);
  ERROR("%s", message);
  yajl_free_error(handle, message);
}

static int parse_json(yajl_callbacks *funcs, char *buffer, void *ctx) {
  yajl_handle handle;
  yajl_status result;
  size_t buffer_length;

#if HAVE_YAJL_V2
  handle = yajl_alloc(funcs, /* alloc = */ NULL, ctx);
#else
  handle = yajl_alloc(funcs, /* config = */ NULL, /* alloc = */ NULL, ctx);
#endif
  if (handle == NULL) return -1;

  buffer_length = strlen(buffer);
  result = yajl_parse(handle, (unsigned char *)buffer, buffer_length);
  handle_yajl_status(result, handle, buffer, buffer_length);

#if HAVE_YAJL_V2
  result = yajl_complete_parse(handle);
#else
  result = yajl_parse_complete(handle);
#endif
  handle_yajl_status(result, handle, NULL, 0);

  yajl_free(handle);
  return result == yajl_status_ok ? 0 : -1;
}

typedef enum {
  FIELD_UNSET = 0,
  FIELD_TYPE,
  FIELD_TOTAL_POINT_COUNT,
  FIELD_SUCCESS_POINT_COUNT,
  FIELD_ERROR_POINT_COUNT,
  FIELD_CODE,
} field_t;

typedef struct {
  struct {
    // Whether the parser is inside a summary map and at what depth the map was
    // found.
    _Bool in_summary;
    int summary_depth;
    // The depth of the current map element.
    int depth;
    // The most recent field encountered.
    field_t current_field;
    // Temporary storage for building error instances.
    time_series_error_t temp_error;
  } state;

  // Holds the output.
  time_series_summary_t *response;
} parse_summary_t;

static void log_context(const parse_summary_t *ctx) {
  DEBUG("in_summary %d; summary_depth %d; depth %d; current_field %d",
       ctx->state.in_summary, ctx->state.summary_depth, ctx->state.depth,
       ctx->state.current_field);
}

static int summary_start_map(void *c) {
  parse_summary_t *ctx = (parse_summary_t *)c;
  ctx->state.depth++;
  return 1;
}

static int summary_end_map(void *c) {
  parse_summary_t *ctx = (parse_summary_t *)c;
  if (ctx->state.depth == ctx->state.summary_depth) {
    ctx->state.in_summary = 0;
  }
  ctx->state.depth--;
  if (ctx->state.in_summary) {
    // If the parser is inside a CreateTimeSeriesSummary message and there is a
    // fully initialized error element, commit it to the response.
    if (ctx->state.temp_error.point_count > 0 && ctx->state.temp_error.code > 0) {
      const int max_key_length = 10;  // Includes trailing NUL.
      char *key;
      time_series_error_t *value;
      key = malloc(max_key_length);
      snprintf(key, max_key_length, "%d", ctx->state.temp_error.code);
      value = malloc(sizeof(time_series_error_t));
      memcpy(value, &ctx->state.temp_error, sizeof(*value));
      memset(&ctx->state.temp_error, 0, sizeof(ctx->state.temp_error));
      if (ctx->response->errors == NULL) {
        ctx->response->errors = llist_create();
      }
      llist_append(ctx->response->errors, llentry_create(key, value));
    }
  }
  return 1;
}

static int summary_parse_map_key(void *c, const unsigned char *key,
                                 wg_yajl_size_t length) {
  parse_summary_t *ctx = (parse_summary_t *)c;
  log_context(ctx);
  DEBUG("map_key: %.*s", (int) length, (const char*) key);
  ctx->state.current_field = FIELD_UNSET;
  // Is this a CreateTimeSeriesSummary object within a CreateCollectdTimeSeriesResponse?
  if (strncmp((const char *)key, "summary", length) == 0) {
    ctx->state.in_summary = 1;
    ctx->state.summary_depth = ctx->state.depth;
    return 1;
  }
  // Is this a @type annotation within a CreateTimeSeries status payload?
  if (strncmp((const char *)key, "@type", length) == 0) {
    ctx->state.current_field = FIELD_TYPE;
    return 1;
  }
  if (!ctx->state.in_summary) {
    return 1;
  }
  // We are inside a summary object. This implementation assumes that the field
  // names used within the message are unique.
  if (strncmp((const char *)key, "total_point_count", length) == 0) {
    ctx->state.current_field = FIELD_TOTAL_POINT_COUNT;
  } else if (strncmp((const char *)key, "success_point_count", length) == 0) {
    ctx->state.current_field = FIELD_SUCCESS_POINT_COUNT;
  } else if (strncmp((const char *)key, "point_count", length) == 0) {
    // Not a typo. The field name doesn't contain "error".
    ctx->state.current_field = FIELD_ERROR_POINT_COUNT;
  } else if (strncmp((const char *)key, "code", length) == 0) {
    ctx->state.current_field = FIELD_CODE;
  }
  return 1;
}

static int summary_parse_string(void *c, const unsigned char *val,
                                 wg_yajl_size_t length) {
  parse_summary_t *ctx = (parse_summary_t *)c;
  log_context(ctx);
  DEBUG("string: %.*s", (int) length, (const char*)val);
  // Is this a CreateTimeSeries object within a CreateTimeSeries status payload?
  if (ctx->state.current_field == FIELD_TYPE &&
      strncmp((const char *)val, TYPE_SUMMARY, length) == 0) {
    ctx->state.in_summary = 1;
    ctx->state.summary_depth = ctx->state.depth;
  }
  return 1;
}

static int summary_parse_integer(void *c, wg_yajl_integer_t val) {
  parse_summary_t *ctx = (parse_summary_t *)c;
  log_context(ctx);
  DEBUG("integer: %lld", val);
  if (ctx->state.current_field == FIELD_TOTAL_POINT_COUNT) {
    if (ctx->response->total_point_count > 0) {
      DEBUG("total_point_count was already set. Bug?");
    }
    ctx->response->total_point_count += val;
  } else if (ctx->state.current_field == FIELD_SUCCESS_POINT_COUNT) {
    if (ctx->response->success_point_count > 0) {
      DEBUG("success_point_count was already set. Bug?");
    }
    ctx->response->success_point_count += val;
  } else if (ctx->state.current_field == FIELD_ERROR_POINT_COUNT) {
    if (ctx->state.temp_error.point_count > 0) {
      DEBUG("error point_count was already set. Bug?");
    }
    ctx->state.temp_error.point_count += val;
  } else if (ctx->state.current_field == FIELD_CODE) {
    if (ctx->state.temp_error.code > 0) {
      DEBUG("error code was already set. Bug?");
    }
    ctx->state.temp_error.code = val;
  }
  return 1;
}

int parse_time_series_summary(char *buffer, time_series_summary_t *response) {
  yajl_callbacks funcs = {
      .yajl_integer = summary_parse_integer,
      .yajl_string = summary_parse_string,
      .yajl_map_key = summary_parse_map_key,
      .yajl_start_map = summary_start_map,
      .yajl_end_map = summary_end_map,
  };
  parse_summary_t ctx;
  if (response == NULL) return -1;
  memset(&ctx, 0, sizeof(ctx));
  ctx.response = response;
  return parse_json(&funcs, buffer, &ctx);
}

void free_time_series_summary(time_series_summary_t *response) {
  if (response->errors != NULL) {
    llentry_t *e_this;
    llentry_t *e_next;
    // Free all elements of `errors`. llist_destroy below will free the actual entries.
    for (e_this = llist_head(response->errors); e_this != NULL; e_this = e_next) {
      e_next = e_this->next;
      free(e_this->key);
      free(e_this->value);
    }
    llist_destroy(response->errors);
    response->errors = NULL;
  }
}
