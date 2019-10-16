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

typedef struct {
  struct {
    // Whether the parser is inside the Summary.total_point_count field.
    _Bool in_summary_total;
    // Whether the parser is inside the Summary.success_point_count field.
    _Bool in_summary_success;
  } state;

  // Holds the output.
  time_series_summary_t *response;
} parse_summary_t;

static int summary_parse_map_key(void *c, const unsigned char *key,
                                 wg_yajl_size_t length) {
  parse_summary_t *ctx = (parse_summary_t *)c;
  memset(&ctx->state, 0, sizeof(ctx->state));
  if (strncmp((const char *)key, "total_point_count", length) == 0) {
    ctx->state.in_summary_total = 1;
  } else if (strncmp((const char *)key, "success_point_count", length) == 0) {
    ctx->state.in_summary_success = 1;
  }
  return 1;
}

static int summary_parse_integer(void *c, wg_yajl_integer_t val) {
  parse_summary_t *ctx = (parse_summary_t *)c;
  if (ctx->state.in_summary_total) {
    if (ctx->response->total_point_count > 0) {
      DEBUG("total_point_count was already set. Bug?");
    }
    ctx->response->total_point_count += val;
  } else if (ctx->state.in_summary_success) {
    if (ctx->response->success_point_count > 0) {
      DEBUG("success_point_count was already set. Bug?");
    }
    ctx->response->success_point_count += val;
  }
  return 1;
}

// This implementation looks for the CreateTimeSeriesSummary fields and assumes
// that they are unique in the input. It's theoretically possible that there
// could be a conflict, but unlikely given their names and that this is always a
// response from CreateTimeSeries.
int parse_time_series_summary(char *buffer, time_series_summary_t *response) {
  yajl_callbacks funcs = {
      .yajl_integer = summary_parse_integer,
      .yajl_map_key = summary_parse_map_key,
  };
  parse_summary_t ctx;
  if (response == NULL) return -1;
  memset(&ctx, 0, sizeof(ctx));
  ctx.response = response;
  return parse_json(&funcs, buffer, &ctx);
}

typedef struct {
  struct {
    // Whether the parser is inside a value_errors map and at what depth the map
    // was found.
    _Bool in_value_errors;
    _Bool value_errors_depth;
    // The depth of the map.
    int depth;
  } state;

  // Holds the output.
  collectd_time_series_response_t *response;
} parse_collectd_t;

static int collectd_parse_map_key(void *c, const unsigned char *key,
                                  wg_yajl_size_t length) {
  parse_collectd_t *ctx = (parse_collectd_t *)c;
  if (strncmp((const char *)key, "value_errors", length) == 0) {
    ctx->state.in_value_errors = 1;
    ctx->state.value_errors_depth = ctx->state.depth;
  } else if (strncmp((const char *)key, "index", length) == 0 &&
             ctx->state.in_value_errors) {
    ctx->response->error_point_count++;
  }
  return 1;
}

static int collectd_start_map(void *c) {
  parse_collectd_t *ctx = (parse_collectd_t *)c;
  ctx->state.depth++;
  return 1;
}

static int collectd_end_map(void *c) {
  parse_collectd_t *ctx = (parse_collectd_t *)c;
  ctx->state.depth--;
  if (ctx->state.depth == ctx->state.value_errors_depth) {
    ctx->state.in_value_errors = 0;
  }
  return 1;
}

// This implementation counts the 'index' fields in the input that are inside a
// value_errors map, as they represent individual points.
int parse_collectd_time_series_response(char *buffer, collectd_time_series_response_t *response) {
  yajl_callbacks funcs = {
      .yajl_map_key = collectd_parse_map_key,
      .yajl_start_map = collectd_start_map,
      .yajl_end_map = collectd_end_map,
  };
  parse_collectd_t ctx;
  if (response == NULL) return -1;
  memset(&ctx, 0, sizeof(ctx));
  ctx.response = response;
  return parse_json(&funcs, buffer, &ctx);
}
