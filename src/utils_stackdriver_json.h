/**
 * collectd - src/utils_format_json.h
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

#ifndef UTILS_STACKDRIVER_JSON_H
#define UTILS_STACKDRIVER_JSON_H 1

#include "collectd.h"
#include "utils_llist.h"

typedef struct {
  int point_count;
  int code;
} time_series_error_t;

typedef struct {
  int total_point_count;
  int success_point_count;
  // Elements have type time_series_error_t.
  llist_t *errors;
} time_series_summary_t;

/*
Extract statistics from the backend API response. Supports both CreateTimeSeries
and CreateCollectdTimeSeries. For sample input see time_series_summary_test.json
and collectd_time_series_response_test.json.
*/
int parse_time_series_summary(char *buffer, time_series_summary_t *response);

/*
Release the resources allocated by the time_series_summary_t instance. It
doesn't release `response` itself.
*/
void free_time_series_summary(time_series_summary_t *response);

#endif /* UTILS_STACKDRIVER_JSON_H */
