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

typedef struct {
  int total_point_count;
  int success_point_count;
} time_series_summary_t;

typedef struct {
  int error_point_count;
} collectd_time_series_response_t;

/*
Expected input:
{
  "error": {
    "code": 429,
    "status", "RESOURCE_EXHAUSTED",
    "message": "Retry in 300 milliseconds.",
    "details": [
      {
        "@type":"type.googleapis.com/google.monitoring.v3.CreateTimeSeriesSummary",
        "total_point_count": 3,
        "success_point_count": 1,
      },
      // Other detail messages, such as CreateTimeSeriesError.
    ],
  }
}

The expected `response` for the input above is:
{
  total_point_count = 3
  success_point_count = 1
}
*/
int parse_time_series_summary(char *buffer, time_series_summary_t *response);

/*
Expected input:
{
  "payload_errors": [
    {
      "index": 0,
      "error": {
        "code": 429,
        "status", "RESOURCE_EXHAUSTED",
        "message": "Retry in 300 milliseconds.",
      }
    }, {
      "index": 1,
      "value_errors": [
      {
        "index": 0,
        "error": {
          // Similar to field "error" above.
        }
      }, {
        "index": 1,
        "error": {
          // Similar to field "error" above.
        }
      }
    ],
  }
}

The expected `response` for the input above is:
{
  error_point_count = 3
}
*/
int parse_collectd_time_series_response(char *buffer, collectd_time_series_response_t *response);

#endif /* UTILS_STACKDRIVER_JSON_H */
