/**
 * collectd - src/utils_format_json_test.c
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

#include "daemon/common.h"
#include "testing.h"
#include "utils_stackdriver_json.h"

DEF_TEST(time_series_summary) {
  char buf[10000];
  OK(read_file_contents("src/time_series_summary_test.json", buf, sizeof(buf)) >= 0);
  time_series_summary_t summary = {0};
  CHECK_ZERO(parse_time_series_summary(buf, &summary));
  EXPECT_EQ_INT(summary.total_point_count, 3);
  EXPECT_EQ_INT(summary.success_point_count, 1);
  return 0;
}

DEF_TEST(collectd_time_series_response) {
  char buf[10000];
  OK(read_file_contents("src/collectd_time_series_response_test.json", buf, sizeof(buf)) >= 0);
  collectd_time_series_response_t response = {0};
  CHECK_ZERO(parse_collectd_time_series_response(buf, &response));
  EXPECT_EQ_INT(response.error_point_count, 3);
  return 0;
}

int main(void) {
  RUN_TEST(time_series_summary);
  RUN_TEST(collectd_time_series_response);
  END_TEST;
}
