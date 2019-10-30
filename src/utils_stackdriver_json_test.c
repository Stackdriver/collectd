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

#include "config.h"

#include "collectd.h"

#include "daemon/common.h"
#include "daemon/utils_llist.h"
#include "testing.h"
#include "utils_stackdriver_json.h"

static int run_summary_test(time_series_summary_t summary) {
  llentry_t *entry;
  time_series_error_t *error;
  EXPECT_EQ_INT(4, summary.total_point_count);
  EXPECT_EQ_INT(1, summary.success_point_count);
  CHECK_NOT_NULL(summary.errors);
  entry = llist_search(summary.errors, "404");
  CHECK_NOT_NULL(entry);
  error = (time_series_error_t*) entry->value;
  EXPECT_EQ_INT(1, error->point_count);
  EXPECT_EQ_INT(404, error->code);
  entry = llist_search(summary.errors, "429");
  CHECK_NOT_NULL(entry);
  error = (time_series_error_t*) entry->value;
  EXPECT_EQ_INT(2, error->point_count);
  EXPECT_EQ_INT(429, error->code);
  EXPECT_EQ_INT(2, llist_size(summary.errors));
  return 0;
}

DEF_TEST(time_series_summary) {
  char buf[10000];
  int ret;
  OK(read_file_contents(SRCDIR "/src/time_series_summary_test.json", buf,
                        sizeof(buf)) >= 0);
  time_series_summary_t summary = {0};
  CHECK_ZERO(parse_time_series_summary(buf, &summary));
  ret = run_summary_test(summary);
  free_time_series_summary(&summary);
  return ret;
}

DEF_TEST(collectd_time_series_response) {
  char buf[10000];
  int ret;
  OK(read_file_contents(SRCDIR "/src/collectd_time_series_response_test.json", buf,
                        sizeof(buf)) >= 0);
  time_series_summary_t summary = {0};
  CHECK_ZERO(parse_time_series_summary(buf, &summary));
  ret = run_summary_test(summary);
  free_time_series_summary(&summary);
  return ret;
}

int main(void) {
  RUN_TEST(time_series_summary);
  RUN_TEST(collectd_time_series_response);
  END_TEST;
}
