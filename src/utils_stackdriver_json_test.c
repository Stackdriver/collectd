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

static int expect_time_series_summary_equals(const time_series_summary_t *a,
                                             const time_series_summary_t *b) {
  EXPECT_EQ_INT(a->total_point_count, b->total_point_count);
  EXPECT_EQ_INT(a->success_point_count, b->success_point_count);
  const llentry_t *a_entry = llist_head(a->errors);
  const llentry_t *b_entry = llist_head(b->errors);
  while (a_entry != NULL && b_entry != NULL) {
    const time_series_error_t *error_a = (time_series_error_t *) a_entry->value;
    const time_series_error_t *error_b = (time_series_error_t *) b_entry->value;
    EXPECT_EQ_STR(a_entry->key, b_entry->key);
    EXPECT_EQ_INT(error_a->code, error_b->code);
    EXPECT_EQ_INT(error_a->point_count, error_b->point_count);
    a_entry = a_entry->next;
    b_entry = b_entry->next;
  }
  EXPECT_EQ_INT(llist_size(a->errors), llist_size(b->errors));
  return 0;
}

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
  ssize_t file_size;
  int ret;
  file_size = read_file_contents(SRCDIR "/src/time_series_summary_test.json", buf,
                                 sizeof(buf) - 1);
  OK(file_size >= 0);
  buf[file_size] = 0;
  time_series_summary_t summary = {0};
  CHECK_ZERO(parse_time_series_summary(buf, &summary));
  ret = run_summary_test(summary);
  free_time_series_summary(&summary);
  return ret;
}

DEF_TEST(collectd_time_series_response) {
  char buf[10000];
  ssize_t file_size;
  int ret;
  file_size = read_file_contents(SRCDIR "/src/collectd_time_series_response_test.json", buf,
                                 sizeof(buf) - 1);
  OK(file_size >= 0);
  buf[file_size] = 0;
  time_series_summary_t summary = {0};
  CHECK_ZERO(parse_time_series_summary(buf, &summary));
  ret = run_summary_test(summary);
  free_time_series_summary(&summary);
  return ret;
}

DEF_TEST(time_series_summary_add) {
  int ret;
  time_series_summary_t a = {
    .total_point_count = 5,
    .success_point_count = 2,
  };
  time_series_summary_t b = {
    .total_point_count = 7,
    .success_point_count = 3,
  };
  time_series_summary_t expected = {
    .total_point_count = 12,
    .success_point_count = 5,
  };
  time_series_summary_append_error(&a, 400, 1);
  time_series_summary_append_error(&a, 403, 2);
  time_series_summary_append_error(&b, 403, 1);
  time_series_summary_append_error(&b, 404, 3);
  time_series_summary_append_error(&expected, 400, 1);
  time_series_summary_append_error(&expected, 403, 3);
  time_series_summary_append_error(&expected, 404, 3);
  time_series_summary_add(&a, &b);
  ret = expect_time_series_summary_equals(&a, &expected);
  free_time_series_summary(&a);
  free_time_series_summary(&b);
  free_time_series_summary(&expected);
  return ret;
}

int main(void) {
  RUN_TEST(time_series_summary);
  RUN_TEST(collectd_time_series_response);
  RUN_TEST(time_series_summary_add);
  END_TEST;
}
