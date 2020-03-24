/**
 * collectd - src/stackdriver_agent.c
 * Copyright 2016 Google Inc. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Corey Kosak <kosak at google.com>
 **/

#include "collectd.h"

#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "daemon/utils_cache.h"
#include "liboconfig/oconfig.h"
#include "stackdriver-agent-keys.h"

#if KERNEL_WIN32
#include "utils_wmi.h"
static wmi_connection_t *wmi;
#endif /* KERNEL_WIN32 */

#define AGENT_PREFIX "agent.googleapis.com/agent"

static const char this_plugin_name[] = "stackdriver_agent";

static const char *hostname = NULL;

static const char *config_keys[] = {
  "Hostname",
};

static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

typedef struct {
  cdtime_t start_time;
} context_t;

static context_t *context_create() {
  context_t *result = calloc(1, sizeof(*result));
  if (result == NULL) {
    ERROR("%s: calloc failed.", this_plugin_name);
    return NULL;
  }
  result->start_time = cdtime();
  return result;
}

static void context_destroy(context_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  sfree(ctx);
}

static int sagt_submit_helper(
    const char *type, const char *type_instance, const char *plugin_instance,
    cdtime_t now, cdtime_t interval, value_t *value, meta_data_t *meta_data)
{
  value_list_t vl = {
    .values = value,
    .values_len = 1,
    .time = now,
    .interval = interval,
    .meta = meta_data
  };
  sstrncpy(vl.host, hostname != NULL ? hostname : hostname_g, sizeof(vl.host));
  sstrncpy(vl.plugin, "agent", sizeof(vl.plugin));
  sstrncpy(vl.type, type, sizeof(vl.type));
  sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));
  if (plugin_instance != NULL) {
    sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  }
  if (plugin_dispatch_values(&vl) != 0) {
    ERROR("%s: plugin_dispatch_values failed.", this_plugin_name);
    return -1;
  }
  return 0;
}

static int sagt_submit_gauge(
    const char *type_instance, const char *plugin_instance, cdtime_t now,
    cdtime_t interval, gauge_t gauge, meta_data_t *meta_data)
{
  value_t v = {.gauge = gauge};
  return sagt_submit_helper("gauge", type_instance, plugin_instance, now,
                            interval, &v, meta_data);
}

static int sagt_submit_derive(
    const char *type_instance, const char *plugin_instance, cdtime_t now,
    cdtime_t interval, derive_t derive, meta_data_t *meta_data)
{
  value_t v = {.derive = derive};
  return sagt_submit_helper("derive", type_instance, plugin_instance, now,
                            interval, &v, meta_data);
}


/**
 * Retrieve process memory used.
 */
static size_t sagt_process_memory_used() {
#if KERNEL_LINUX
  FILE *f = fopen("/proc/self/statm", "r");
  if (!f)
    return 0;

  size_t vm = 0;
  int status = fscanf(f, "%zu", &vm);
  fclose(f);
  if (!status) {
    return 0;
  }

  long page_size = sysconf(_SC_PAGESIZE);
  return vm * page_size;
#elif KERNEL_WIN32
  wmi_result_list_t *results;
  char statement[128];
  snprintf(statement, sizeof(statement),
           "select * from Win32_Process where ProcessID = %d", getpid());
  results = wmi_query(wmi, statement);

  if (results->count == 0) {
    ERROR("%s: no results for query %s.", this_plugin_name, statement);
    wmi_result_list_release(results);
    return 0;
  }

  if (results->count > 1) {
    WARNING("%s: multiple results for query %s.", this_plugin_name, statement);
  }

  wmi_result_t *result = wmi_get_next_result(results);
  VARIANT vm_value_v;

  if (wmi_result_get_value(result, "VirtualSize", &vm_value_v) != 0) {
    VariantClear(&vm_value_v);
    ERROR("%s: failed to read field 'VirtualSize'", this_plugin_name);
    wmi_result_release(result);
    return 0;
  }

  size_t mused = variant_get_int64(&vm_value_v);

  VariantClear(&vm_value_v);
  wmi_result_release(result);
  wmi_result_list_release(results);

  return mused;
#endif /* KERNEL_WIN32 */
}


/**
 * Send a variety of agent status/health-related metrics.
 */
static int sagt_read(user_data_t *user_data) {
  context_t *ctx = user_data->data;
  cdtime_t now = cdtime();
  cdtime_t interval = plugin_get_interval();

  // This value list exists merely for the purpose of harvesting its key fields for the purpose
  // of looking stuff up in the cache.
  value_list_t vl = {};  // zero-init
  sstrncpy(vl.plugin, this_plugin_name, sizeof(vl.plugin));

  // This function passes metric information using two mechanisms. The standard
  // collectd type and type_instance are useful for most plugins and expected by
  // some of the caching inside collectd, and the Stackdriver metadata is needed
  // to write these with the CreateTimeSeries call in the write_gcm plug-in.

  // uptime
  {
    meta_data_t *md = meta_data_create();
    if (meta_data_add_string(
            md, "stackdriver_metric_type", AGENT_PREFIX "/uptime") == 0 &&
        meta_data_add_string(md, "label:version", COLLECTD_USERAGENT) == 0) {
      derive_t uptime = CDTIME_T_TO_TIME_T(now - ctx->start_time);
      sagt_submit_derive("uptime", NULL, now, interval, uptime, md);
    }
    meta_data_destroy(md);
  }

  // memory used
  {
    size_t mused = sagt_process_memory_used();
    if (mused != 0) {
      meta_data_t *md = meta_data_create();
      if (meta_data_add_string(
              md, "stackdriver_metric_type",
              AGENT_PREFIX "/memory_usage") == 0) {
        sagt_submit_gauge("memory_usage", NULL, now, interval, mused, md);
      }
      meta_data_destroy(md);
    }
  }

  // Stats for API requests. The corresponding uc_meta_data_set calls are in
  // write_gcm.c.
  {
    meta_data_t *md = meta_data_create();
    if (meta_data_add_string(
            md, "stackdriver_metric_type",
            AGENT_PREFIX "/api_request_count") == 0) {
      uint64_t value;
      if (uc_meta_data_get_unsigned_int(
              &vl, SAGT_API_REQUESTS_SUCCESS, &value) == 0 &&
          meta_data_add_string(md, "label:state", "success") == 0) {
        sagt_submit_derive(
            "api_request_count", "success", now, interval, value, md);
      }
      if (uc_meta_data_get_unsigned_int(
              &vl, SAGT_API_REQUESTS_CONNECTIVITY_FAILURES, &value) == 0 &&
          meta_data_add_string(
              md, "label:state", "connectivity_failures") == 0) {
        sagt_submit_derive(
            "api_request_count", "connectivity_failures", now, interval, value,
            md);
      }
      if (uc_meta_data_get_unsigned_int(
              &vl, SAGT_API_REQUESTS_ERRORS, &value) == 0 &&
          meta_data_add_string(md, "label:state", "errors") == 0) {
        sagt_submit_derive(
            "api_request_count", "errors", now, interval, value, md);
      }
    }
    meta_data_destroy(md);
  }

  // Metric point_count from write_gcm.c.
  {
    value_list_t vl = {};  // zero-init
    int status;
    char **status_keys;
    sstrncpy(vl.plugin, this_plugin_name, sizeof(vl.plugin));
    sstrncpy(vl.plugin_instance, SAGT_POINT_COUNT, sizeof(vl.plugin_instance));
    status = uc_meta_data_toc(&vl, &status_keys);
    if (status > 0) {
      size_t status_keys_size = (size_t) status;
      meta_data_t *md = meta_data_create();
      if (meta_data_add_string(
              md, "stackdriver_metric_type",
              AGENT_PREFIX "/monitoring/point_count") == 0) {
        for (size_t i = 0; i < status_keys_size; ++i) {
          uint64_t value;
          if (uc_meta_data_get_unsigned_int(&vl, status_keys[i], &value) == 0 &&
              meta_data_add_string(md, "label:status", status_keys[i]) == 0) {
            sagt_submit_derive(
                SAGT_POINT_COUNT, status_keys[i], now, interval, value, md);
          }
        }
      }
      meta_data_destroy(md);
      for (size_t i = 0; i < status_keys_size; ++i)
        sfree(status_keys[i]);
      sfree(status_keys);
    }
  }

  // Cloud Monarch-related stats. The corresponding uc_meta_data_set calls are in
  // match_throttle_metadata_keys.c.
  {
    meta_data_t *md = meta_data_create();
    uint64_t streamspace_size;
    _Bool throttling;
    if (meta_data_add_string(
            md, "stackdriver_metric_type",
            AGENT_PREFIX "/streamspace_size") == 0 &&
        uc_meta_data_get_unsigned_int(
            &vl, SAGT_STREAMSPACE_SIZE, &streamspace_size) == 0) {
      sagt_submit_gauge(
          "streamspace_size", NULL, now, interval, streamspace_size, md);
    }
    if (meta_data_add_string(
            md, "stackdriver_metric_type",
            AGENT_PREFIX "/streamspace_size_throttling") == 0 &&
        uc_meta_data_get_boolean(
            &vl, SAGT_STREAMSPACE_SIZE_THROTTLING, &throttling) == 0) {
      sagt_submit_gauge(
          "streamspace_size_throttling", NULL, now, interval, throttling, md);
    }
    meta_data_destroy(md);
  }

  return 0;
}

/*
 * The init routine. Creates a context and registers a read callback.
 */
static int sagt_init() {
  int result = -1;  // Pessimistically assume failure.

  context_t *ctx = context_create();
  if (ctx == NULL) {
    goto leave;
  }

  user_data_t user_data = {
    .data = ctx,
    .free_func = (void (*)(void *)) &context_destroy
  };

  if (plugin_register_complex_read(NULL, this_plugin_name,
                                   &sagt_read, 0, &user_data) != 0) {
    ERROR("%s: plugin_register_complex_read failed.", this_plugin_name);
    goto leave;
  }

#if KERNEL_WIN32
  wmi = wmi_connect();
#endif /* KERNEL_WIN32 */

  ctx = NULL;  // Owned by plugin system now.
  result = 0;  // Success!

leave:
  context_destroy(ctx);
  return result;
}

/*
 * The shutdown routine.
 */
static int sagt_shutdown() {
#if KERNEL_WIN32
  wmi_release(wmi);
#endif /* KERNEL_WIN32 */
  return 0;
}

static int sagt_config(const char *key, const char *value) {
  if (strcmp(key, "Hostname") == 0) {
    hostname = (const char *)sstrdup(value);
    if (hostname == NULL) {
      ERROR("%s: sagt_config sstrdup failed.", this_plugin_name);
      return -1;
    }
    return 0;
  }
  WARNING("%s: Unknwon config option found. Key: %s, Value: %s",
          this_plugin_name, key, value);
  return -1;
}

/* Register this module with collectd */
void module_register(void) {
  plugin_register_config(this_plugin_name, sagt_config, config_keys,
                         config_keys_num);
  plugin_register_init(this_plugin_name, sagt_init);
  plugin_register_shutdown(this_plugin_name, sagt_shutdown);
}
