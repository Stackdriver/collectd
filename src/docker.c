/**
 * collectd - src/docker.c
 * Copyright (C) 2017  Google Inc.
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
 *   Dhrupad Bhardwaj <dhrupad at google.com>
 **/

#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "utils_avltree.h"
#include "yajl/yajl_tree.h"

#include <curl/curl.h>

// Default size of the response buffer when calling the Docker stats API
#define RESPONSE_BUFFER_SIZE 16400

// The default version of the Docker API engine and the default UNIX socket
// to which the API writes responses.
static const char *DEFAULT_SOCKET = "/var/run/docker.sock";
static const char *DEFAULT_VERSION = "1.23";

// Useragent used to make the cURL request to the Docket STATs API.
const char *USERAGENT = "stackdriver-docker-plugin";

// Struct used by curl_get_json to copy over the STATs API response after 
// invoking the GET request.
typedef struct {
  char *data;
  size_t size;
} curl_write_ctx_t;

// Disk metrics for a given device (sda/ or 8.0)
typedef struct {
  unsigned long read; // Number of bytes read from disk.
  unsigned long write; // Number of bytes written to disk.
  unsigned long sync; // Number of bytes read/written synchronously.
  unsigned long async; // Number of bytes read/writen asynchronously.
  unsigned long total; // Total bytes = read + write = sync + async.
} blkio_device_stats_t;

// Struct with all supported BlockIO metric types and values.
typedef struct {
  c_avl_tree_t *io_bytes; // Metrics for bytes transferred to/from disk.
} blkio_stats_t;

//Block IO (Disk) Stats
static const char *BLKIO_TYPE_KEYS[] = {
  "major", // First number describing an IO device (i.e. 8 for /sda)
  "minor", // Second number describing an IO device (i.e. 0 for /sda)
  "value", // Metric value
};

static const char *BLKIO_KEYS[] = {
  "io_service_bytes_recursive",
};

static const char *BLKIO_PATH[] = { "blkio_stats", (const char *) 0 };

// Stats for a given CPU core.
typedef struct {
  unsigned long usage; // CPU seconds used for the particular core.
  unsigned long idle; // CPU seconds idle for the particular core.
  double percent_used; // % of CPU used by the core.
  double percent_idle; // % of CPU left idle by the core.
} cpu_core_stats_t;

//CPU Stats
typedef struct {
  unsigned long system_cpu_usage; // Total number of CPU seconds used.
  unsigned long num_cpus; // Number of cores on the machine.
  cpu_core_stats_t **percpu_stats; // List of CPU stats per core.
} cpu_stats_t;

// Structure which stores historical CPU metrics from interval t-1 to calculate
// deltas from cumulative values.
typedef struct {
  cdtime_t t; // Time at which stats were polled.
  unsigned long old_system_usage;
  // Total number of CPU seconds used at time t-1.
  unsigned long *old_percpu_usage;
  // List of CPU used seconds per core at time t-1.
  unsigned long num_cpus; // Number of cores on the machine.
} cpu_state_t;

c_avl_tree_t *cpu_hist_values = NULL;
// AVL tree map with the CPU core for keys and historical stats for values.

static const char *CPU_KEYS[] = {
  "system_cpu_usage",
};

static const char *CPU_PATH[] = { "cpu_stats", (const char *) 0 };

//Memory Stats
typedef struct {
  unsigned long usage; // Memory bytes used at time t.
  unsigned long limit; // Total bytes of memory available (i.e. used + free).
  unsigned long free; // Remaining bytes of memory available at time t.
  double percent_used; // % of memory used.
  double percent_free; // Remaining % of memory available.
} memory_stats_t;

static const char *MEMORY_RESPONSE_KEYS[] = {
  "usage",
  "limit",
};

static const char *MEMORY_METRIC_TYPES[] = {
  "used",
  "available",
};

static const char *MEMORY_PATH[] = { "memory_stats", (const char *) 0 };

// Connection metrics for a given interface
typedef struct {
  char *name; // Interface device name (i.e. eth0)
  unsigned long rx_bytes; // Number of bytes received.
  unsigned long rx_packets; // Number of packets received.
  unsigned long rx_errors; // Number of errors occurred in receiving data.
  unsigned long tx_bytes; // Number of bytes transferred.
  unsigned long tx_packets; // NUmber of packets transferred.
  unsigned long tx_errors; // Number of errors occured in transmitting data.
} interface_stats_t;

static const char *INTERFACE_KEYS[] = {
  "bytes",
  "packets",
  "errors",
};

static const char *NETWORK_PATH[] = { "networks", (const char *) 0 };

typedef struct {
  size_t count;
  interface_stats_t **interfaces; // List of metrics for every network interface.
} network_stats_t;

typedef struct {
  char *name; // Container name.
  blkio_stats_t *blkio_stats; // Disk stats.
  cpu_stats_t *cpu_stats; // CPU stats.
  memory_stats_t *memory_stats; // Memory stats.
  network_stats_t *network_stats; // Network interface stats.
} container_stats_t;

static const char *DOCKER_VERSION = NULL;
static const char *DOCKER_SOCKET = NULL;

static const char *config_version = NULL;
static const char *config_socket = NULL;

static const char *config_keys[] = {
  "Socket",
  "Version"
};

static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

//==============================================================================
//==============================================================================
//==============================================================================
// Misc utility functions.
//==============================================================================
//==============================================================================
//==============================================================================

static void free_list(void ***p, int size) {
  void **ptr = *p;
  for (int i = 0; i < size; i++) {
    if (ptr[i] != NULL) {
      sfree(ptr[i]);
      ptr[i] = NULL;
    }
  }
  sfree(ptr);
  ptr = NULL;
}

// Takes a string containing commas as a delimiter and creates an array of
// strings terminated by a NULL string. Used to create paths required to
// traverse the YAJL tree.
static const char **tokenize_path(const char *path, int *len) {
  if (strlen(path) == 0) { *len = 0; return NULL; }
  int count = 1;
  for (int i = 0; i < strlen(path); i++) {
    if (path[i] == ',') {
      count++;
    }
  }
  char *copy_str = sstrdup(path);
  const char **tokens = (const char **) calloc(count + 1, sizeof(char *));
  if (tokens == NULL) {
    ERROR("docker: tokenize_path: malloc failed!");
    return NULL;
  }
  char *rest = (char *) copy_str;
  const char **tok_ptr = tokens;
  char *ptr = strtok_r(copy_str, ",", &rest);
  while (ptr != NULL) {
    *tokens = ptr;
    tokens++;
    ptr = strtok_r(NULL, ",", &rest);
  }
  *tokens = (const char *) 0;
  *len = count;
  return tok_ptr;
}

static void free_blkio_device_tree(c_avl_tree_t *tree) {
  void *key;
  void *value;
  while (c_avl_pick(tree, (void **) &key, (void **) &value) == 0) {
      sfree(key);
      sfree(value);
  }
  c_avl_destroy(tree);
}

static void free_blkio(blkio_stats_t *stats) {
  if (stats == NULL) return;
  c_avl_tree_t *ptrs[] = {
    stats->io_bytes,
  };
  for (int i = 0; i < STATIC_ARRAY_SIZE(ptrs); i++) {
    if (ptrs[i] != NULL) {
      free_blkio_device_tree(ptrs[i]);
    }
  }
  sfree(stats);
}

static void free_cpu(cpu_stats_t *stats) {
  if (stats == NULL) return;
  for (int i = 0; i < stats->num_cpus; i++) {
    if (stats->percpu_stats[i] != NULL) {
      sfree(stats->percpu_stats[i]);
    }
  }
  sfree(stats);
}

static void free_network_stats(network_stats_t *stats) {
  if (stats == NULL) return;
  for (int i = 0; i < stats->count; i++) {
    if (stats->interfaces[i] != NULL) {
      sfree(stats->interfaces[i]->name);
      sfree(stats->interfaces);
    }
  }
  sfree(stats);
}

static void free_stats(container_stats_t *stats) {
  if (stats == NULL) return;
  if (stats->blkio_stats != NULL) {
    free_blkio(stats->blkio_stats);
  }
  if (stats->cpu_stats != NULL) {
    free_cpu(stats->cpu_stats);
  }
  if (stats->memory_stats != NULL) {
    sfree(stats->memory_stats);
  }
  if (stats->network_stats != NULL) {
    free_network_stats(stats->network_stats);
  }
  if (stats->name != NULL) {
    sfree(stats->name);
  }
 sfree(stats);
}

// Copied from src/write_gcm.c. As all collectd methods are static, copying this
// instead of rewriting it as a separate utility method. This method 
// implements the callback needed by curl_get_json() to retrieve data from cURL
// call.
static size_t plugin_curl_write_callback(char *ptr, size_t size,
    size_t num_members, void *userdata) {
  curl_write_ctx_t *ctx = userdata;
  if (ctx->size == 0) {
    return 0;
  }
  size_t requested_bytes = size *num_members;
  size_t actual_bytes = requested_bytes;
  if (actual_bytes >= ctx->size) {
    actual_bytes = ctx->size - 1;
  }
  memcpy(ctx->data, ptr, actual_bytes);
  ctx->data += actual_bytes;
  ctx->size -= actual_bytes;

  // We lie about the number of bytes successfully transferred to prevent curl
  // from returning an error to our caller. Our caller is keeping track of
  // buffer consumption so it will independently know if the buffer filled up;
  // the only errors it wants to hear about from curl are the more 
  // catastrophic ones.
  return requested_bytes;
}

// Using implementation with modifications from src/write_gcm.c. Removed support
// for POST requests as all calls to the Docker Engine API are GET requests.
// Additionally this makes the call specifically to a UNIX socket.
static int curl_get_json(char *response_buffer, size_t response_buffer_size,
    const char *url, const char *socket) {
  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    ERROR("docker: curl_easy_init failed");
    return -1;
  }
  curl_write_ctx_t write_ctx = {
    .data = response_buffer,
    .size = response_buffer_size
  };

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, USERAGENT);
  int status = curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, socket);
  if (status != CURLE_OK) {
    ERROR("docker: curl_easy_setopt() failed: %s\n",
	  curl_easy_strerror(status));
    curl_easy_cleanup(curl); return -1;
  }
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &plugin_curl_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_ctx);
  // http://stackoverflow.com/questions/9191668/error-longjmp-causes-uninitialized-stack-frame
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);	// 5 seconds.


  int curl_result = curl_easy_perform(curl);
  if (curl_result != CURLE_OK) {
    ERROR("docker: curl_easy_perform() failed: %s",
	  curl_easy_strerror(curl_result));
    curl_easy_cleanup(curl); return -1;
  }

  long response_code;
  curl_result = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
  write_ctx.data[0] = 0;
  if (response_code >= 400) {
    ERROR("docker: Unsuccessful HTTP request %ld: %s",
	  response_code, response_buffer);
    curl_easy_cleanup(curl); return -2;
  }

  if (write_ctx.size < 2) {
    ERROR("docker: curl_get_json: The receive buffer overflowed.");
    DEBUG("docker: curl_get_json: Received data is: %s", response_buffer);
    curl_easy_cleanup(curl); return -2;
  }

  return 0;			// Success!
}

//==============================================================================
//==============================================================================
//==============================================================================
// Functionality to compute derived statistics.
//==============================================================================
//==============================================================================
//==============================================================================

// Computes percentages for CPU metrics in different states.
static void compute_cpu_stats(cpu_core_stats_t **stats,
    unsigned long system_cpu_usage, int total_cores, int active_cores,
    const char *container_id) {
  cdtime_t now = cdtime();
  cpu_state_t *old_stats = NULL;
  if (c_avl_get(cpu_hist_values, (void *) container_id,
                    (void **) &old_stats) == 0) {
    assert(total_cores == old_stats->num_cpus);
    assert(now >= old_stats->t);
    unsigned long delta_system_cpu = system_cpu_usage -
        old_stats->old_system_usage;
    // We divide the total number of CPU cycles used evenly among the cores
    // with a non-zero number of seconds used. This assumes the scheduler is
    // equally likely to pick the cores. We use cores with non-zero values
    // only as it is possible for a particular core to be disabled and thus not
    // picked by the scheduler at all.
    unsigned long proportional_footprint = delta_system_cpu/active_cores;
    for (int i = 0; i < total_cores; i++) {
      stats[i]->idle = delta_system_cpu/active_cores - stats[i]->usage;
      old_stats->old_percpu_usage[i] = stats[i]->usage;
      old_stats->old_system_usage = system_cpu_usage;
      // We set the stats here to a default value in case a counter reset
      // occures.
      stats[i]->percent_used = (100.00*stats[i]->usage)/proportional_footprint;
      stats[i]->percent_idle = 100.00 - stats[i]->percent_used;
      if ((stats[i]->usage < old_stats->old_percpu_usage[i]) ||
              (system_cpu_usage < old_stats->old_system_usage)) {
        DEBUG("docker.c: compute_cpu_stats Counter reset occurred.");
        continue;
      }
      unsigned long delta_percpu = stats[i]->usage -
          old_stats->old_percpu_usage[i];
      if (delta_system_cpu < delta_percpu) {
        DEBUG("docker: system seconds less than core seconds."
              " System Seconds: %lu, CPU Seconds: %lu.", delta_system_cpu,
              delta_percpu);
        continue;
      }
      double used_percent =
          proportional_footprint > 0 ?
              (delta_percpu*100.00)/proportional_footprint : 0.00;
      if (used_percent > 100) {
        // If the values are bad, we let the default values set above get passed
        // through and log the error.
        ERROR("docker: Invalid CPU values for core %d. Used percentage: %lf, "
              "Proportional System seconds: %lu, CPU seconds: %lu,"
              "Old seconds: %lu, Num active cores: %d.", i, used_percent,
              proportional_footprint, delta_percpu,
              old_stats->old_percpu_usage[i], active_cores);
      } else {
        stats[i]->percent_used = used_percent;
        stats[i]->percent_idle = 100.00 - used_percent;
      }
    }
  } else {
    unsigned long proportional_footprint = system_cpu_usage/active_cores;
    for (int i = 0; i < total_cores; i++) {
      stats[i]->idle = proportional_footprint - stats[i]->usage;
    }
    cpu_state_t *old_stats = (cpu_state_t *) calloc(1, sizeof(cpu_state_t));
    if (old_stats == NULL) {
      ERROR("docker: compute_cpu_stats. malloc failed! Could not allocate"
            " historical stats struct for container %s.", container_id);
      return;
    }
    old_stats->t = now;
    old_stats->num_cpus = total_cores;
    old_stats->old_system_usage = system_cpu_usage;
    old_stats->old_percpu_usage =
        (unsigned long *) calloc(total_cores, sizeof(unsigned long));
    if (old_stats->old_percpu_usage == NULL) {
      ERROR("docker: compute_cpu_stats. malloc failed! Could not allocate"
            " historical stats list for container %s", container_id);
      sfree(old_stats);
      old_stats = NULL;
      return;
    }
    for (int i = 0; i < total_cores; i++) {
      old_stats->old_percpu_usage[i] = stats[i]->usage;
      stats[i]->percent_used = system_cpu_usage > 0 ?
          (100.00*stats[i]->usage)/proportional_footprint : 0.00;
      if (stats[i]->percent_used > 100) {
        ERROR("docker: Invalid CPU values for core %d. Used percentage: %lf, "
              "Proportional System seconds: %lu, CPU seconds: %lu,"
              "Num active cores: %d.", i,
              stats[i]->percent_used, proportional_footprint, stats[i]->usage,
              active_cores);
        stats[i]->percent_used = 0.00;
        stats[i]->percent_idle = 100.00;
      } else {
        stats[i]->percent_idle = 100.00 - stats[i]->percent_used;
      }
    }
    if (c_avl_insert(cpu_hist_values, (void *) container_id,
           (void *) old_stats) < 0) {
      ERROR("docker: c_avl_insert failed!");
    }
  }
}

// Computes percentages for memory metrics in different states.
static void compute_memory_stats(memory_stats_t *stats) {
  if (stats == NULL) {
    ERROR("docker: compute_memory_stats. memory stats NULL");
  }
  stats->free = stats->limit - stats->usage;
  stats->percent_used = (stats->usage * 100.00)/(stats->limit);
  stats->percent_free = 100.00 - stats->percent_used;
}

//==============================================================================
//==============================================================================
//==============================================================================
// Functionality to parse the Docker Stats JSON response and retrieve stats.
//==============================================================================
//==============================================================================
//==============================================================================

// Retrieves the list of 64 character container IDs from the containers/json
// endpoint.
static int extract_container_ids_from_response(char ***container_list,
    char *response_buffer) {
  yajl_val node;
  char errbuf[1024];
  int num_containers = -1;
  char **list;
  node = yajl_tree_parse(response_buffer, errbuf, sizeof(errbuf));
  if (node == NULL) {
    if (strlen(errbuf)) {
      ERROR("docker: parse_error: %s.\n", errbuf);
    } else {
      ERROR("docker: extract_container_ids_from_response: parse_error.\n");
    }
    return num_containers;
  }
  if (node->u.array.len == 0) {
    yajl_tree_free(node);
    return 0;
  }

  const char *id_path[] = { "Id", (const char *) 0 };
  if (YAJL_IS_ARRAY(node)) {
    list = (char **) calloc(node->u.array.len, sizeof(char *));
    if (list == NULL) {
      ERROR("docker: extract_container_ids_from_response: malloc failed!");
      yajl_tree_free(node);
      return -1;
    }
    num_containers = node->u.array.len;
    for (int i = 0; i < num_containers; i++) {
      yajl_val elem = node->u.array.values[i];
      yajl_val id_node = yajl_tree_get(elem, id_path, yajl_t_string);
      if (!YAJL_IS_OBJECT(id_node)) {
	list[i] = sstrdup(YAJL_GET_STRING(id_node));
      } else {
	ERROR("docker: Container ID could not be extracted.\n");
        DEBUG("docker: Bad response:\n %s", response_buffer);
      }
    }
    *(container_list) = list;
  }
  yajl_tree_free(node);
  return num_containers;
}

static int get_container_list(const char *socket, const char *version,
    char ***container_list) {
  char *response_buffer = (char *) calloc(RESPONSE_BUFFER_SIZE, sizeof(char));
  char *url = (char *) calloc(28, sizeof(char));
  int count = 0;
  if (response_buffer == NULL || url == NULL) {
    ERROR("docker: get_container_list: malloc failed!");
  }
  ssnprintf(url, 28, "http:/v%s/containers/json", version);
  int result = curl_get_json(response_buffer, RESPONSE_BUFFER_SIZE, url, socket);
  if (result != 0) {
    WARNING("docker.c: Error occurred when querying Docker Engine API");
  } else {
    count = extract_container_ids_from_response(container_list, response_buffer);
  }
  sfree(response_buffer);
  sfree(url);
  return count;
}

// Extracts a string from the YAJL node and sets it to the result_ptr.
static void extract_string(yajl_val node, const char *key, char **result_ptr) {
  char *result = NULL;
  int tokens;
  const char **path = tokenize_path(key, &tokens);
  yajl_val val_node = yajl_tree_get(node, path, yajl_t_string);
  if (YAJL_IS_STRING(val_node)) {
    result = sstrdup(YAJL_GET_STRING(val_node));
    if (result == NULL) {
      ERROR("docker: extract_string. sstrdup failed.");
    }
  } else {
    WARNING("docker: %s not parsed.", key);
  }
  free_list((void ***) &path, tokens-1);
  *(result_ptr) = result;
}

// Extracts an array of unsigned long values from the YAJL node.
// Retuns the number of array elements. -1 in case of an error.
static int extract_arr_value(yajl_val node, const char *key,
    unsigned long **result_ptr) {
  int tokens;
  int len = -1; // Pessimistically assume error.
  const char **path = tokenize_path(key, &tokens);
  yajl_val val_node = yajl_tree_get(node, path, yajl_t_array);
  if (YAJL_IS_ARRAY(val_node)) {
    unsigned long *ptrs = (unsigned long *)
        calloc(val_node->u.array.len, sizeof(unsigned long));
    if (ptrs == NULL) {
      ERROR("docker_plugin: extract_arr_value malloc failed.\n");
      // We don't want to free the tokens[len-1]th element as it is a NULL
      // string.
      free_list((void ***) &path, tokens-1);
      return -1;
    }
    for (int i = 0; i < val_node->u.array.len; i++) {
      ptrs[i] = YAJL_GET_INTEGER(val_node->u.array.values[i]);
    }
    *(result_ptr) = ptrs;
    len = val_node->u.array.len;
  } else {
    WARNING("docker_plugin: %s not parsed.", key);
  }

  // We don't want to free the tokens[len-1]th element as it is a NULL string.
  free_list((void ***) &path, tokens-1);
  return len;
}

// Extracts a single unsigned long value from the YAJL node.
static int extract_value(yajl_val node, const char *key,
    unsigned long *result_ptr) {
  int ret_val = -1; // Pessimistically assume error.
  unsigned long result = 0;
  int tokens;
  const char **path = tokenize_path(key, &tokens);
  yajl_val val_node = yajl_tree_get(node, path, yajl_t_any);
  if (YAJL_IS_ARRAY(val_node)) {
    if (val_node->u.array.len > 0)
      result = YAJL_GET_INTEGER(val_node->u.array.values[0]);
    ret_val = 0;
  } else if (YAJL_IS_NUMBER(val_node)) {
    result = YAJL_GET_INTEGER(val_node);
    ret_val = 0;
  } else {
    WARNING("docker: %s not parsed.", key);
  }
  free_list((void ***) &path, tokens-1);
  *(result_ptr) = result;
  return ret_val;
}

// Takes a parsed BlockIO stats and creates a stat structure for that device
// or updates the stats for an existing device.
static int insert_blkio_stat_in_tree(c_avl_tree_t *tree, char *op,
    unsigned long major, unsigned long minor, unsigned long value) {
  char *key = (char *) calloc(4, sizeof(char));
  if (key == NULL) {
    ERROR("docker: insert_blkio_stat_in_tree: malloc failed");
    return -1;
  }
  ssnprintf(key, 4, "%lu.%lu", major, minor);
  blkio_device_stats_t *stats = NULL;
  if (c_avl_get(tree, (const void *) key, (void *) (&stats)) != 0) {
    stats = (blkio_device_stats_t *) calloc (1, sizeof(blkio_device_stats_t));
    if (stats == NULL) {
      ERROR("docker: insert_blkio_stat_in_tree: malloc failed!");
      return -1;
    }
    if (c_avl_insert(tree, (void *) key, (void *) stats) < 0) {
      ERROR ("docker: c_avl_insert failed due to error.");
      sfree(stats);
      return -1;
    }
  }
  if (strcmp(op, "Read") == 0) {
    stats->read = value;
  }
  if (strcmp(op, "Write") == 0) {
    stats->write = value;
  }
  if (strcmp(op, "Sync") == 0) {
    stats->sync = value;
  }
  if (strcmp(op, "Async") == 0) {
    stats->async = value;
  }
  if (strcmp(op, "Total") == 0) {
    stats->total = value;
  }
  return 0;
}

// Extracts BlockIO (Disk) stats of a given type from the STATS API response.
static int extract_blkio_values(yajl_val node, c_avl_tree_t *tree) {
  int result = -1;
  unsigned long major, minor, value;
  unsigned long *result_ptr[] = {
    &(major),
    &(minor),
    &(value),
  };

  assert(STATIC_ARRAY_SIZE(BLKIO_TYPE_KEYS) == STATIC_ARRAY_SIZE(result_ptr));
  for (int i = 0; i < STATIC_ARRAY_SIZE(BLKIO_TYPE_KEYS); i++) {
    if(extract_value(node, BLKIO_TYPE_KEYS[i], result_ptr[i]) == -1) {
      ERROR("docker: extract_blkio_values failed");
      return -1;
    }
  }
  static const char *op_path[] = { "op", (const char *) 0 };
  yajl_val op_node = yajl_tree_get(node, op_path, yajl_t_string);
  if (YAJL_IS_STRING(op_node)) {
    char *op = YAJL_GET_STRING(op_node);
    result = insert_blkio_stat_in_tree(tree, op, major, minor, value);
  }
  return result;
}

// Extracts all BlockIO (Disk) stats for all devices and populates the
// device to stats tree.
static void extract_blkio_struct(yajl_val node, const char *key,
                                 c_avl_tree_t **result_ptr) {
  c_avl_tree_t *device_tree = c_avl_create((
      int(*)(const void *, const void *))&strcmp);
  if (device_tree == NULL) {
    ERROR("docker: extract_blkio_struct: c_avl_create failed!");
    *(result_ptr) = NULL;
    return;
  }
  int tokens;
  const char **path = tokenize_path(key, &tokens);
  yajl_val val_node = yajl_tree_get(node, path, yajl_t_any);
  if (YAJL_IS_ARRAY(val_node) && val_node->u.array.len > 0) {
    for (int i = 0; i < val_node->u.array.len; i++) {
      if(extract_blkio_values(val_node->u.array.values[i], device_tree) == -1) {
        c_avl_destroy(device_tree);
        *(result_ptr) = NULL;
      }
    }
  } else {
    c_avl_destroy(device_tree);
    device_tree = NULL;
  }

  free_list((void ***) &path, tokens-1);
  *(result_ptr) = device_tree;
  return;
}

static void get_blkio_stats(yajl_val node, container_stats_t *stats) {
  stats->blkio_stats = (blkio_stats_t *) calloc(1, sizeof(blkio_stats_t));
  if (stats->blkio_stats == NULL) {
    ERROR("docker: get_block_io_stats: malloc failed!");
  }
  yajl_val blkio_node = yajl_tree_get(node, BLKIO_PATH, yajl_t_object);
  if (!YAJL_IS_OBJECT(blkio_node)) {
    ERROR("docker: BlockIO stats cannot be parsed. JSON Error.");
    sfree(stats->blkio_stats);
    return;
  }

  c_avl_tree_t **result_ptrs[] = {
    &(stats->blkio_stats->io_bytes),
  };

  assert(STATIC_ARRAY_SIZE(BLKIO_KEYS) == STATIC_ARRAY_SIZE(result_ptrs));
  for (int i = 0; i < STATIC_ARRAY_SIZE(BLKIO_KEYS); i++) {
    extract_blkio_struct(blkio_node, BLKIO_KEYS[i], result_ptrs[i]);
  }
}

// Retrieves CPU statistics from the STATS API response
static int get_cpu_stats(yajl_val node, container_stats_t *stats,
    const char *container_id) {
  unsigned long *percpu_usage;
  stats->cpu_stats = (cpu_stats_t *) calloc(1, sizeof(cpu_stats_t));
  if (stats->cpu_stats == NULL) {
    ERROR("docker: get_cpu_stats: malloc failed!");
    return -1;
  }
  yajl_val cpu_node = yajl_tree_get(node, CPU_PATH, yajl_t_object);
  if (!YAJL_IS_OBJECT(cpu_node)) {
    ERROR("docker: CPU stats cannot be parsed. JSON Error.");
    goto leave;
  }

  unsigned long *result_ptrs[] = {
    &(stats->cpu_stats->system_cpu_usage),
  };

  assert(STATIC_ARRAY_SIZE(CPU_KEYS) == STATIC_ARRAY_SIZE(result_ptrs));
  for (int i = 0; i < STATIC_ARRAY_SIZE(CPU_KEYS); i++) {
    if (extract_value(cpu_node, CPU_KEYS[i], result_ptrs[i]) != 0) {
      ERROR("docker: Unable to parse system_cpu_usage. CPU stats not populated"
            " in this cycle.");
      goto leave;
    }
  }

  int len = extract_arr_value(cpu_node, "cpu_usage,percpu_usage", &percpu_usage);
  if (len <= 0) {
    WARNING("docker: No CPU stats found or unable to parse percpu_stats. CPU"
            " stats not populated in this cycle.");
    goto leave;
  }
  stats->cpu_stats->num_cpus = (unsigned long) len;
  stats->cpu_stats->percpu_stats =
      (cpu_core_stats_t **) calloc(len, sizeof(cpu_core_stats_t *));
  if (stats->cpu_stats->percpu_stats == NULL) {
    ERROR("docker: get_cpu_stats: malloc failed!");
    sfree(percpu_usage);
    goto leave;
  }
  int active_cores = 0;
  for (int i = 0; i < len; i++) {
    stats->cpu_stats->percpu_stats[i] =
        (cpu_core_stats_t *) calloc (1, sizeof(cpu_core_stats_t));
    if (stats->cpu_stats->percpu_stats[i] == NULL) {
      ERROR("docker: get_cpu_stats: malloc failed. Core %d stats not populated",
            i);
      continue;
    }
    stats->cpu_stats->percpu_stats[i]->usage = percpu_usage[i];
    if (stats->cpu_stats->percpu_stats[i] > 0) active_cores++;
  }

  compute_cpu_stats(stats->cpu_stats->percpu_stats,
      stats->cpu_stats->system_cpu_usage, len, active_cores, container_id);
  return 0;
 leave:
  sfree(stats->cpu_stats);
  stats->cpu_stats = NULL;
  return -1;
}

// Retrieves Memory statistics from the STATS API response
static void get_memory_stats(yajl_val node, container_stats_t *stats) {
  stats->memory_stats = (memory_stats_t *) calloc(1, sizeof(memory_stats_t));
  if (stats->memory_stats == NULL) {
    ERROR("docker: get_memory_stats: malloc failed!");
  }
  yajl_val memory_node = yajl_tree_get(node, MEMORY_PATH, yajl_t_object);
  if (!YAJL_IS_OBJECT(memory_node)) {
    ERROR("docker: memory stats cannot be parsed. JSON Error.");
    sfree(stats->memory_stats);
    return;
  }

  unsigned long *result_ptrs[] = {
    &(stats->memory_stats->usage),
    &(stats->memory_stats->limit),
  };

  assert(STATIC_ARRAY_SIZE(MEMORY_RESPONSE_KEYS)
             == STATIC_ARRAY_SIZE(result_ptrs));
  for (int i = 0; i < STATIC_ARRAY_SIZE(MEMORY_RESPONSE_KEYS); i++) {
    extract_value(memory_node, MEMORY_RESPONSE_KEYS[i], result_ptrs[i]);
  }
  compute_memory_stats(stats->memory_stats);
}

// Extracts stats for a given interface.
static void get_interface_stats(yajl_val interface_node,
    interface_stats_t *stats) {
  //Network Stats
  unsigned long *rx_result_ptrs[] = {
    &(stats->rx_bytes),
    &(stats->rx_packets),
    &(stats->rx_errors),
  };

  unsigned long *tx_result_ptrs[] = {
    &(stats->tx_bytes),
    &(stats->tx_packets),
    &(stats->tx_errors),
  };

  assert(STATIC_ARRAY_SIZE(INTERFACE_KEYS) == STATIC_ARRAY_SIZE(rx_result_ptrs));
  assert(STATIC_ARRAY_SIZE(INTERFACE_KEYS) == STATIC_ARRAY_SIZE(tx_result_ptrs));
  for (int i = 0; i < STATIC_ARRAY_SIZE(INTERFACE_KEYS); i++) {
    // Format: tx_{interface_key}\0 .
    // 4 characters is for "tx_" and terminating "\0" character.
    int len = strlen(INTERFACE_KEYS[i]) + 4;
    char *tx_key = (char *) calloc(len, sizeof(char));
    char *rx_key = (char *) calloc(len, sizeof(char));
    if (tx_key == NULL || rx_key == NULL) {
      ERROR("docker: get_metrics_for_container: malloc failed. Unable to get"
            " network interface %s stats.", INTERFACE_KEYS[i]);
      return;
    }
    ssnprintf(tx_key, len, "tx_%s", INTERFACE_KEYS[i]);
    ssnprintf(rx_key, len, "rx_%s", INTERFACE_KEYS[i]);
    extract_value(interface_node, tx_key, tx_result_ptrs[i]);
    extract_value(interface_node, rx_key, rx_result_ptrs[i]);
    sfree(tx_key);
    sfree(rx_key);
  }
}

// Retrieves Network statistics for each networking interface from the STATS API
// response.
static int get_network_stats(yajl_val node, container_stats_t *stats) {
  stats->network_stats = (network_stats_t *) calloc(1, sizeof(network_stats_t));
  if (stats->network_stats == NULL) {
    ERROR("docker: get_network_stats: malloc failed!");
  }

  yajl_val network_node = yajl_tree_get(node, NETWORK_PATH, yajl_t_object);
  if (!YAJL_IS_OBJECT(network_node)) {
    ERROR("docker: network interface stats cannot be parsed. JSON Error.");
    sfree(stats->network_stats);
    return -1;
  }
  unsigned int num_interfaces = STATIC_ARRAY_SIZE(network_node->u.object.keys);
  stats->network_stats->interfaces = (interface_stats_t **)
      calloc(num_interfaces, sizeof(interface_stats_t *));
  if (stats->network_stats->interfaces == NULL) {
    ERROR("docker: get_network_stats: malloc failed!");
    sfree(stats->network_stats);
    stats->network_stats = NULL;
    return -1;
  }
  int successes = 0;
  // This is the number of interfaces in the response from the Docker stats API.
  // This may be more than the actual number of interface statistics
  // successfully parsed.
  stats->network_stats->count = num_interfaces;
  for (int i = 0; i < num_interfaces; i++) {
    stats->network_stats->interfaces[i] = (interface_stats_t *)
        calloc(1, sizeof(interface_stats_t));
    if (stats->network_stats->interfaces[i] == NULL) {
      ERROR("docker: get_network_stats: malloc failed!");
      continue;
    }
    const char *interface_name = network_node->u.object.keys[i];
    stats->network_stats->interfaces[i]->name = sstrdup(interface_name);
    if (stats->network_stats->interfaces[i]->name == NULL) {
      ERROR("docker: get_network_stats sstrdup failed for %s!", interface_name);
      sfree(stats->network_stats->interfaces[i]);
      stats->network_stats->interfaces[i] = NULL;
      continue;
    }
    const char *interface_path[] = { interface_name, (const char *) 0 };
    yajl_val interface_node =
        yajl_tree_get(network_node, interface_path, yajl_t_object);
    if (!YAJL_IS_OBJECT(interface_node)) {
      ERROR("docker: interface stats for %s cannot be parsed. JSON Error.",
            interface_name);
      sfree(stats->network_stats->interfaces[i]->name);
      sfree(stats->network_stats->interfaces[i]);
      continue;
    }
    get_interface_stats(interface_node, stats->network_stats->interfaces[i]);
    successes++;
  }
  if (successes == 0) {
    WARNING("Interface stats for all %d interface(s) could not be parsed",
            num_interfaces);
    sfree(stats->network_stats);
    stats->network_stats = NULL;
  }
  return successes;
}

// Parses the JSON response from the Docker STATS API and extracts metrics
// for memory, disk, CPU and networking interfaces.
static void extract_stats_from_response(char *response_buffer,
    container_stats_t **stats, const char *container_id) {
  yajl_val node;
  char errbuf[1024];
  container_stats_t *ptr = (container_stats_t *)
      calloc(1, sizeof(container_stats_t));
  if (ptr == NULL) {
    ERROR("docker: extract_stats_from_response: malloc failed!");
    return;
  }
  node = yajl_tree_parse(response_buffer, errbuf, sizeof(errbuf));
  if (node == NULL) {
    if (strlen(errbuf)) {
      ERROR("docker: parse_error: %s.\n", errbuf);
    } else {
      ERROR("docker: parse_error.\n");
    }
    free_stats(ptr);
    return;
  }
  get_memory_stats(node, ptr);
  get_blkio_stats(node, ptr);
  get_cpu_stats(node, ptr, container_id);
  if (get_network_stats(node, ptr) <= 0) {
    WARNING("Network stats could not be parsed");
  }
  extract_string(node, "name", &(ptr->name));
  if (ptr->name == NULL) {
    WARNING("docker: extract_stats_from_response: container name could not be"
            " parsed from Docker API response.");
  }
  yajl_tree_free(node);
  *(stats) = ptr;
}

static container_stats_t *get_stats_for_container(const char *container_id,
    const char *socket, const char *version) {
  char *response_buffer = (char *) calloc(RESPONSE_BUFFER_SIZE, sizeof(char));
  if (response_buffer == NULL) {
    ERROR("docker: get_metrics_for_container: malloc failed.\n");
    return NULL;
  }
  char *url = (char *) calloc(107, sizeof(char));
  if (url == NULL) {
    ERROR("docker: get_metrics_for_container: malloc failed.\n");
    return NULL;
  }
  // 107 = 64 (for container id) + 3 (docker version) + text
  ssnprintf(url, 107, "http:/v%s/containers/%s/stats?stream=false", version,
      container_id);
  curl_get_json(response_buffer, RESPONSE_BUFFER_SIZE, url, socket);
  container_stats_t *ptr;
  extract_stats_from_response(response_buffer, &ptr, container_id);
  sfree(response_buffer);
  sfree(url);
  return ptr;
}

//==============================================================================
//==============================================================================
//==============================================================================
// Funcitonality to dispatch Collectd Value lists with metrics.
//==============================================================================
//==============================================================================
//==============================================================================

static void dispatch_value_list(const char *hostname, const char *plugin,
  const char *plugin_instance, const char *type, const char *type_instance,
  meta_data_t *md, size_t count, value_t value, ...) {
  value_t values[count];
  value_list_t vl = VALUE_LIST_INIT;
  value_t val = value;
  va_list ap;
  va_start(ap, value);
  for (int i = 0; i < count; i++) {
    memcpy(&values[i], &val, sizeof(val));
    val = va_arg(ap, value_t);
  }
  va_end(ap);

  vl.values = values;
  vl.values_len = count;
  // Plugin name format: docker.{plugin_name}\0
  // => len(docker.) + len(name) + len(\0)
  size_t plugin_name_len = 7 + strlen(plugin) + 1;
  char *plugin_name = (char *) calloc(plugin_name_len, sizeof(char));
  if (plugin_name == NULL) {
    ERROR("docker: dispatch_value_list malloc failed!");
    return;
  }
  ssnprintf(plugin_name, plugin_name_len, "docker.%s", plugin);
  sstrncpy(vl.host, hostname, sizeof(vl.host));
  sstrncpy(vl.plugin, plugin_name, sizeof(vl.plugin));
  sstrncpy(vl.type, type, sizeof(vl.type));
  if (plugin_instance != NULL) {
    sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  }
  if (type_instance != NULL) {
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));
  }
  if (md != NULL) {
    vl.meta = md;
  }
  plugin_dispatch_values(&vl);
  sfree(plugin_name);
}

static void dispatch_container_blkio_devices(const char *path,
    c_avl_tree_t *tree, char *hostname) {
  if (tree == NULL) {
    DEBUG("docker: No data for %s for container: %s", path, hostname);
    return;
  }
  char *device;
  blkio_device_stats_t *value;
  c_avl_iterator_t *iterator = c_avl_get_iterator(tree);
  value_t values[2];
  while (
      c_avl_iterator_next(iterator, (void **) &device, (void **) &value) == 0) {
    values[0].derive = value->read;
    values[1].derive = value->write;
    dispatch_value_list(hostname, "disk", device, "disk_octets", NULL, NULL, 2,
        values[0], values[1]);
  }
  c_avl_iterator_destroy(iterator);
}

static void dispatch_container_blkio_stats(blkio_stats_t *stats,
    char *hostname) {
  c_avl_tree_t *result_ptrs[] = {
    stats->io_bytes,
  };

  assert(STATIC_ARRAY_SIZE(result_ptrs) == STATIC_ARRAY_SIZE(BLKIO_KEYS));
  for (int i = 0; i < STATIC_ARRAY_SIZE(BLKIO_KEYS); i++) {
    dispatch_container_blkio_devices(BLKIO_KEYS[i], result_ptrs[i], hostname);
  }
}

static void dispatch_container_cpu_stats(cpu_core_stats_t **stats, int num_cores,
    char *hostname) {
    value_t used;
    value_t idle;
    value_t used_percent;
    value_t idle_percent;
  for (int i = 0; i < num_cores; i++) {
    unsigned int cpu_count = i + 1;	// 1 indexed
    if (stats[i] == NULL) {
      WARNING("docker: No CPU stats for core %d for %s", cpu_count, hostname);
      continue;
    }
    // UINT_MAX = 4294967295. len(UINT_MAX) + len(\0) = 11.
    char *cpu_num = (char *) calloc (11, sizeof(char));
    if (cpu_num == NULL) {
      ERROR("docker: dispatch_container_cpu_stats malloc failed!");
    }
    ssnprintf(cpu_num, 10, "%d", cpu_count);
    used.counter = stats[i]->usage;
    idle.counter = stats[i]->idle;
    used_percent.gauge = stats[i]->percent_used;
    idle_percent.gauge = stats[i]->percent_idle;
    dispatch_value_list(hostname, "cpu", cpu_num, "cpu", "used", NULL, 1, used);
    dispatch_value_list(hostname, "cpu", cpu_num, "cpu", "idle", NULL, 1, idle);
    dispatch_value_list(hostname, "cpu", cpu_num, "percent", "used", NULL, 1,
        used_percent);
    dispatch_value_list(hostname, "cpu", cpu_num, "percent", "idle", NULL, 1,
        idle_percent);
  }
}

static void dispatch_container_memory_stats(memory_stats_t *stats,
    char *hostname) {
  if (stats == NULL) {
    WARNING("docker: No memory stats for %s", hostname);
  }
  unsigned long bytes_results[] = {
    stats->usage,
    stats->free,
  };

  unsigned long percent_results[] = {
    stats->percent_used,
    stats->percent_free,
  };

  assert(STATIC_ARRAY_SIZE(bytes_results) == STATIC_ARRAY_SIZE(percent_results));
  for (int i = 0; i < STATIC_ARRAY_SIZE(bytes_results); i++) {
    value_t bytes, percent;
    bytes.gauge = bytes_results[i];
    percent.gauge = percent_results[i];
    dispatch_value_list(hostname, "memory", NULL, "memory",
        MEMORY_METRIC_TYPES[i], NULL, 1, bytes);
    dispatch_value_list(hostname, "memory", NULL, "percent",
        MEMORY_METRIC_TYPES[i], NULL, 1, percent);
  }
}

static void dispatch_container_interface_stats(interface_stats_t *stats,
    char *hostname) {
  unsigned long rx_results[] = {
    stats->rx_bytes,
    stats->rx_packets,
    stats->rx_errors,
  };

  unsigned long tx_results[] = {
    stats->tx_bytes,
    stats->tx_packets,
    stats->tx_errors,
  };

  const char *types[] = {
    "if_octets",
    "if_packets",
    "if_errors",
  };

  assert(STATIC_ARRAY_SIZE(rx_results) == STATIC_ARRAY_SIZE(INTERFACE_KEYS));
  assert(STATIC_ARRAY_SIZE(tx_results) == STATIC_ARRAY_SIZE(INTERFACE_KEYS));
  value_t values[2];
  for (int i = 0; i < STATIC_ARRAY_SIZE(INTERFACE_KEYS); i++) {
    values[0].derive = rx_results[i];
    values[1].derive = tx_results[i];
    dispatch_value_list(hostname, "interface", stats->name, types[i], NULL, NULL,
                        2, values[0], values[1]);
  }
}

static void dispatch_container_network_stats(network_stats_t *stats,
    char *hostname) {
  if (stats == NULL) {
    WARNING("docker: No network interface stats for %s on all interfaces",
            hostname);
    return;
  }
  for (int i = 0; i < stats->count; i++) {
    if (stats->interfaces[i] != NULL) {
      dispatch_container_interface_stats(stats->interfaces[i], hostname);
    }
  }
}

static void dispatch_container_stats(const char *id, container_stats_t *stats) {
  // This plugin sets the hostname to "container.{container_id}"
  // 75 = 64 (container ID) + len(container.) + len(\0).
  char *hostname = (char *) calloc (75, sizeof(char));
  if (hostname == NULL) {
    ERROR("docker: dispatch_container_stats malloc failed!");
    return;
  }
  ssnprintf(hostname, 74, "container.%s", id);
  dispatch_container_blkio_stats(stats->blkio_stats, hostname);
  dispatch_container_cpu_stats(stats->cpu_stats->percpu_stats,
      stats->cpu_stats->num_cpus, hostname);
  dispatch_container_memory_stats(stats->memory_stats, hostname);
  dispatch_container_network_stats(stats->network_stats, hostname);
  sfree(hostname);
}

static int dispatch_stats_all(void) {
  char **container_list = NULL;
  int count = get_container_list(DOCKER_SOCKET, DOCKER_VERSION, &container_list);
  if (count == 0) {
    DEBUG("docker: No containers running on this machine.");
    free_list((void ***) &container_list, count);
    return 0;
  } else if (count == -1) {
    ERROR("docker: Unable to parse container information.");
    free_list((void ***) &container_list, count);
    return 0;
  }
  container_stats_t *stats;
  for (int i = 0; i < count; i++) {
    stats = get_stats_for_container(container_list[i], DOCKER_SOCKET,
                DOCKER_VERSION);
    if (stats != NULL) {
      dispatch_container_stats(container_list[i], stats);
      free_stats(stats);
      stats = NULL;
    } else {
      WARNING("docker: stats for resource %s are NULL", container_list[i]);
    }
  }
  free_list((void ***) &container_list, count);
  return 0;
}

//==============================================================================
//==============================================================================
//==============================================================================
// Collectd plugin load and configuration fucntionality.
//==============================================================================
//==============================================================================
//==============================================================================

static int docker_config(const char *key, const char *value) {
  if (strcmp(key, "Socket") == 0) {
    config_socket = (const char *) sstrdup(value);
    if (config_socket == NULL) {
      WARNING("docker: docker_config sstrdup failed. Using defaults.");
    }
    return 0;
  }

  if (strcmp(key, "Version") == 0) {
    config_version = (const char *) sstrdup(value);
    if (config_version == NULL) {
      WARNING("docker: docker_config sstrdup failed. Using defaults.");
    }
    return 0;
  }
  WARNING("docker: Unknown config option found. Key: %s, Value: %s", key, value);
  return -1;
}

static int docker_init(void) {
  if (DOCKER_VERSION == NULL) {
    DOCKER_VERSION = (const char *)
        (config_version != NULL ? config_version : DEFAULT_VERSION);
  }

  if (DOCKER_SOCKET == NULL) {
    DOCKER_SOCKET = (const char *)
        (config_socket != NULL ? config_socket : DEFAULT_SOCKET);
  }
  cpu_hist_values = c_avl_create((int(*)(const void *, const void *))&strcmp);
  if (cpu_hist_values == NULL) {
    ERROR("docker: c_avl_create failed.");
    return -1;
  }
  return 0;
}

static int docker_shutdown(void) {
  void *key;
  void *value;
  while (c_avl_pick(cpu_hist_values, &key, &value) == 0) {
      sfree(key);
      sfree(((cpu_state_t *) value)->old_percpu_usage);
      sfree(value);
  }
  c_avl_destroy(cpu_hist_values);
  return 0;
}

void module_register(void) {
  plugin_register_config("docker", docker_config, config_keys, config_keys_num);
  plugin_register_init("docker", docker_init);
  plugin_register_read("docker", dispatch_stats_all);
  plugin_register_shutdown("docker", docker_shutdown);
}