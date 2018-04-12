/**
 * collectd - src/eventlog.c
 * Copyright (c) 2018  Google LLC
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

#include "common.h"
#include "plugin.h"

#include "eventlogres.h"

#include <windows.h>

#if COLLECT_DEBUG
static int log_level = LOG_DEBUG;
#else
static int log_level = LOG_INFO;
#endif /* COLLECT_DEBUG */
static int notif_severity = 0;

static const char *config_keys[] = {
    "LogLevel", "NotifyLevel",
};
static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

static HANDLE event_source;
static char log_prefix[512];

int event_type_from_priority(int event_id) {
  switch (event_id) {
    case LOG_INFO:
      return EVENTLOG_INFORMATION_TYPE;
    case LOG_NOTICE:
      return EVENTLOG_INFORMATION_TYPE;
    case LOG_DEBUG:
      return EVENTLOG_INFORMATION_TYPE;
    case LOG_ERR:
      return EVENTLOG_ERROR_TYPE;
    default:
      return EVENTLOG_WARNING_TYPE;
  }
}

static void openlog(const char *ident) {
  sprintf(log_prefix, "%s[%d]", ident, getpid());
  event_source = RegisterEventSource(NULL, ident);
  if (event_source == NULL) {
    ERROR("eventlog: failed to register '%s' as an event source", ident);
  }
}

static int closelog() {
  BOOL success = DeregisterEventSource(event_source);
  if (!success) {
    ERROR("eventlog: failed to deregister 'collectd' as an event source");
	return 1;
  }
  return 0;
}

static void veventlog(int priority, const char *format, va_list args) {
  char msg[2056];
  vsprintf(msg, format, args);
  const char *messages[] = {log_prefix, msg};

  BOOL success = ReportEvent(
      event_source,
      event_type_from_priority(priority), // wType
      0,        // wCategory
      MSG_LOG,  // dwEventID
      NULL,     // lpUserSid
      2,        // wNumStrings
      0,        // dwDataSize
      messages, // lpStrings
      NULL      // lpRawData
  );
  if (!success) {
    ERROR("eventlog: failed to report event to event log");
  }
}

static void eventlog(int priority, const char *format, ...) {
  va_list args;
  va_start(args, format);
  veventlog(priority, format, args);
  va_end(args);
}

static int el_config(const char *key, const char *value) {
  if (strcasecmp(key, "LogLevel") == 0) {
    log_level = parse_log_severity(value);
    if (log_level < 0) {
      log_level = LOG_INFO;
      ERROR("eventlog: invalid loglevel [%s] defaulting to 'info'", value);
      return 1;
    }
  } else if (strcasecmp(key, "NotifyLevel") == 0) {
    notif_severity = parse_notif_severity(value);
    if (notif_severity < 0)
      return 1;
  }

  return 0;
} /* int el_config */

static void el_log(int severity, const char *msg,
                   user_data_t __attribute__((unused)) * user_data) {
  if (severity > log_level)
    return;

  eventlog(severity, "%s", msg);
} /* void el_log */

static int el_shutdown(void) {
  return closelog();
}

static int el_notification(const notification_t *n,
                           user_data_t __attribute__((unused)) * user_data) {
  char buf[1024] = "";
  size_t offset = 0;
  int log_severity;
  const char *severity_string;
  int status;

  if (n->severity > notif_severity)
    return 0;

  switch (n->severity) {
  case NOTIF_FAILURE:
    severity_string = "FAILURE";
    log_severity = LOG_ERR;
    break;
  case NOTIF_WARNING:
    severity_string = "WARNING";
    log_severity = LOG_WARNING;
    break;
  case NOTIF_OKAY:
    severity_string = "OKAY";
    log_severity = LOG_NOTICE;
    break;
  default:
    severity_string = "UNKNOWN";
    log_severity = LOG_ERR;
  }

#define BUFFER_ADD(...)                                                        \
  do {                                                                         \
    status = snprintf(&buf[offset], sizeof(buf) - offset, __VA_ARGS__);        \
    if (status < 1)                                                            \
      return -1;                                                               \
    else if (((size_t)status) >= (sizeof(buf) - offset))                       \
      return -ENOMEM;                                                          \
    else                                                                       \
      offset += ((size_t)status);                                              \
  } while (0)

#define BUFFER_ADD_FIELD(field)                                                \
  do {                                                                         \
    if (n->field[0])                                                           \
      BUFFER_ADD(", " #field " = %s", n->field);                               \
  } while (0)

  BUFFER_ADD("Notification: severity = %s", severity_string);
  BUFFER_ADD_FIELD(host);
  BUFFER_ADD_FIELD(plugin);
  BUFFER_ADD_FIELD(plugin_instance);
  BUFFER_ADD_FIELD(type);
  BUFFER_ADD_FIELD(type_instance);
  BUFFER_ADD_FIELD(message);

#undef BUFFER_ADD_FIELD
#undef BUFFER_ADD

  buf[sizeof(buf) - 1] = '\0';

  el_log(log_severity, buf, NULL);

  return 0;
} /* int el_notification */

void module_register(void) {
  openlog("collectd");

  plugin_register_config("eventlog", el_config, config_keys, config_keys_num);
  plugin_register_log("eventlog", el_log, /* user_data = */ NULL);
  plugin_register_notification("eventlog", el_notification, NULL);
  plugin_register_shutdown("eventlog", el_shutdown);
} /* void module_register(void) */