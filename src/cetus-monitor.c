/* $%BEGINLICENSE%$
   Copyright (c) 2007, 2012, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; version 2 of the
   License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
   02110-1301  USA

   $%ENDLICENSE%$ */

#include "cetus-monitor.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <fcntl.h>
#include <limits.h>
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "cetus-users.h"
#include "cetus-util.h"
#include "chassis-timings.h"
#include "chassis-event.h"
#include "glib-ext.h"

#include <netdb.h>
#include <arpa/inet.h>

#define ADDRESS_LEN 64
#define MGR_STATE_LEN 64
#define MGR_ROLE_LEN 64
#define MGR_GTID_LEN 32

struct cetus_monitor_t {
  struct chassis *chas;
  GThread *thread;
  chassis_event_loop_t *evloop;

  struct event check_config_timer;
  struct event check_alive_timer;
  GString *db_passwd;
  GHashTable *backend_conns;

  GList *registered_objects;
  char *config_id;

  unsigned int mysql_init_called : 1;
};

typedef struct gtid_interval {
  int64_t min;
  int64_t max;
} gtid_interval;

typedef struct gtid_set_t {
  int size;
  int num;
  gtid_interval *gtids;
} gtid_set_t;


static int is_equal_set(gtid_interval *set, gtid_interval *candidate_subset) {
  if (candidate_subset->min == set->min && candidate_subset->max == set->max) {
    return 1;
  } else {
    return 0;
  }
}

static int is_subset(gtid_interval *set, gtid_interval *candidate_subset) {
  if (candidate_subset->min >= set->min && candidate_subset->max <= set->max) {
    return 1;
  } else {
    return 0;
  }
}

static int combine_set(gtid_interval *set, gtid_interval *combined_set) {
  if (set->max >= combined_set->min && set->min <= combined_set->min) {
    set->max = combined_set->max;
    return 1;
  } else if (combined_set->max >= set->min && combined_set->max <= set->max) {
    set->min = combined_set->min;
    return 1;
  }
  return 0;
}

static void mysql_conn_free(gpointer e) {
  MYSQL *conn = e;
  if (conn) {
    mysql_close(conn);
  }
}


static MYSQL *
get_mysql_connection(cetus_monitor_t *monitor, char *addr) {
  MYSQL *conn = g_hash_table_lookup(monitor->backend_conns, addr);
  if (conn) {
    if (mysql_ping(conn) == 0) {
      return conn;
    } else {
      g_hash_table_remove(monitor->backend_conns, addr);
      g_debug("monitor: remove dead mysql conn of backend: %s", addr);
    }
  }

  conn = mysql_init(NULL);
  monitor->mysql_init_called = 1;
  if (!conn)
    return NULL;

  unsigned int timeout = 3 * SECONDS;
  mysql_options(conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
  mysql_options(conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
  timeout = 6 * SECONDS;
  mysql_options(conn, MYSQL_OPT_READ_TIMEOUT, &timeout);

  char **ip_port = g_strsplit(addr, ":", -1);
  int port = atoi(ip_port[1]);
  char *user = monitor->chas->default_username;
  if (mysql_real_connect(conn, ip_port[0], user, monitor->db_passwd->str, NULL,
                         port, NULL, 0) == NULL) {
    g_debug("monitor thread cannot connect to backend: %s@%s",
            monitor->chas->default_username, addr);
    mysql_conn_free(conn);
    g_strfreev(ip_port);
    return NULL;
  }
  g_hash_table_insert(monitor->backend_conns, g_strdup(addr), conn);
  g_debug("monitor thread connected to backend: %s, cached %d conns", addr,
          g_hash_table_size(monitor->backend_conns));
  g_strfreev(ip_port);
  return conn;
}

static gint
get_ip_by_name(const gchar *name, gchar *ip) {
  if (ip == NULL || name == NULL)
    return -1;
  char **pptr;
  struct hostent *hptr;
  hptr = gethostbyname(name);
  if (hptr == NULL) {
    g_debug("gethostbyname failed.");
    return -1;
  }
  for (pptr = hptr->h_addr_list; *pptr != NULL; pptr++) {
    if (inet_ntop(hptr->h_addrtype, *pptr, ip, ADDRESS_LEN)) {
      return 0;
    }
  }
  return -1;
}

typedef struct mgr_node_info {
  char address[ADDRESS_LEN];
  char state[MGR_STATE_LEN];
  char member_role[MGR_ROLE_LEN];
  unsigned int valid : 1;
  unsigned int master : 1;
  unsigned int is_recovering : 1;
} mgr_node_info;

#define GTID_GREATER 1
#define GTID_EQUAL 0
#define GTID_LESSER -1
#define GTID_UNKNOWN -2

static void free_gtid_set(gtid_set_t *gtid_set) {
  g_free(gtid_set->gtids);
  g_free(gtid_set);
}

static gtid_set_t *get_gtid_interval(const char *gtid, int previous_num) {
  int index = 0;
  int count = 0;
  char gtid_str[MGR_STATE_LEN];
  const char *p = NULL;
  const char *q = NULL;
  size_t len = strlen(gtid);

  /* find intervals */
  while (index < len) {
    if (gtid[index] == ':') {
      count++;
    }
    index++;
  }

  index = 0;
  /* skip source_id */
  while (gtid[index] != ':') {
    index++;
    if (index == len) {
      g_message("gtid is strange, gtid:%s", gtid);
      return NULL;
    }
  }

  int max_set_num = previous_num + count;
  gtid_set_t *gtid_set = g_new0(gtid_set_t, 1);
  gtid_set->num = count;
  gtid_set->size = max_set_num;

  gtid_set->gtids = g_new0(gtid_interval, gtid_set->size);
  index++;

  g_debug("get_gtid_interval, gtid:%s, num:%d, size:%d", gtid, count,
          max_set_num);
  count = 0;
  q = gtid + index;
  int64_t max = 0, min = 0;
  while (index < len && gtid[index] != '\0') {
    if (gtid[index] == ':') {
      memset(gtid_str, 0, MGR_GTID_LEN);
      p = gtid + index + 1;
      if (p > (q + 1)) {
        strncpy(gtid_str, q, p - q - 1);
        max = (int64_t)atoll(gtid_str);
        if (min == 0) {
          min = max;
        }
        gtid_set->gtids[count].max = max;
        gtid_set->gtids[count].min = min;
        count++;
        g_debug("add gtid interval, max:%lld, min:%lld", max, min);
        min = 0;
      } else {
        free_gtid_set(gtid_set);
        return NULL;
      }
      q = p;
    } else if (gtid[index] == '-') {
      memset(gtid_str, 0, MGR_GTID_LEN);
      p = gtid + index + 1;
      if (p > (q + 1)) {
        strncpy(gtid_str, q, p - q - 1);
        min = (int64_t)atoll(gtid_str);
      } else {
        free_gtid_set(gtid_set);
        return NULL;
      }
      q = p;
    } else if (gtid[index] == ',') {
      free_gtid_set(gtid_set);
      return NULL;
    }
    index++;
  }

  /* last value */
  max = (int64_t)atoll(q);
  if (min == 0) {
    min = max;
  }
  if (count < gtid_set->size) {
    gtid_set->gtids[count].max = max;
    gtid_set->gtids[count].min = min;
    g_debug("add gtid interval, max:%lld, min:%lld", max, min);

#ifdef USE_GLIB_DEBUG_LOG
    int i;
    for (i = 0; i <= count; i++) {
      g_debug("gtid interval, max:%lld, min:%lld", gtid_set->gtids[i].max,
              gtid_set->gtids[i].min);
    }
#endif

    return gtid_set;
  } else {
    g_message("unexpected count:%d, gtid size:%d, gtid:%s", count,
              gtid_set->size, gtid);
    free_gtid_set(gtid_set);
    return NULL;
  }
}

/**
 * if set1 is subset set2, then return GTID_LESSER.
 * if set1 is not subset set2 and if set2 is subset of set1 then return
 * GTID_GREATER.
 * if set1 is equals to set2, then return GTID_EQUAL
 */
static int compare_gtid_set(gtid_set_t *set1, gtid_set_t *set2) {
  int i, j;
  int count = 0;
  if (set1->num == set2->num) {
    for (i = 0; i < set1->num; i++) {
      for (j = 0; j < set2->num; j++) {
        if (is_equal_set(set1->gtids + i, set2->gtids + j)) {
          count++;
          break;
        }
      }
      if (j == set2->num) {
        break;
      }
    }
    if (count == set1->num) {
      return GTID_EQUAL;
    }
  }

  for (i = 0; i < set1->num; i++) {
    for (j = 0; j < set2->num; j++) {
      if (is_subset(set1->gtids + i, set2->gtids + j)) {
        count++;
        break;
      }
    }
    if (j == set2->num) {
      break;
    }
  }

  if (count == set2->num) {
    return GTID_GREATER;
  }

  count = 0;
  for (i = 0; i < set2->num; i++) {
    for (j = 0; j < set1->num; j++) {
      if (is_subset(set2->gtids + i, set1->gtids + j)) {
        count++;
        break;
      }
    }
    if (j == set1->num) {
      break;
    }
  }

  if (count == set1->num) {
    return GTID_LESSER;
  }

  return GTID_UNKNOWN;
}

static int group_replication_restart_secondary(const char *backend_addr,
                                               cetus_monitor_t *monitor) {
  gchar *start_mgr_sql = "start group_replication";

  MYSQL *conn = get_mysql_connection(monitor, backend_addr);
  if (conn == NULL) {
    g_debug("return, get connection failed. error: %d, text: %s, backend: %s",
            mysql_errno(conn), mysql_error(conn), backend_addr);
    return -1;
  }

  if (mysql_real_query(conn, L(start_mgr_sql))) {
    g_message(
        "in group_replication_restart_secondary, start secondary failed for "
        "group_replication. error: %d, "
        "text: %s, backend: %s",
        mysql_errno(conn), mysql_error(conn), backend_addr);
  } else {
    MYSQL_RES *rs_set = mysql_store_result(conn);
    if (rs_set == NULL) {
      if (mysql_field_count(conn) != 0) {
        g_message("start secondary result set failed for group_replication. "
                  "error: %d, text: %s, backend: %s",
                  mysql_errno(conn), mysql_error(conn), backend_addr);
      }
    } else {
      mysql_free_result(rs_set);
    }
  }

  return 0;
}

static int group_replication_restart(network_backends_t *bs,
                                     cetus_monitor_t *monitor,
                                     const char *biggest_gtid_node_addr) {
  gchar *set_mgr_primary_bootstrap_on_sql =
      "SET GLOBAL group_replication_bootstrap_group=ON";
  gchar *set_mgr_primary_bootstrap_off_sql =
      "SET GLOBAL group_replication_bootstrap_group=OFF";
  gchar *start_mgr_sql = "start group_replication";

  g_debug("Adopt bakend:%s as the primary node", biggest_gtid_node_addr);

  guint backends_num = network_backends_count(bs);
  guint i = 0;

  for (; i < backends_num; i++) {
    network_backend_t *backend = network_backends_get(bs, i);
    if (backend->state == BACKEND_STATE_MAINTAINING ||
        backend->state == BACKEND_STATE_DELETED)
      continue;
    char *backend_addr = backend->addr->name->str;
    MYSQL *conn = get_mysql_connection(monitor, backend_addr);
    if (conn == NULL) {
      g_debug("return, get connection failed. error: %d, text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
      return -1;
    }
  }

  int start_primary_error = 0;
  for (i = 0; i < backends_num; i++) {
    network_backend_t *backend = network_backends_get(bs, i);
    if (backend->state == BACKEND_STATE_MAINTAINING ||
        backend->state == BACKEND_STATE_DELETED) {
      continue;
    }

    char *backend_addr = backend->addr->name->str;
    g_debug("restart check master, biggest gtid addr:%s, "
            "backend addr:%s",
            biggest_gtid_node_addr, backend_addr);
    if (backend_addr != biggest_gtid_node_addr) {
      continue;
    }
    MYSQL *conn = get_mysql_connection(monitor, backend_addr);
    if (conn == NULL) {
      g_debug("get connection failed. error: %d, text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
      continue;
    }

    if (mysql_real_query(conn, L(set_mgr_primary_bootstrap_on_sql))) {
      g_message("set bootstrap on failed for group_replication. error: %d, "
                "text: %s, backend: %s",
                mysql_errno(conn), mysql_error(conn), backend_addr);
      continue;
    } else {
      MYSQL_RES *rs_set = mysql_store_result(conn);
      if (rs_set == NULL) {
        if (mysql_field_count(conn) != 0) {
          g_message("set bootstrap on result set failed for group_replication. "
                    "error: %d, text: %s, backend: %s",
                    mysql_errno(conn), mysql_error(conn), backend_addr);
        }
      } else {
        mysql_free_result(rs_set);
      }
    }

    if (mysql_real_query(conn, L(start_mgr_sql))) {
      start_primary_error = 1;
      g_debug("start mgr masger failed for group_replication. error: %d, "
              "text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
    } else {
      MYSQL_RES *rs_set = mysql_store_result(conn);
      if (rs_set == NULL) {
        if (mysql_field_count(conn) != 0) {
          g_message("start mgr result set failed for group_replication. "
                    "error: %d, text: %s, backend: %s",
                    mysql_errno(conn), mysql_error(conn), backend_addr);
        }
      } else {
        mysql_free_result(rs_set);
      }
    }

    if (mysql_real_query(conn, L(set_mgr_primary_bootstrap_off_sql))) {
      g_message("set bootstrap off failed for group_replication. error: %d, "
                "text: %s, backend: %s",
                mysql_errno(conn), mysql_error(conn), backend_addr);
      continue;
    } else {
      MYSQL_RES *rs_set = mysql_store_result(conn);
      if (rs_set == NULL) {
        if (mysql_field_count(conn) != 0) {
          g_message(
              "set bootstrap off result set failed for group_replication. "
              "error: %d, text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
          continue;
        }
      } else {
        mysql_free_result(rs_set);
      }
    }
  }

  if (start_primary_error) {
    return -1;
  }

  for (i = 0; i < backends_num; i++) {
    network_backend_t *backend = network_backends_get(bs, i);
    if (backend->state == BACKEND_STATE_MAINTAINING ||
        backend->state == BACKEND_STATE_DELETED) {
      continue;
    }

    char *backend_addr = backend->addr->name->str;
    if (backend_addr == biggest_gtid_node_addr) {
      continue;
    }

    g_debug("in group_replication_restart, get secondary connection for "
            "backend:%p",
            backend_addr);
    MYSQL *conn = get_mysql_connection(monitor, backend_addr);
    if (conn == NULL) {
      g_debug("get connection failed. error: %d, text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
      continue;
    }

    g_debug("in group_replication_restart, start secondary for "
            "backend:%p",
            backend_addr);
    if (mysql_real_query(conn, L(start_mgr_sql))) {
      g_debug("in group_replication_restart, start secondary failed for "
              "group_replication. error: %d, "
              "text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
    } else {
      g_debug("in group_replication_restart, after start secondary for "
              "backend:%p",
              backend_addr);
      MYSQL_RES *rs_set = mysql_store_result(conn);
      if (rs_set == NULL) {
        if (mysql_field_count(conn) != 0) {
          g_message("start secondary result set failed for group_replication. "
                    "error: %d, text: %s, backend: %s",
                    mysql_errno(conn), mysql_error(conn), backend_addr);
        }
      } else {
        mysql_free_result(rs_set);
      }
    }
    g_debug("in group_replication_restart, end start secondary for "
            "backend:%p",
            backend_addr);
  }

  return 0;
}

static gtid_set_t *group_replication_retrieve_gtid(MYSQL *conn,
                                                   const char *backend_addr) {
  gchar *relay_gtid_sql = "select RECEIVED_TRANSACTION_SET from "
                          "performance_schema.replication_connection_status";
  if (mysql_real_query(conn, L(relay_gtid_sql))) {
    g_message("retrieve relay gtid failed for group_replication. error: %d, "
              "text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
    return NULL;
  }

  MYSQL_RES *rs_set = mysql_store_result(conn);
  if (rs_set == NULL) {
    g_message("retrieve gtid result set failed for group_replication. "
              "error: %d, text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
    return NULL;
  }
  MYSQL_ROW row = mysql_fetch_row(rs_set);
  if (row == NULL) {
    mysql_free_result(rs_set);
    return NULL;
  }

  gtid_set_t *relayed_gtid_set = get_gtid_interval(row[0], 0);
  if (relayed_gtid_set == NULL) {
    g_message("relayed_gtid_set is null from backend:%s", backend_addr);
  }

  g_debug("relayed_gtid_set:%s from backend:%s", row[0], backend_addr);

  mysql_free_result(rs_set);

  gchar *gtid_sql = "show variables like 'gtid_executed'";
  if (mysql_real_query(conn, L(gtid_sql))) {
    g_message("retrieve gtid failed for group_replication. error: %d, "
              "text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
    if (relayed_gtid_set) {
      free_gtid_set(relayed_gtid_set);
    }
    return NULL;
  }

  rs_set = mysql_store_result(conn);
  if (rs_set == NULL) {
    g_message("retrieve gtid result set failed for group_replication. "
              "error: %d, text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
    if (relayed_gtid_set) {
      free_gtid_set(relayed_gtid_set);
    }
    return NULL;
  }
  row = mysql_fetch_row(rs_set);
  if (row == NULL) {
    if (relayed_gtid_set) {
      free_gtid_set(relayed_gtid_set);
    }
    mysql_free_result(rs_set);
    return NULL;
  }

  gtid_set_t *executed_gtid_set =
      get_gtid_interval(row[1], relayed_gtid_set->num);
  if (executed_gtid_set == NULL) {
    g_critical("executed_gtid_set is null from backend:%s", backend_addr);
  }

  g_debug("executed_gtid_set:%s from backend:%s", row[1], backend_addr);
  mysql_free_result(rs_set);

  if (relayed_gtid_set && executed_gtid_set) {
    int i, j;
    for (i = 0; i < relayed_gtid_set->num; i++) {
      for (j = 0; j < executed_gtid_set->num; j++) {
        if (is_subset(executed_gtid_set->gtids + j,
                      relayed_gtid_set->gtids + i)) {
          break;
        }
      }
      /* relayed gtid is not subset of executed_gtids */
      if (j == executed_gtid_set->num) {
        for (j = 0; j < executed_gtid_set->num; j++) {
          if (combine_set(executed_gtid_set->gtids + j,
                          relayed_gtid_set->gtids + i)) {
            break;
          }
        }
      }

      if (j == executed_gtid_set->num) {
        executed_gtid_set->gtids[executed_gtid_set->num].min =
            relayed_gtid_set->gtids[j].min;
        executed_gtid_set->gtids[executed_gtid_set->num].max =
            relayed_gtid_set->gtids[j].max;
        executed_gtid_set->num++;
        if (executed_gtid_set->num >= executed_gtid_set->size) {
          free_gtid_set(executed_gtid_set);
          free_gtid_set(relayed_gtid_set);
          g_critical("unexpected here, set num:%d", executed_gtid_set->num);
          return NULL;
        }
      }
    }

    free_gtid_set(relayed_gtid_set);
  }

#ifdef USE_GLIB_DEBUG_LOG
  if (executed_gtid_set) {
    for (int i = 0; i < executed_gtid_set->num; i++) {
      g_debug("gtid from backend:%s, interval:%d, min:%lld, max:%lld",
              backend_addr, i + 1, executed_gtid_set->gtids[i].min,
              executed_gtid_set->gtids[i].max);
    }
  }
#endif

  return executed_gtid_set;
}

static int group_replication_detect_offline(const char *backend_addr,
                                            cetus_monitor_t *monitor,
                                            const gchar *sql) {
  g_debug("group_replication_detect_offline is called for %s", backend_addr);
  int result = 0;
  MYSQL *conn = get_mysql_connection(monitor, backend_addr);
  if (conn == NULL) {
    g_debug("get connection failed. error: %d, text: %s, backend: %s",
            mysql_errno(conn), mysql_error(conn), backend_addr);
    return result;
  }

  if (mysql_real_query(conn, L(sql))) {
    g_message("select node info failed for group_replication. error: %d, "
              "text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
    return result;
  }

  MYSQL_RES *rs_set = mysql_store_result(conn);
  if (rs_set == NULL) {
    g_message("get node info result set failed for group_replication. "
              "error: %d, text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
    return result;
  }

  MYSQL_ROW row = mysql_fetch_row(rs_set);
  if (row != NULL) {
    if (strcasecmp(row[0], "OFFLINE") == 0) {
      result = 1;
    }
  }

  mysql_free_result(rs_set);

  return result;
}

static int is_could_start_mgr_now(cetus_monitor_t *monitor, int agggressive) {
  int workers = monitor->chas->worker_processes;
  int max_num = workers * 3;
  if (!agggressive) {
    max_num = max_num << 2;
  }
  int x = g_random_int_range(0, max_num);
  if (x == 0) {
    g_message("g_random_int_range num:%d", x);
    return 1;
  } else {
    return 0;
  }
}

static void group_replication_detect(network_backends_t *bs,
                                     cetus_monitor_t *monitor) {
  if (bs == NULL) {
    return;
  }

  mgr_node_info mgr_node[MAX_SERVER_NUM];
  unsigned char offline[MAX_SERVER_NUM];
  guint master_cnt = 0;
  guint i = 0;
  guint backends_num = 0;
  int has_valid_mgr_partition = 0;
  int valid_mgr_node_num = 0;
  int write_num = 0;


  g_debug("group_replication_detect is called");
  gchar *sql = "SELECT `MEMBER_STATE`, `MEMBER_HOST`, `MEMBER_PORT`, "
               "`MEMBER_ROLE` FROM "
               "performance_schema.replication_group_members";

  gtid_set_t *max_gtid_set = NULL;
  const char *biggest_gtid_node_addr = NULL;
  memset(offline, 0, MAX_SERVER_NUM);

  backends_num = network_backends_count(bs);
  for (i = 0; i < backends_num; i++) {
    network_backend_t *backend = network_backends_get(bs, i);
    if (backend->state == BACKEND_STATE_MAINTAINING ||
        backend->state == BACKEND_STATE_DELETED) {
      continue;
    }

    memset(mgr_node, 0, sizeof(mgr_node_info) * MAX_SERVER_NUM);
    char *backend_addr = backend->addr->name->str;
    MYSQL *conn = get_mysql_connection(monitor, backend_addr);
    if (conn == NULL) {
      g_debug("get connection failed. error: %d, text: %s, backend: %s",
              mysql_errno(conn), mysql_error(conn), backend_addr);
      continue;
    }

    if (mysql_real_query(conn, L(sql))) {
      g_message("select node info failed for group_replication. error: %d, "
                "text: %s, backend: %s",
                mysql_errno(conn), mysql_error(conn), backend_addr);
      continue;
    }

    MYSQL_RES *rs_set = mysql_store_result(conn);
    if (rs_set == NULL) {
      g_message("get node info result set failed for group_replication. "
                "error: %d, text: %s, backend: %s",
                mysql_errno(conn), mysql_error(conn), backend_addr);
      continue;
    }

    int valid_node = 0;
    int index = 0;
    int need_retrieve_gtid = 0;
    /* Check all node info is valid */
    do {
      MYSQL_ROW row = mysql_fetch_row(rs_set);
      if (row == NULL) {
        break;
      }
      g_debug("group_replication_detect backend:%s, state:%s", backend_addr,
              row[0]);
      if (strcasecmp(row[0], "OFFLINE") == 0) {
        offline[i] = 1;
        /* Retrieve most updated gtid for selecting master */
        need_retrieve_gtid = 1;
        break;
      }

      snprintf(mgr_node[index].state, MGR_STATE_LEN, "%s", row[0]);
      gchar ip[ADDRESS_LEN] = {""};
      if ((get_ip_by_name(row[1], ip) == -1)) {
        g_message(
            "get node ip by name failed. error: %d, text: %s, backend: %s",
            mysql_errno(conn), mysql_error(conn), backend_addr);
        break;
      }

      snprintf(mgr_node[index].address, ADDRESS_LEN, "%s:%s", ip, row[2]);
      snprintf(mgr_node[index].member_role, MGR_ROLE_LEN, "%s", row[3]);

      if (strcasecmp("ONLINE", mgr_node[index].state) == 0 ||
          strcasecmp("RECOVERING", mgr_node[index].state) == 0) {
        if (strcasecmp("RECOVERING", mgr_node[index].state) == 0) {
          mgr_node[index].is_recovering = 1;
        }
        valid_node++;
        if (strcasecmp("ARBITRATOR", mgr_node[index].member_role) != 0) {
          mgr_node[index].valid = 1;
          if (strcasecmp("PRIMARY", mgr_node[index].member_role) == 0) {
            mgr_node[index].master = 1;
            write_num++;
          }
        } else {
          g_debug("monitor: backend_addr:%s is arbitrator",
                  mgr_node[index].address);
          mgr_node[index].valid = 0;
        }
      }

      index++;
    } while (1);

    mysql_free_result(rs_set);

    if (need_retrieve_gtid) {
      g_debug("before group_replication_retrieve_gtid,biggest gtid addr:%p,"
              "backend_addr:%p",
              biggest_gtid_node_addr, backend_addr);
      gtid_set_t *gtid_set =
          group_replication_retrieve_gtid(conn, backend_addr);
      if (gtid_set == NULL) {
        continue;
      }
      if (max_gtid_set == NULL) {
        max_gtid_set = gtid_set;
        biggest_gtid_node_addr = backend_addr;
      } else {
        /* compare gtid set */
        int compared_value = compare_gtid_set(gtid_set, max_gtid_set);
        g_debug(
            "compare_gtid_set result:%d, current backend:%s, last candidate "
            "primary:%s",
            compared_value, backend_addr, biggest_gtid_node_addr);

        if (compared_value == GTID_GREATER) {
          free_gtid_set(max_gtid_set);
          max_gtid_set = gtid_set;
          biggest_gtid_node_addr = backend_addr;
        } else if (compared_value == GTID_EQUAL) {
          if (backend->type == BACKEND_TYPE_RW) {
            biggest_gtid_node_addr = backend_addr;
          }
          free_gtid_set(gtid_set);
        } else if (compared_value == GTID_LESSER) {
          free_gtid_set(gtid_set);
        } else {
          free_gtid_set(gtid_set);
          free_gtid_set(max_gtid_set);
          g_critical("gtid in mgr cluster is not compatible");
          return;
        }
      }
    }

    if (valid_node > index / 2) {
      has_valid_mgr_partition = 1;
      valid_mgr_node_num = index;
      biggest_gtid_node_addr = NULL;
      break;
    }
  }

  if (max_gtid_set) {
    free_gtid_set(max_gtid_set);
  }

  if (write_num > 1) {
    monitor->chas->multi_write = 1;
    g_debug("group_replication detect mgr group multi-write");
  } else {
    monitor->chas->multi_write = 0;
  }

  g_debug("group_replication check biggest_gtid_node_addr");
  if (biggest_gtid_node_addr) {
    g_debug(
        "group_replication_restart now for all, biggest gtid addr:%s for bs:%p",
        biggest_gtid_node_addr, bs);
    if (is_could_start_mgr_now(monitor, 1)) {
      if (group_replication_restart(bs, monitor, biggest_gtid_node_addr) ==
          -1) {
        g_debug("group_replication_restart failed, return");
        return;
      }
    }
    g_debug("after group_replication_restart for bs:%p", bs);
  }

  if (has_valid_mgr_partition) {
    g_debug("group_replication has valid partition");
    /* Send start mgr to secondary for offline node */
    for (i = 0; i < backends_num; i++) {
      network_backend_t *backend = network_backends_get(bs, i);
      char *backend_addr = backend->addr->name->str;
      guint j = 0;
      for (; j < valid_mgr_node_num; j++) {
        if (strcasecmp(mgr_node[j].address, backend_addr) == 0) {
          break;
        }
      }
      if (j == valid_mgr_node_num) {
        if (!offline[i]) {
          /* Check if the node is offline */
          if (group_replication_detect_offline(backend_addr, monitor, sql)) {
            offline[i] = 1;
          }
        }
      }

      if (offline[i]) {
        g_debug("group_replication_restart secondary now for %s", backend_addr);
        if (is_could_start_mgr_now(monitor, 0)) {
          if (group_replication_restart_secondary(backend_addr, monitor) ==
              -1) {
            continue;
          }
        }
      }
    }

    g_debug("group_replication process master now");
    /* Process primary here */
    for (i = 0; i < backends_num; i++) {
      network_backend_t *backend = network_backends_get(bs, i);

      backend->already_processed = 0;
      char *backend_addr = backend->addr->name->str;

      if (backend->type == BACKEND_TYPE_RW) {
        g_debug("group_replication process master now for %s", backend_addr);
        mgr_node_info *node = NULL;
        guint j = 0;
        for (; j < valid_mgr_node_num; j++) {
          if (strcasecmp(mgr_node[j].address, backend_addr) == 0) {
            node = &mgr_node[j];
            break;
          }
        }
        if (node != NULL && node->master) {
          if (backend->state == BACKEND_STATE_OFFLINE ||
              backend->state == BACKEND_STATE_UNKNOWN) {
            network_backends_modify(bs, i, BACKEND_TYPE_RW, BACKEND_STATE_UP,
                                    NO_PREVIOUS_STATE);
            master_cnt++;
          } else {
            g_debug("check here for multi_write");
            if (monitor->chas->multi_write) {
              if (backend->candidate_down) {
                g_debug("set offline for master:%s", backend_addr);
                network_backends_modify(bs, i, BACKEND_TYPE_RO,
                                        BACKEND_STATE_OFFLINE,
                                        NO_PREVIOUS_STATE);
              } else {
                g_debug("set up for master:%s", backend_addr);
                network_backends_modify(bs, i, BACKEND_TYPE_RW,
                                        BACKEND_STATE_UP, NO_PREVIOUS_STATE);
                master_cnt++;
              }
            } else {
              master_cnt++;
            }
          }
          backend->already_processed = 1;
          break;
        }
        if (node) {
          if (backend->state == BACKEND_STATE_OFFLINE ||
              backend->state == BACKEND_STATE_UNKNOWN) {
            if (node->valid) {
              if (!node->is_recovering) {
                network_backends_modify(bs, i, BACKEND_TYPE_RO,
                                        BACKEND_STATE_UP, NO_PREVIOUS_STATE);
              }
            }
          } else {
            if (node->valid) {
              network_backends_modify(bs, i, BACKEND_TYPE_RO, backend->state,
                                      NO_PREVIOUS_STATE);
            } else {
              network_backends_modify(bs, i, BACKEND_TYPE_RO,
                                      BACKEND_STATE_OFFLINE, NO_PREVIOUS_STATE);
            }
          }
        } else {
          if (backend->state != BACKEND_STATE_MAINTAINING &&
              backend->state != BACKEND_STATE_DELETED) {
            network_backends_modify(bs, i, BACKEND_TYPE_RO,
                                    BACKEND_STATE_OFFLINE, NO_PREVIOUS_STATE);
            g_debug("process master, set offline for node:%s", backend_addr);
          }
        }
        backend->already_processed = 1;
        break;
      }
    }

    /* Process secondary here */
    for (i = 0; i < backends_num; i++) {
      network_backend_t *backend = network_backends_get(bs, i);

      if (backend->already_processed) {
        backend->already_processed = 0;
        continue;
      }
      char *backend_addr = backend->addr->name->str;

      if (backend->type == BACKEND_TYPE_RO ||
          backend->type == BACKEND_TYPE_UNKNOWN) {
        mgr_node_info *node = NULL;
        guint j = 0;
        g_debug("valid mgr node num:%d, backend:%s", valid_mgr_node_num,
                backend_addr);
        for (; j < valid_mgr_node_num; j++) {
          if (strcasecmp(mgr_node[j].address, backend_addr) == 0) {
            node = &mgr_node[j];
            break;
          }
        }
        if (node == NULL || (!node->valid)) {
          if (backend->state != BACKEND_STATE_MAINTAINING &&
              backend->state != BACKEND_STATE_DELETED) {
            network_backends_modify(bs, i, BACKEND_TYPE_RO,
                                    BACKEND_STATE_OFFLINE, NO_PREVIOUS_STATE);
            g_debug("set offline for node:%s", backend_addr);
          }
          continue;
        }
        if (master_cnt) {
          if (backend->state == BACKEND_STATE_OFFLINE ||
              backend->state == BACKEND_STATE_UNKNOWN) {

            if (!node->is_recovering) {
              network_backends_modify(bs, i, BACKEND_TYPE_RO, BACKEND_STATE_UP,
                                      NO_PREVIOUS_STATE);
            }
          } else {
            network_backends_modify(bs, i, BACKEND_TYPE_RO, backend->state,
                                    NO_PREVIOUS_STATE);
          }
        } else {
          if (node->master) {
            if (backend->state == BACKEND_STATE_OFFLINE ||
                backend->state == BACKEND_STATE_UNKNOWN) {
              network_backends_modify(bs, i, BACKEND_TYPE_RW, BACKEND_STATE_UP,
                                      NO_PREVIOUS_STATE);
            } else {
              network_backends_modify(bs, i, BACKEND_TYPE_RW, backend->state,
                                      NO_PREVIOUS_STATE);
            }
            master_cnt++;
          }
        }
      }
    }
  } else {
    g_critical("group_replication_detect set all nodes offline");
    for (i = 0; i < backends_num; i++) {
      network_backend_t *backend = network_backends_get(bs, i);
      char *backend_addr = backend->addr->name->str;
      if (backend->state != BACKEND_STATE_MAINTAINING &&
          backend->state != BACKEND_STATE_DELETED) {
        if (backend->type == BACKEND_TYPE_RO ||
            backend->connected_clients == 0) {
          network_backends_modify(bs, i, BACKEND_TYPE_RO, BACKEND_STATE_OFFLINE,
                                  NO_PREVIOUS_STATE);
          g_message("set offline for node:%s", backend_addr);
        }
      }
    }
  }
  g_debug("group_replication_detect is called over");
}

#define ADD_MONITOR_TIMER(ev_struct, ev_cb, timeout)                           \
  ev_now_update((struct ev_loop *)monitor->evloop);                            \
  evtimer_set(&(monitor->ev_struct), ev_cb, monitor);                          \
  event_base_set(monitor->evloop, &(monitor->ev_struct));                      \
  evtimer_add(&(monitor->ev_struct), &timeout);

gint check_hostname(network_backend_t *backend) {
  gint ret = 0;
  if (!backend)
    return ret;

  gchar old_addr[INET_ADDRSTRLEN] = {""};
  inet_ntop(AF_INET, &(backend->addr->addr.ipv4.sin_addr), old_addr,
            sizeof(old_addr));
  if (0 != network_address_set_address(backend->addr, backend->address->str)) {
    return ret;
  }
  char new_addr[INET_ADDRSTRLEN] = {""};
  inet_ntop(AF_INET, &(backend->addr->addr.ipv4.sin_addr), new_addr,
            sizeof(new_addr));
  if (strcmp(old_addr, new_addr) != 0) {
    ret = 1;
  }
  return ret;
}

static void check_backend_alive(int fd, short what, void *arg) {
  cetus_monitor_t *monitor = arg;
  chassis *chas = monitor->chas;
  network_backends_t *bs = chas->priv->backends;

  if (chas->group_replication_mode == 1) {
    group_replication_detect(bs, monitor);
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    ADD_MONITOR_TIMER(check_alive_timer, check_backend_alive, timeout);
  }
}

static void *cetus_monitor_mainloop(void *data) {
  cetus_monitor_t *monitor = data;

  chassis_event_loop_t *loop = chassis_event_loop_new();
  monitor->evloop = loop;

  chassis *chas = monitor->chas;
  monitor->config_id = chassis_config_get_id(chas->config_manager);
  if (!chas->default_username) {
    g_warning("default-username not set, monitor will not work");
    return NULL;
  }

  cetus_users_get_server_pwd(chas->priv->users, chas->default_username,
                             monitor->db_passwd);
  if (monitor->db_passwd->len == 0) { /* TODO: retry */
    g_warning("no password for %s, monitor will not work",
              chas->default_username);
    return NULL;
  }
  monitor->backend_conns =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, mysql_conn_free);

  struct timeval timeout;
  timeout.tv_sec = 1;
  timeout.tv_usec = 0;
  ADD_MONITOR_TIMER(check_alive_timer, check_backend_alive, timeout);

  chassis_event_loop(loop, NULL);

  g_debug("monitor thread closing %d mysql conns",
          g_hash_table_size(monitor->backend_conns));
  g_hash_table_destroy(monitor->backend_conns);

  if (monitor->mysql_init_called) {
    mysql_thread_end();
    g_debug("%s:mysql_thread_end is called", G_STRLOC);
  }

  g_debug("exiting monitor loop");
  chassis_event_loop_free(loop);
  return NULL;
}

void cetus_monitor_start_thread(cetus_monitor_t *monitor, chassis *chas) {
  monitor->chas = chas;
  if (chas->disable_threads) {
    g_debug("monitor thread is disabled");
    return;
  }

  g_assert(monitor->thread == 0);

  GThread *new_thread = NULL;
#if !GLIB_CHECK_VERSION(2, 32, 0)
  GError *error = NULL;
  new_thread = g_thread_create(cetus_monitor_mainloop, monitor, TRUE, &error);
  if (new_thread == NULL && error != NULL) {
    g_critical("Create thread error: %s", error->message);
    g_clear_error(&error);
  }
#else
  new_thread = g_thread_new("monitor-thread", cetus_monitor_mainloop, monitor);
  if (new_thread == NULL) {
    g_critical("Create thread error.");
  }
#endif

  monitor->thread = new_thread;
  g_debug("monitor thread started");
}

void cetus_monitor_stop_thread(cetus_monitor_t *monitor) {
  if (monitor->thread) {
    g_debug("Waiting for monitor thread to quit ...");
    g_thread_join(monitor->thread);
    g_debug("Monitor thread stopped");
  }
}

cetus_monitor_t *cetus_monitor_new() {
  cetus_monitor_t *monitor = g_new0(cetus_monitor_t, 1);

  monitor->db_passwd = g_string_new(0);
  return monitor;
}

void cetus_monitor_free(cetus_monitor_t *monitor) {
  /* backend_conns should be freed in its own thread, not here */
  g_string_free(monitor->db_passwd, TRUE);
  g_list_free_full(monitor->registered_objects, g_free);
  if (monitor->config_id)
    g_free(monitor->config_id);
  g_free(monitor);
}

