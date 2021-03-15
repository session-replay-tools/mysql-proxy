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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <errno.h>

#include <glib.h>

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif

#include <mysqld_error.h> /** for ER_UNKNOWN_ERROR */

#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-mysqld-packet.h"

#include "network-conn-pool.h"
#include "network-conn-pool-wrap.h"

#include "sys-pedantic.h"
#include "network-injection.h"
#include "network-backend.h"
#include "sql-context.h"
#include "sql-filter-variables.h"
#include "glib-ext.h"
#include "chassis-timings.h"
#include "chassis-event.h"
#include "character-set.h"
#include "cetus-util.h"
#include "cetus-users.h"
#include "chassis-options.h"
#include "plugin-common.h"
#include "network-ssl.h"
#include "chassis-sql-log.h"
#include "cetus-acl.h"

#define MAX_CACHED_ITEMS 65536

extern int      cetus_last_process;

/* judge if client_ip_with_username is in allow or deny ip_table*/
static gboolean client_ip_table_lookup(GHashTable *ip_table,
                                       char *client_ip_with_username) {
  char ip_range[128] = {0};
  char wildcard[128] = {0};
  char client_user[128] = {0};
  char client_ip[128] = {0};
  sscanf(client_ip_with_username, "%64[a-zA-Z]@%64[0-9.]", client_user,
         client_ip);
  GList *ip_range_table = g_hash_table_get_keys(ip_table);
  GList *l;
  for (l = ip_range_table; l; l = l->next) {
    char address[128] = {0};
    sscanf(l->data, "%64[a-zA-Z@0-9.]", address);
    gchar *pos = NULL;
    if (strrchr(address, '@') == NULL) {
      sscanf(address, "%64[0-9.].%s", ip_range, wildcard);
      if ((pos = strcasestr(client_ip, ip_range))) {
        if (pos == client_ip) {
          return TRUE;
        }
      }
    } else {
      sscanf(address, "%64[a-zA-Z@0-9.].%s", ip_range, wildcard);
      if ((pos = strcasestr(client_ip_with_username, ip_range))) {
        if (pos == client_ip_with_username) {
          return TRUE;
        }
      }
    }
  }
  return FALSE;
}

network_socket_retval_t do_read_auth(network_mysqld_con *con) {
  /* read auth from client */
  network_packet packet;
  network_socket *recv_sock;
  network_mysqld_auth_response *auth;

  recv_sock = con->client;

  packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
  packet.offset = 0;
  network_mysqld_proto_skip_network_header(&packet);

  /* assume that we may get called twice:
   *
   * 1. for the initial packet
   * 2. in case auth switch happened, for the auth switch response
   *
   * this is detected by con->client->response being NULL
   */

  if (con->client->response == NULL) {

    if (con->client->challenge == NULL) {
      log_sql_connect(con, "client's challenge is NULL");
      return NETWORK_SOCKET_ERROR;
    }

    guint32 capabilities = con->client->challenge->capabilities;
    auth = network_mysqld_auth_response_new(capabilities);

    int err = network_mysqld_proto_get_auth_response(&packet, auth);
    if (err) {
      network_mysqld_auth_response_free(auth);
      log_sql_connect(con, "get auth response failed");
      return NETWORK_SOCKET_ERROR;
    }

#ifdef HAVE_OPENSSL
    if (con->srv->ssl && auth->ssl_request) {
      if (network_ssl_create_connection(recv_sock, NETWORK_SSL_SERVER) ==
          FALSE) {
        network_mysqld_con_send_error_full(con->client, C("SSL server failed"),
                                           1045, "28000");
        network_mysqld_auth_response_free(auth);
        return NETWORK_SOCKET_ERROR;
      } else {
        g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
        if (recv_sock->recv_queue->chunks->length > 0) {
          g_warning("%s: client-recv-queue-len = %d", G_STRLOC,
                    recv_sock->recv_queue->chunks->length);
        }
        con->state = ST_FRONT_SSL_HANDSHAKE;
        return NETWORK_SOCKET_SUCCESS;
      }
    }
#endif
    if (!(auth->client_capabilities & CLIENT_PROTOCOL_41)) {
      /* should use packet-id 0 */
      network_mysqld_queue_append(con->client, con->client->send_queue,
                                  C("\xff\xd7\x07"
                                    "4.0 protocol is not supported"));
      network_mysqld_auth_response_free(auth);
      log_sql_connect(con, "4.0 protocol is not supported");
      return NETWORK_SOCKET_ERROR;
    }

    if (auth->client_capabilities & CLIENT_COMPRESS) {
      con->is_client_compressed = 1;
      g_message("%s: client compressed for con:%p", G_STRLOC, con);
    }
    if (auth->client_capabilities & CLIENT_MULTI_STATEMENTS) {
      con->client->is_multi_stmt_set = 1;
    }

    con->client->response = auth;
    g_string_assign_len(con->client->default_db, S(auth->database));

    if ((auth->client_capabilities & CLIENT_PLUGIN_AUTH) &&
        (g_strcmp0(auth->auth_plugin_name->str, "mysql_native_password") !=
         0)) {
      GString *packet = g_string_new(0);
      network_mysqld_proto_append_auth_switch(
          packet, "mysql_native_password",
          con->client->challenge->auth_plugin_data);
      network_mysqld_queue_append(con->client, con->client->send_queue,
                                  S(packet));
      con->state = ST_SEND_AUTH_RESULT;
      con->auth_result_state = AUTH_SWITCH;
      g_string_free(packet, TRUE);
      g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
      return NETWORK_SOCKET_SUCCESS;
    }

    g_debug("%s:1nd round auth and set default db:%s for con:%p", G_STRLOC,
            con->client->default_db->str, con);

  } else {
    /* auth switch response */
    gsize auth_data_len = packet.data->len - NET_HEADER_SIZE;
    GString *auth_data = g_string_sized_new(calculate_alloc_len(auth_data_len));
    network_mysqld_proto_get_gstr_len(&packet, auth_data_len, auth_data);

    g_string_assign_len(con->client->response->auth_plugin_data, S(auth_data));

    g_string_free(auth_data, TRUE);

    auth = con->client->response;
    g_debug("sock:%p, 2nd round auth", con);
  }

  char **client_addr_arr = g_strsplit(con->client->src->name->str, ":", -1);
  char *client_ip = client_addr_arr[0];
  char *client_username = con->client->response->username->str;

  gboolean can_pass =
      cetus_acl_verify(con->srv->priv->acl, client_username, client_ip);
  if (!can_pass) {
    char *ip_err_msg = g_strdup_printf("Access denied for user '%s@%s'",
                                       client_username, client_ip);
    network_mysqld_con_send_error_full(recv_sock, L(ip_err_msg), 1045, "28000");
    log_sql_connect(con, ip_err_msg);
    g_free(ip_err_msg);
    g_strfreev(client_addr_arr);
    con->state = ST_SEND_ERROR;
    return NETWORK_SOCKET_SUCCESS;
  }

  g_strfreev(client_addr_arr);

  const char *client_charset = charset_get_name(auth->charset);
  if (client_charset == NULL) {
    g_message("%s: client charset is nil, orig charset num:%d", G_STRLOC,
              auth->charset);
    char *err_msg = g_strdup_printf("client charset is not supported");
    network_mysqld_con_send_error_full(recv_sock, L(err_msg), 1045, "28000");
    log_sql_connect(con, err_msg);
    g_free(err_msg);
    con->state = ST_SEND_ERROR;
    return NETWORK_SOCKET_SUCCESS;
  }

  recv_sock->charset_code = auth->charset;
  g_string_assign(recv_sock->charset, client_charset);
  g_string_assign(recv_sock->charset_client, client_charset);
  g_string_assign(recv_sock->charset_results, client_charset);
  g_string_assign(recv_sock->charset_connection, client_charset);

  cetus_users_t *users = con->srv->priv->users;
  network_mysqld_auth_challenge *challenge = con->client->challenge;
  network_mysqld_auth_response *response = con->client->response;
  if (cetus_users_authenticate_client(users, challenge, response)) {
    con->state = ST_SEND_AUTH_RESULT;
    network_mysqld_con_send_ok(recv_sock);
    log_sql_connect(con, NULL);
  } else {
    char msg[256] = {0};
    snprintf(msg, sizeof(msg),
             "Access denied for user '%s'@'%s' (using password: YES)",
             response->username->str, con->client->src->name->str);
    network_mysqld_con_send_error_full(con->client, L(msg),
                                       ER_ACCESS_DENIED_ERROR, "28000");
    g_message("%s", msg);
    log_sql_connect(con, msg);
    con->state = ST_SEND_ERROR;
  }

  g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);
  if (recv_sock->recv_queue->chunks->length > 0) {
    g_warning("%s: client-recv-queue-len = %d", G_STRLOC,
              recv_sock->recv_queue->chunks->length);
  }
  return NETWORK_SOCKET_SUCCESS;
}

static int proxy_c_connect_server(network_mysqld_con *con,
                                  network_backend_t **p_backend,
                                  int *p_backend_ndx) {
  int i, num;
  network_backends_t *bs = con->srv->priv->backends;
  num = bs->backends->len;

  for (i = 0; i < num; i++) {
    network_backend_t *backend = g_ptr_array_index(bs->backends, i);

    if (backend->state != BACKEND_STATE_UP &&
        backend->state != BACKEND_STATE_UNKNOWN) {
      continue;
    }

    if (backend->config == NULL) {
      g_warning("%s, config is null for back ndx:%d", G_STRLOC, i);
      continue;
    }

    int total = network_backend_conns_count(backend);
    int connected_clts = backend->connected_clients;
    int cur_idle = total - connected_clts;
    int max_idle_conns = backend->config->max_conn_pool;

    g_debug("%s, ndx:%d, total:%d, connected:%d, idle:%d, max:%d", G_STRLOC, i,
            total, connected_clts, cur_idle, max_idle_conns);

    if (cur_idle > 0 || total <= max_idle_conns) {
      *p_backend_ndx = i;
      *p_backend = backend;
      break;
    }
  }

  if (i == num) {
    g_message("%s, service unavailable for con:%p, back ndx:%d", G_STRLOC, con,
              *p_backend_ndx);
    /* no backend server */
    network_mysqld_con_send_error(con->client,
                                  C("(proxy) service unavailable"));
    return PROXY_SEND_RESULT;
  }

  return PROXY_IGNORE_RESULT;
}

network_socket_retval_t do_connect_cetus(network_mysqld_con *con,
                                         network_backend_t **backend,
                                         int *backend_ndx) {
  chassis_private *g = con->srv->priv;
  guint i;
  network_backend_t *cur;

  *backend = NULL;
  *backend_ndx = -1;

  /* Disable backend check
   * Conflict to backend state active check.
   */
  guint disable_threads = con->srv->disable_threads;
  if (disable_threads) {
    network_backends_check(g->backends);
  }

  network_mysqld_stmt_ret ret;
  ret = proxy_c_connect_server(con, backend, backend_ndx);

  switch (ret) {
  case PROXY_SEND_RESULT:
    /* we answered directly ... like denial ...
     *
     * for sure we have something in the send-queue
     *
     */

    return NETWORK_SOCKET_SUCCESS;
  case PROXY_NO_DECISION:
    /* just go on */

    break;
  case PROXY_IGNORE_RESULT:
    break;
  default:
    g_error("%s: ... ", G_STRLOC);
    break;
  }

  /* protect the typecast below */
  g_assert_cmpint(g->backends->backends->len, <, G_MAXINT);

  /**
   * if the current backend is down, ignore it
   */
  cur = network_backends_get(g->backends, *backend_ndx);

  if (cur) {
    if (cur->state == BACKEND_STATE_DOWN ||
        cur->state == BACKEND_STATE_MAINTAINING) {
      *backend_ndx = -1;
    }
  }

  if (*backend_ndx < 0) {
    /**
     * we can choose between different back addresses
     *
     * prefer SQF (shorted queue first) to load all backends equally
     */

    int min_connected_clients = 0x7FFFFFFF;
    int backends_count = network_backends_count(g->backends);
    for (i = 0; i < backends_count; i++) {
      cur = network_backends_get(g->backends, i);

      /**
       * skip backends which are down or not writable
       */
      if (cur->state == BACKEND_STATE_DOWN ||
          cur->state == BACKEND_STATE_MAINTAINING ||
          cur->type != BACKEND_TYPE_RW)
        continue;

      if (cur->connected_clients < min_connected_clients) {
        *backend_ndx = i;
        min_connected_clients = cur->connected_clients;
      }
    }

    if ((cur = network_backends_get(g->backends, *backend_ndx))) {
      *backend = cur;
    }
  } else if (*backend == NULL) {
    if ((cur = network_backends_get(g->backends, *backend_ndx))) {
      *backend = cur;
    }
  }

  if (*backend == NULL) {
    network_mysqld_con_send_error(con->client,
                                  C("(proxy) all backends are down"));
    con->state = ST_SEND_AUTH_RESULT;
    g_critical("%s: Cannot connect, all backends are down.", G_STRLOC);
    return NETWORK_SOCKET_SUCCESS;
  }

  /* create a "mysql_native_password" handshake packet */
  network_mysqld_auth_challenge *challenge =
      network_mysqld_auth_challenge_new();
#ifdef HAVE_OPENSSL
  if (con->srv->ssl)
    challenge->capabilities |= CLIENT_SSL;
  else
    challenge->capabilities &= ~CLIENT_SSL;
#endif

  if (con->srv->compress_support) {
    challenge->capabilities |= CLIENT_COMPRESS;
  }

  network_mysqld_auth_challenge_set_challenge(challenge);
  challenge->server_status |= SERVER_STATUS_AUTOCOMMIT;
  challenge->charset = charset_get_number(con->srv->default_charset);
  GString *version = g_string_new("");
  network_backends_server_version(g->backends, version);
  challenge->server_version_str = version->str;
  g_string_free(version, FALSE);
  challenge->thread_id = g->thread_id++;
  g_debug("%s: generate thread id:%d", G_STRLOC, challenge->thread_id);

  if (g->thread_id > g->max_thread_id) {
    g->thread_id = 1 + (cetus_last_process << 24);
    g_message("%s: rewind first thread id:%d", G_STRLOC, g->thread_id);
  }

  GString *auth_packet = g_string_new(NULL);
  network_mysqld_proto_append_auth_challenge(auth_packet, challenge);

  network_mysqld_queue_append(con->client, con->client->send_queue,
                              S(auth_packet));

  g_string_free(auth_packet, TRUE);

  g_assert(con->client->challenge == NULL);

  con->client->challenge = challenge;

  con->state = ST_SEND_HANDSHAKE;

  /**
   * connect_clients is already incremented
   */

  return NETWORK_SOCKET_SUCCESS;
}

network_socket_retval_t
plugin_add_backends(chassis *chas, gchar **backend_addresses,
                    gchar **read_only_backend_addresses) {
  guint i;
  chassis_private *g = chas->priv;

  GPtrArray *backends_arr = g->backends->backends;
  for (i = 0; backend_addresses[i]; i++) {
    if (BACKEND_OPERATE_SUCCESS !=
        network_backends_add(g->backends, backend_addresses[i], BACKEND_TYPE_RW,
                             BACKEND_STATE_UNKNOWN, chas)) {
      g_critical("add rw node: %s failed.", backend_addresses[i]);
      continue;
    }
    network_backend_init_extra(backends_arr->pdata[backends_arr->len - 1],
                               chas);
  }

  for (i = 0; read_only_backend_addresses && read_only_backend_addresses[i];
       i++) {
    if (BACKEND_OPERATE_SUCCESS !=
        network_backends_add(g->backends, read_only_backend_addresses[i],
                             BACKEND_TYPE_RO, BACKEND_STATE_UNKNOWN, chas)) {
      g_critical("add ro node: %s failed.", read_only_backend_addresses[i]);
      continue;
    }
    /* set conn-pool config */
    network_backend_init_extra(backends_arr->pdata[backends_arr->len - 1],
                               chas);
  }

  g_message("%s, ro server num:%d", G_STRLOC, i);

  return 0;
}

void truncate_default_db_when_drop_database(network_mysqld_con *con,
                                            char *schema_name) {
  if (schema_name &&
      strcasecmp(con->client->default_db->str, schema_name) == 0) {
    g_string_truncate(con->client->default_db, 0);
  }
}

