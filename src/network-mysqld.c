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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h> /** inet_ntoa */
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <netdb.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include <glib.h>

#include <mysql.h>
#include <mysqld_error.h>

#include "glib-ext.h"
#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-mysqld-packet.h"
#include "network-conn-pool.h"
#include "chassis-mainloop.h"
#include "chassis-event.h"
#include "network-conn-pool-wrap.h"
#include "cetus-util.h"
#include "cetus-users.h"
#include "cetus-monitor.h"
#include "plugin-common.h"
#include "network-compress.h"
#include "network-ssl.h"
#include "chassis-sql-log.h"
#include "cetus-acl.h"

#ifdef HAVE_WRITEV
#define USE_BUFFERED_NETIO
#else
#undef USE_BUFFERED_NETIO
#endif

#define E_NET_CONNRESET ECONNRESET
#define E_NET_CONNABORTED ECONNABORTED
#define E_NET_INPROGRESS EINPROGRESS
#if EWOULDBLOCK == EAGAIN
/**
 * some system make EAGAIN == EWOULDBLOCK which would lead to a
 * error in the case handling
 *
 * set it to -1 as this error should never happen
 */
#define E_NET_WOULDBLOCK -1
#else
#define E_NET_WOULDBLOCK EWOULDBLOCK
#endif

extern int      cetus_last_process;

static void network_mysqld_self_con_handle(int event_fd, short events, void *user_data);
static network_socket_retval_t
network_mysqld_process_select_resp(network_mysqld_con *con,
                                   network_socket *server, int *finish_flag,
                                   int *disp_flag);

/**
 * call the cleanup callback for the current connection
 *
 * @param srv    global context
 * @param con    connection context
 *
 * @return       NETWORK_SOCKET_SUCCESS on success
 */
network_socket_retval_t plugin_call_cleanup(chassis *srv,
                                            network_mysqld_con *con) {
  NETWORK_MYSQLD_PLUGIN_FUNC(func) = NULL;
  network_socket_retval_t retval = NETWORK_SOCKET_SUCCESS;

  if (!con->plugin_con_state && con->proxy_state == ST_PROXY_QUIT)
    return retval;

  func = con->plugins.con_cleanup;

  if (!func)
    return retval;

  retval = (*func)(srv, con);

  return retval;
}

/**
 * call the timeout callback for the current connection
 *
 * @param srv    global context
 * @param con    connection context
 *
 * @return       NETWORK_SOCKET_SUCCESS on success
 */
static network_socket_retval_t plugin_call_timeout(chassis *srv,
                                                   network_mysqld_con *con) {
  NETWORK_MYSQLD_PLUGIN_FUNC(func) = NULL;
  network_socket_retval_t retval = NETWORK_SOCKET_ERROR;

  func = con->plugins.con_timeout;

  if (!func) {
    /* default implementation */
    g_debug("%s: connection between %s and %s timed out. closing it", G_STRLOC,
            con->client->src->name->str,
            con->server ? con->server->dst->name->str : "(server)");
    con->prev_state = con->state;
    con->state = ST_ERROR;
    return NETWORK_SOCKET_SUCCESS;
  }

  if (!con->plugin_con_state && con->proxy_state == ST_PROXY_QUIT) {
    g_critical("%s: %p quit because of proxy state", G_STRLOC, con);
    return NETWORK_SOCKET_SUCCESS;
  }

  retval = (*func)(srv, con);

  return retval;
}

chassis_private *network_mysqld_priv_init() {
  chassis_private *priv;

  priv = g_new0(chassis_private, 1);

  priv->cons = g_ptr_array_new();
  priv->backends = network_backends_new();
  priv->users = cetus_users_new();
  priv->monitor = cetus_monitor_new();
  priv->acl = cetus_acl_new();
  priv->thread_id = 1;

  return priv;
}

void network_mysqld_priv_shutdown(chassis *chas, chassis_private *priv) {
  int i, len;

  if (!priv)
    return;

  len = priv->cons->len;
  for (i = 0; i < len; i++) {
    network_mysqld_con *con = g_ptr_array_index(priv->cons, i);
    con->server_to_be_closed = 1;
    plugin_call_cleanup(chas, con);
    con->proxy_state = ST_PROXY_QUIT;
    g_debug("%s: %p set proxy state ST_PROXY_QUIT", G_STRLOC, con);
  }
}

void network_mysqld_priv_finally_free_shared(chassis *chas,
                                             chassis_private *priv) {
  int i, len;

  if (!priv)
    return;

  len = priv->cons->len;

  for (i = 0; i < len; i++) {
    network_mysqld_con *con = g_ptr_array_index(priv->cons, i);
    g_debug("%s: %p finally release, total:%d", G_STRLOC, con, len);
    network_mysqld_con_free(con);
  }
}

void network_mysqld_priv_free(chassis G_GNUC_UNUSED *chas,
                              chassis_private *priv) {
  if (!priv)
    return;

  g_ptr_array_free(priv->cons, TRUE);

  network_backends_free(priv->backends);
  cetus_users_free(priv->users);
  g_free(priv->stats_variables);
  cetus_monitor_free(priv->monitor);
  cetus_acl_free(priv->acl);
  g_free(priv);
}

int network_mysqld_init(chassis *srv) {
  srv->priv_free = network_mysqld_priv_free;
  srv->priv_shutdown = network_mysqld_priv_shutdown;
  srv->priv_finally_free_shared = network_mysqld_priv_finally_free_shared;
  srv->priv = network_mysqld_priv_init();

  cetus_users_read_json(srv->priv->users, srv->config_manager, 0);

#ifdef HAVE_OPENSSL
  if (srv->ssl) {
    gboolean ok = network_ssl_init(srv->conf_dir);
    if (!ok) {
      g_critical("SSL init error, not using secure connection");
      srv->ssl = 0;
    }
  } else {
    g_message("ssl is false");
  }
#endif
  return 0;
}

/**
 * create a connection 
 *
 * @return       a connection context
 */
network_mysqld_con *network_mysqld_con_new() {
  network_mysqld_con *con;

  con = g_new0(network_mysqld_con, 1);
  con->parse.command = -1;

  con->max_retry_serv_cnt = 72;
  con->is_auto_commit = 1;

  con->orig_sql = g_string_new(NULL);

  con->connect_timeout.tv_sec = 2 * SECONDS;
  con->connect_timeout.tv_usec = 0;

  con->read_timeout.tv_sec = 10 * MINUTES;
  con->read_timeout.tv_usec = 0;

  con->write_timeout.tv_sec = 10 * MINUTES;
  con->write_timeout.tv_usec = 0;

  con->wait_clt_next_sql.tv_sec = 0;
  con->wait_clt_next_sql.tv_usec = 256 * 1000;
  return con;
}

void network_mysqld_add_connection(chassis *srv, network_mysqld_con *con,
                                   gboolean listen) {
  con->srv = srv;

  g_ptr_array_add(srv->priv->cons, con);
  if (listen) {
    srv->priv->listen_conns = g_list_append(srv->priv->listen_conns, con);
  }
}

/**
 * free a connection 
 *
 * closes the client and server sockets 
 *
 * @param con    connection context
 */
void network_mysqld_con_free(network_mysqld_con *con) {
  if (!con)
    return;

  g_debug("%s: connections total: %d, free con:%p", G_STRLOC,
          con->srv->priv->cons->len, con);

  if (con->parse.data && con->parse.data_free) {
    con->parse.data_free(con->parse.data);
  }

  if (con->servers != NULL) {
    g_warning("%s: servers are not null for con:%p", G_STRLOC, con);
  }

  if (con->server)
    network_socket_send_quit_and_free(con->server);
  if (con->client)
    network_socket_free(con->client);

  g_string_free(con->orig_sql, TRUE);

  /* we are still in the conns-array */

  g_ptr_array_remove_fast(con->srv->priv->cons, con);
  con->srv->priv->listen_conns =
      g_list_remove(con->srv->priv->listen_conns, con);
  con->srv->allow_new_conns = TRUE;

  g_free(con);
}

static struct timeval
network_mysqld_con_retry_timeout(network_mysqld_con *con) {
  /*
   *retry count   1  2  3  4...  8  9  10 11 12 ...
   *timeout (ms)  20 30 40 50... 90 10 10 10 10 ...
   */
  static struct timeval min_interval = {0, 10 * 1000}; /* 10ms */

  struct timeval timeout = min_interval;
  int cnt = con->retry_serv_cnt;
  if (cnt <= 8) {
    timeout.tv_usec += cnt * 10000;
  }
  return timeout;
}

int network_mysqld_queue_reset(network_socket *sock) {
  sock->packet_id_is_reset = TRUE;

  return 0;
}

/**
 * appends a raw MySQL packet to the queue 
 *
 * the packet is append the queue directly and shouldn't be used by the caller 
 * afterwards anymore and has to by in the MySQL Packet format
 *
 */
int network_mysqld_queue_append_raw(network_socket *sock, network_queue *queue,
                                    GString *data) {
  guint32 packet_len;
  guint8 packet_id;

  /* check that the length header is valid */
  if (queue != sock->send_queue && queue != sock->recv_queue) {
    g_critical("%s: queue = %p doesn't belong to sock %p", G_STRLOC,
               (void *)queue, (void *)sock);
    return -1;
  }

  g_assert_cmpint(data->len, >=, 4);

  packet_len = network_mysqld_proto_get_packet_len(data);
  packet_id = network_mysqld_proto_get_packet_id(data);

  g_assert_cmpint(packet_len, ==, data->len - 4);

  if (sock->packet_id_is_reset) {
    /* the ->last_packet_id is undefined, accept what we get */
    sock->last_packet_id = packet_id;
    g_debug("%s: set server pack id: %d", G_STRLOC, sock->last_packet_id);
    sock->packet_id_is_reset = FALSE;
  } else if (packet_id != (guint8)(sock->last_packet_id + 1)) {
    sock->last_packet_id++;
    g_debug("%s: server pack id ++: %d", G_STRLOC, sock->last_packet_id);
  } else {
    sock->last_packet_id++;
    g_debug("%s: server pack id ++: %d", G_STRLOC, sock->last_packet_id);
  }

  network_queue_append(queue, data);

  return 0;
}

/**
 * appends a payload to the queue
 *
 * the packet is copied and prepended with the mysql packet header 
 * before it is appended to the queue if neccesary the payload is
 * spread over multiple mysql packets
 */
int network_mysqld_queue_append(network_socket *sock, network_queue *queue,
                                const char *data, size_t packet_len) {
  gsize packet_offset = 0;

  do {
    GString *s;
    gsize cur_packet_len = MIN(packet_len, PACKET_LEN_MAX);

    s = g_string_sized_new(calculate_alloc_len(packet_len + NET_HEADER_SIZE));

    if (sock->packet_id_is_reset) {
      sock->packet_id_is_reset = FALSE;
      /** the ++last_packet_id will make sure we send a 0 */
      sock->last_packet_id = 0xff;
    }

    network_mysqld_proto_append_packet_len(s, cur_packet_len);
    network_mysqld_proto_append_packet_id(s, ++sock->last_packet_id);

    g_string_append_len(s, data + packet_offset, cur_packet_len);

    network_queue_append(queue, s);

    if (packet_len == PACKET_LEN_MAX) {
      s = g_string_sized_new(NET_HEADER_SIZE);

      network_mysqld_proto_append_packet_len(s, 0);
      network_mysqld_proto_append_packet_id(s, ++sock->last_packet_id);
      g_debug("%s: server pack id ++: %d", G_STRLOC, sock->last_packet_id);

      network_queue_append(queue, s);
    }

    packet_len -= cur_packet_len;
    packet_offset += cur_packet_len;
  } while (packet_len > 0);

  return 0;
}

/**
 * create a OK packet and append it to the send-queue
 *
 * @param con             a client socket 
 * @param affected_rows   affected rows 
 * @param insert_id       insert_id 
 * @param server_status   server_status (bitfield of SERVER_STATUS_*) 
 * @param warnings        number of warnings to fetch with SHOW WARNINGS 
 * @return 0
 *
 * @todo move to network_mysqld_proto
 */
int network_mysqld_con_send_ok_full(network_socket *con, guint64 affected_rows,
                                    guint64 insert_id, guint16 server_status,
                                    guint16 warnings) {
  GString *packet = g_string_new(NULL);
  network_mysqld_ok_packet_t *ok_packet;

  ok_packet = network_mysqld_ok_packet_new();
  ok_packet->affected_rows = affected_rows;
  ok_packet->insert_id = insert_id;
  ok_packet->server_status = server_status;
  g_debug("%s: server status: %d", G_STRLOC, server_status);
  ok_packet->warnings = warnings;

  network_mysqld_proto_append_ok_packet(packet, ok_packet);

  network_mysqld_queue_append(con, con->send_queue, S(packet));
  network_mysqld_queue_reset(con);

  g_string_free(packet, TRUE);
  network_mysqld_ok_packet_free(ok_packet);

  return 0;
}

/**
 * send a simple OK packet
 *
 * - no affected rows
 * - no insert-id
 * - AUTOCOMMIT
 * - no warnings
 *
 * @param con             a client socket 
 */
int network_mysqld_con_send_ok(network_socket *con) {
  return network_mysqld_con_send_ok_full(con, 0, 0, SERVER_STATUS_AUTOCOMMIT,
                                         0);
}

static int network_mysqld_con_send_error_full_all(network_socket *con,
                                                  const char *errmsg,
                                                  gsize errmsg_len,
                                                  guint errorcode,
                                                  const gchar *sqlstate) {
  GString *packet;
  network_mysqld_err_packet_t *err_packet;

  packet = g_string_sized_new(calculate_alloc_len(10 + errmsg_len));

  err_packet = network_mysqld_err_packet_new();
  err_packet->errcode = errorcode;
  if (errmsg)
    g_string_assign_len(err_packet->errmsg, errmsg, errmsg_len);
  if (sqlstate) {
    g_string_assign_len(err_packet->sqlstate, sqlstate, strlen(sqlstate));
  }

  network_mysqld_proto_append_err_packet(packet, err_packet);

  network_mysqld_queue_append(con, con->send_queue, S(packet));
  network_mysqld_queue_reset(con);

  network_mysqld_err_packet_free(err_packet);
  g_string_free(packet, TRUE);

  return 0;
}

/**
 * send a error packet to the client connection
 *
 * @note the sqlstate has to match the SQL standard. 
 * If no matching SQL state is known, leave it at NULL
 *
 * @param con         the client connection
 * @param errmsg      the error message
 * @param errmsg_len  byte-len of the error-message
 * @param errorcode   mysql error-code we want to send
 * @param sqlstate    if none-NULL, 5-char SQL state to send, 
 *                    if NULL, default SQL state is used
 *
 * @return 0 on success
 */
int network_mysqld_con_send_error_full(network_socket *con, const char *errmsg,
                                       gsize errmsg_len, guint errorcode,
                                       const gchar *sqlstate) {
  return network_mysqld_con_send_error_full_all(con, errmsg, errmsg_len,
                                                errorcode, sqlstate);
}

/**
 * send a error-packet to the client connection
 *
 * errorcode is 1000, sqlstate is NULL
 *
 * @param con         the client connection
 * @param errmsg      the error message
 * @param errmsg_len  byte-len of the error-message
 *
 * @see network_mysqld_con_send_error_full
 */
int network_mysqld_con_send_error(network_socket *con, const char *errmsg,
                                  gsize errmsg_len) {
  return network_mysqld_con_send_error_full(con, errmsg, errmsg_len,
                                            ER_UNKNOWN_ERROR, NULL);
}

/**
 * get a full packet from the raw queue and move it to the packet queue 
 */
network_socket_retval_t network_mysqld_con_get_packet(chassis *chas,
                                                      network_socket *con) {
  GString *packet;
  GString header;
  char header_str[NET_HEADER_SIZE + 1] = {0};
  guint32 packet_len;
  guint8 packet_id;

  network_queue *recv_queue_raw;
  if (con->do_compress) {
    g_debug("%s:queue from recv_queue_uncompress_raw:%p", G_STRLOC, con);
    recv_queue_raw = con->recv_queue_uncompress_raw;
  } else if (con->ssl) {
    recv_queue_raw = con->recv_queue_decrypted_raw;
  } else {
    recv_queue_raw = con->recv_queue_raw;
  }

  /**
   * read the packet header (4 bytes)
   */
  header.str = header_str;
  header.allocated_len = sizeof(header_str);
  header.len = 0;

  g_debug("%s:queue_len:%d", G_STRLOC, (int)recv_queue_raw->len);
  /* read the packet len if the leading packet */
  if (!network_queue_peek_str(recv_queue_raw, NET_HEADER_SIZE, &header)) {
    g_debug("%s:wait for event", G_STRLOC);
    /* too small */
    return NETWORK_SOCKET_WAIT_FOR_EVENT;
  }

  packet_len = network_mysqld_proto_get_packet_len(&header);
  if (packet_len > chas->cetus_max_allowed_packet) {
    g_message("packet len: %d excess max_allowed_packet: %d", packet_len,
              chas->cetus_max_allowed_packet);
    return NETWORK_SOCKET_ERROR;
  }
  packet_id = network_mysqld_proto_get_packet_id(&header);

  /* move the packet from the raw queue to the recv-queue */
  if ((packet = network_queue_pop_str(recv_queue_raw,
                                      packet_len + NET_HEADER_SIZE, NULL))) {
#if NETWORK_DEBUG_TRACE_IO
    g_debug("%s:output for sock:%p, packet id:%d, packet_len:%d", G_STRLOC, con,
            packet_id, packet_len);
    /* to trace the data we received from the socket, enable this */
    g_debug_hexdump(G_STRLOC, S(packet));
#endif

    if (con->packet_id_is_reset) {
      con->last_packet_id = packet_id;
      con->packet_id_is_reset = FALSE;
    } else if (packet_id != (guint8)(con->last_packet_id + 1)) {
      g_message("%s: recv pack-id %d, but expected %d ... out of sync",
                G_STRLOC, packet_id, con->last_packet_id + 1);
      g_string_free(packet, TRUE);

      return NETWORK_SOCKET_ERROR;
    } else {
      con->last_packet_id = packet_id;
    }

    network_queue_append(con->recv_queue, packet);
  } else {
    g_debug("%s:wait for event", G_STRLOC);
    return NETWORK_SOCKET_WAIT_FOR_EVENT;
  }

  return NETWORK_SOCKET_SUCCESS;
}

static GString* network_mysqld_get_compressed_packet(network_socket* sock)
{
  network_queue *queue = sock->send_queue;
  if (g_queue_get_length(queue->chunks) == 0)
    return NULL;
  GString *compressed_packet = g_string_sized_new(16384);
  network_mysqld_proto_append_packet_len(compressed_packet, 0);
  sock->compressed_packet_id++;
  network_mysqld_proto_append_packet_id(compressed_packet,
                                        sock->compressed_packet_id);
  network_mysqld_proto_append_packet_len(compressed_packet, 0);

  z_stream strm;
  cetus_compress_init(&strm);

  int uncompressed_len = 0;
  int flush = 0;

  int chunk_id = 0;
  GList *chunk;
  for (chunk = queue->chunks->head, chunk_id = 0; chunk;
       chunk_id++, chunk = chunk->next) {
    GString *s = chunk->data;
    char *buf;
    int buf_len;
    if (chunk_id == 0) {
      buf = s->str + queue->offset;
      buf_len = s->len - queue->offset;
    } else {
      buf = s->str;
      buf_len = s->len;
    }

    uncompressed_len += buf_len;
    if (uncompressed_len > PACKET_LEN_MAX) {
      flush = 1;
      uncompressed_len -= buf_len;
      buf_len = PACKET_LEN_MAX - uncompressed_len;
      if (buf_len == 0) {
        buf = NULL;
      }
      uncompressed_len = PACKET_LEN_MAX;
      cetus_compress(&strm, compressed_packet, buf, buf_len, 1);
      cetus_compress_end(&strm);
    } else {
      flush = (chunk == queue->chunks->tail) ? 1 : 0;
      cetus_compress(&strm, compressed_packet, buf, buf_len, flush);
      if (flush) {
        cetus_compress_end(&strm);
      }
    }
    queue->offset += buf_len;
    sock->total_output += buf_len;
    if (flush == 1) {
      break;
    }
  }
  /* delete used chunks, adjust offset */
  for (chunk = queue->chunks->head; chunk;) {
    GString *s = chunk->data;

    if (queue->offset >= s->len) {
      queue->offset -= s->len;
      g_string_free(s, TRUE);
      g_queue_delete_link(queue->chunks, chunk);

      chunk = queue->chunks->head;
    } else {
      break; /* have some residual */
    }
  }

  int compressed_len =
      compressed_packet->len - NET_HEADER_SIZE - COMP_HEADER_SIZE;
  network_mysqld_proto_set_compressed_packet_len(
      compressed_packet, compressed_len, uncompressed_len);
  return compressed_packet;
}

static int network_mysqld_con_compress_all_packets(network_socket* sock)
{
  GString *packet = NULL;
  while (packet = network_mysqld_get_compressed_packet(sock)) {
    network_queue_append(sock->send_queue_compressed, packet);
  }
  return 1;
}

network_socket_retval_t
network_mysqld_con_get_uncompressed_packet(chassis *chas, network_socket *con) {
  GString *packet;
  GString header;
  char header_str[NET_HEADER_SIZE + COMP_HEADER_SIZE + 1] = {0};
  guint32 packet_len;

  int header_length = NET_HEADER_SIZE + COMP_HEADER_SIZE;

  /**
   * read the packet header (4 bytes)
   */
  header.str = header_str;
  header.allocated_len = sizeof(header_str);
  header.len = 0;
  network_queue *src_queue = con->recv_queue_raw;
#ifdef HAVE_OPENSSL
  if (con->ssl) {
    src_queue = con->recv_queue_decrypted_raw;
  }
#endif
  while (1) {
    header.len = 0;
    /* read the packet len if the leading packet */
    if (!network_queue_peek_str(src_queue, header_length, &header)) {
      /* too small */
      g_debug("%s:network_queue_peek_str wait for event for sock:%p", G_STRLOC,
              con);
      return NETWORK_SOCKET_WAIT_FOR_EVENT;
    }

    packet_len = network_mysqld_proto_get_packet_len(&header);
    if (packet_len > chas->cetus_max_allowed_packet) {
      g_message("packet len: %d excess max_allowed_packet: %d", packet_len,
                chas->cetus_max_allowed_packet);
      return NETWORK_SOCKET_ERROR;
    }

    /* move the packet from the raw queue to the recv-queue */
    if ((packet = network_queue_pop_str(
             src_queue, packet_len + NET_HEADER_SIZE + COMP_HEADER_SIZE,
             NULL))) {
#if NETWORK_DEBUG_TRACE_IO
      g_debug("%s:output for sock:%p", G_STRLOC, con);
      /* to trace the data we received from the socket, enable this */
      g_debug_hexdump(G_STRLOC, S(packet));
#endif
      unsigned char *info = (unsigned char *)packet->str + NET_HEADER_SIZE;
      int uncompressed_len = (info[0]) | (info[1] << 8) | (info[2] << 16);
      con->compressed_packet_id = info[-1];
      g_debug("%s: do uncompress here, com len:%d, uncompress len:%d", G_STRLOC,
              packet_len, uncompressed_len);

      GString *uncompressed_packet;
      if (uncompressed_len == 0) {
        uncompressed_len = packet_len;
        uncompressed_packet =
            g_string_sized_new(calculate_alloc_len(uncompressed_len));
        g_string_append_len(uncompressed_packet,
                            (char *)(info + COMP_HEADER_SIZE),
                            uncompressed_len);
      } else {
        uncompressed_packet =
            g_string_sized_new(calculate_alloc_len(uncompressed_len));
        int ret = cetus_uncompress(uncompressed_packet,
                                   (unsigned char *)packet->str + header_length,
                                   packet_len);
        if (ret != Z_OK) {
          g_critical("%s:cetus_uncompress error for con:%p, ret:%d", G_STRLOC,
                     con, ret);
        }
        g_debug("%s:call cetus_uncompress for con:%p", G_STRLOC, con);
      }

      network_queue_append(con->recv_queue_uncompress_raw, uncompressed_packet);
      g_string_free(packet, TRUE);
    } else {
      return NETWORK_SOCKET_WAIT_FOR_EVENT;
    }
  }

  return NETWORK_SOCKET_SUCCESS;
}

/**
 * read a MySQL packet from the socket
 *
 * the packet is added to the con->recv_queue and contains a full mysql packet
 * with packet-header and everything 
 */
network_socket_retval_t network_mysqld_read(chassis G_GNUC_UNUSED *chas,
                                            network_socket *sock) {
  switch (network_socket_read(sock)) {
  case NETWORK_SOCKET_WAIT_FOR_EVENT:
    return NETWORK_SOCKET_WAIT_FOR_EVENT;
  case NETWORK_SOCKET_ERROR:
    return NETWORK_SOCKET_ERROR;
  case NETWORK_SOCKET_SUCCESS:
    break;
  case NETWORK_SOCKET_ERROR_RETRY:
    g_error("NETWORK_SOCKET_ERROR_RETRY wasn't expected");
    break;
  }
#ifdef HAVE_OPENSSL
  if (sock->ssl) {
    if (!network_ssl_decrypt_packet(sock)) {
      return NETWORK_SOCKET_ERROR;
    }
  }
#endif
  if (sock->do_compress) {
    network_mysqld_con_get_uncompressed_packet(chas, sock);
  }

  return network_mysqld_con_get_packet(chas, sock);
}

network_socket_retval_t network_mysqld_write(network_socket *sock) {
  if (sock->do_compress) {
    if (!sock->write_uncomplete) {
      network_mysqld_con_compress_all_packets(sock);
    }
  }
  network_socket_retval_t ret;
#ifdef HAVE_OPENSSL
  if (sock->ssl)
    ret = network_ssl_write(sock, -1);
  else
#endif
    ret = network_socket_write(sock, -1);

  return ret;
}

/**
 * call the hooks of the plugins for each state
 *
 * if the plugin doesn't implement a hook, we provide a default operation
 *
 * @param srv      the global context
 * @param con      the connection context
 * @param state    state to handle
 * @return         NETWORK_SOCKET_SUCCESS on success
 */
network_socket_retval_t plugin_call(chassis *srv, network_mysqld_con *con,
                                    int state) {
  network_socket_retval_t ret;
  NETWORK_MYSQLD_PLUGIN_FUNC(func) = NULL;

  if (!con->plugin_con_state && con->proxy_state == ST_PROXY_QUIT) {
    g_critical("%s: %p quit because of proxy state not zero", G_STRLOC, con);
    return NETWORK_SOCKET_SUCCESS;
  }

  switch (state) {
  case ST_INIT:
    func = con->plugins.con_init;

    if (!func) {
      con->state = ST_CONNECT_SERVER;
    }
    break;
  case ST_CONNECT_SERVER:
    func = con->plugins.con_connect_server;
    break;
  case ST_SEND_HANDSHAKE:
    func = con->plugins.con_send_handshake;

    if (!func) {
      con->state = ST_READ_AUTH;
    }

    break;
  case ST_READ_AUTH:
    func = con->plugins.con_read_auth;

    break;
  case ST_SEND_AUTH_RESULT:
    /* called after the auth data is sent to the client */
    func = con->plugins.con_send_auth_result;

    if (!func) {
      /*
       * figure out what to do next:
       * - switch to 'read command from client'
       * - close connection
       * - read auth-data from client
       * - read another auth-result packet from server
       */
      switch (con->auth_result_state) {
      case MYSQLD_PACKET_OK:
        /*
         * OK, delivered to client,
         * switch to command phase
         */
        con->state = ST_READ_QUERY;
        if (con->is_client_compressed) {
          con->client->do_compress = 1;
          network_socket_set_send_buffer_size(con->client, COMPRESS_BUF_SIZE);
        }
        break;
      case MYSQLD_PACKET_ERR:
        /* ERR delivered to client, close the conn now */
        con->prev_state = con->state;
        con->state = ST_ERROR;
        g_debug("%s, con:%p:state is set ST_ERROR", G_STRLOC, con);
        break;
      case AUTH_SWITCH:
        con->auth_result_state = MYSQLD_PACKET_OK;
        con->state = ST_READ_AUTH;
        break;
      default:
        g_debug("%s: unexpected st for SEND_AUTH_RESULT: %02x", G_STRLOC,
                con->auth_result_state);
        con->prev_state = con->state;
        con->state = ST_ERROR;
        break;
      }
    }
    break;
  case ST_READ_QUERY:
    func = con->plugins.con_read_query;
    break;
  case ST_READ_QUERY_RESULT:
    func = con->plugins.con_read_query_result;
    break;
  case ST_SEND_QUERY_RESULT:
    func = con->plugins.con_send_query_result;

    if (!func) {
      if (!con->server_to_be_closed) {
        con->state = ST_READ_QUERY;
        g_debug("%s: set ST_READ_QUERY for con:%p", G_STRLOC, con);
      } else {
        con->state = ST_CLOSE_SERVER;
        g_debug("%s: set ST_CLOSE_SERVER for con:%p", G_STRLOC, con);
      }
    }
    break;

  case ST_ERROR:
    g_debug("%s: not executing plugin func in state ST_ERROR", G_STRLOC);
    return NETWORK_SOCKET_SUCCESS;
  default:
    g_error("%s: unhandled state: %d", G_STRLOC, state);
    break;
  }

  if (!func)
    return NETWORK_SOCKET_SUCCESS;

  if (!con->plugin_con_state && con->proxy_state == ST_PROXY_QUIT) {
    g_critical("%s: %p quit because of proxy state not zero", G_STRLOC, con);
    return NETWORK_SOCKET_SUCCESS;
  }

  ret = (*func)(srv, con);

  return ret;
}

/**
 * reset the command-response parsing
 *
 * some commands needs state information and we have to 
 * reset the parsing as soon as we add a new command to the send-queue
 */
void network_mysqld_con_reset_command_response_state(network_mysqld_con *con) {
  con->parse.command = -1;
  if (con->parse.data && con->parse.data_free) {
    con->parse.data_free(con->parse.data);

    con->parse.data = NULL;
    con->parse.data_free = NULL;
  }
}

/**
 * reset per-query states
 */
void network_mysqld_con_reset_query_state(network_mysqld_con *con) {
  g_string_truncate(con->orig_sql, 0);
}

/**
 * get the name of a connection state
 */
const char *network_mysqld_con_st_name(network_mysqld_con_state_t state) {
  switch (state) {
  case ST_INIT:
    return "ST_INIT";
  case ST_CONNECT_SERVER:
    return "ST_CONNECT_SERVER";
  case ST_SEND_HANDSHAKE:
    return "ST_SEND_HANDSHAKE";
  case ST_READ_AUTH:
    return "ST_READ_AUTH";
  case ST_SEND_AUTH_RESULT:
    return "ST_SEND_AUTH_RESULT";
  case ST_READ_QUERY:
    return "ST_READ_QUERY";
  case ST_SEND_QUERY:
    return "ST_SEND_QUERY";
  case ST_READ_QUERY_RESULT:
    return "ST_READ_QUERY_RESULT";
  case ST_SEND_QUERY_RESULT:
    return "ST_SEND_QUERY_RESULT";
  case ST_CLIENT_QUIT:
    return "ST_CLIENT_QUIT";
  case ST_CLOSE_CLIENT:
    return "ST_CLOSE_CLIENT";
  case ST_CLOSE_SERVER:
    return "ST_CLOSE_SERVER";
  case ST_ERROR:
    return "ST_ERROR";
  case ST_SEND_ERROR:
    return "ST_SEND_ERROR";
  }

  return "unknown";
}

#define DISP_STOP 1
#define DISP_CONTINUE 2
#define WAIT_FOR_EVENT(ev_struct, ev_type, timeout)                            \
  event_set(&(ev_struct->event), ev_struct->fd, ev_type,                       \
            network_mysqld_con_handle, con);                                   \
  g_debug("%s:call WAIT_FOR_EVENT, ev:%p", G_STRLOC, &(ev_struct->event));     \
  chassis_event_add_with_timeout(con->srv, &(ev_struct->event), timeout);

static void log_slowquery(int interval_ms, char *ip, char *domain, char *user,
                          char *sql) {
  uint64_t usec;
  struct timeval t;
  gettimeofday(&t, NULL);
  usec = (uint64_t)t.tv_sec * 1000000 + t.tv_usec;
  char time_str[64];
  make_iso8601_timestamp(time_str, usec);

  float interval = interval_ms / 1000.0;
  g_log("slowquery", G_LOG_LEVEL_MESSAGE,
        "# Time: %s\n"
        "# User@Host: %s[%s] @ %s[%s] Id: 0\n"
        "# Query_time: %f Lock_time: 0.000000 Rows_sent: 0 Rows_examined: 0\n"
        "SET timestamp=%ld;\n%s;\n",
        time_str, user, user, domain == NULL ? " " : domain,
        ip == NULL ? " " : ip, interval, t.tv_sec, sql);
}

static void handle_query_time_stats(network_mysqld_con *con) {
  int diff = (con->resp_send_time.tv_sec - con->req_recv_time.tv_sec) * 1000;
  diff += (con->resp_send_time.tv_usec - con->req_recv_time.tv_usec) / 1000;

  diff = MAX(0, diff);
  if (diff >= con->srv->long_query_time) {
    gchar **ip = g_strsplit_set(con->client->src->name->str, ":", -1);
    log_slowquery(diff, ip[0], NULL, con->client->response->username->str,
                  con->orig_sql->str);
    g_strfreev(ip);
    diff = con->srv->long_query_time - 1;
  }
  con->srv->query_stats.query_time_table[diff]++;
}

static void handle_query_wait_stats(network_mysqld_con *con) {
  struct timeval cur;
  gettimeofday(&cur, NULL);

  int diff = (cur.tv_sec - con->req_recv_time.tv_sec) * 1000;
  diff += (cur.tv_usec - con->req_recv_time.tv_usec) / 1000;

  if (diff < 0 || diff >= MAX_WAIT_TIME) {
    g_message("%s: query waits too long:%d for con:%p", G_STRLOC, diff, con);
    diff = MAX_WAIT_TIME - 1;
  }

  con->srv->query_stats.query_wait_table[diff]++;
}

static void process_service_unavailable(network_mysqld_con *con) {
  con->state = ST_SEND_QUERY_RESULT;
  g_message("%s: service unavailable for con:%p", G_STRLOC, con);

  network_mysqld_con_send_error_full(con->client, C("service unavailable"),
                                     ER_TOO_MANY_USER_CONNECTIONS, "42000");
  con->server_to_be_closed = 1;
  con->is_wait_server = 0;
  network_queue_clear(con->client->recv_queue);
  network_mysqld_queue_reset(con->client);
}

static int handle_read_query(network_mysqld_con *con,
                             network_mysqld_con_state_t ostate) {
  struct timeval timeout;
  network_socket *recv_sock;
  network_packet last_packet;

  chassis *srv = con->srv;
  recv_sock = con->client;

  recv_sock->total_output = 0;

  recv_sock->compressed_packet_id = 0;
  con->is_read_ro_server_allowed = 0;

  gettimeofday(&(con->req_recv_time), NULL);

  if (!con->is_wait_server) {
    do {
      switch (network_mysqld_read(srv, recv_sock)) {
      case NETWORK_SOCKET_SUCCESS:
        break;
      case NETWORK_SOCKET_WAIT_FOR_EVENT:
        if (con->client->is_need_q_peek_exec) {
          timeout = con->wait_clt_next_sql;
          con->client->is_need_q_peek_exec = 0;
          g_debug("%s: set a short timeout:%p", G_STRLOC, con);
        } else {
          if (con->srv->maintain_close_mode && !con->is_admin_client) {
            timeout.tv_sec = con->srv->maintained_client_idle_timeout;
            timeout.tv_usec = 0;
            g_debug("%s: set a maintained client timeout:%p", G_STRLOC, con);
          } else {
            if (!con->is_in_transaction) {
              timeout.tv_sec = con->srv->client_idle_timeout;
            } else {
              timeout.tv_sec = con->srv->incomplete_tran_idle_timeout;
            }
            timeout.tv_usec = 0;
            g_debug("%s: set a long timeout:%p", G_STRLOC, con);
          }
        }

        WAIT_FOR_EVENT(con->client, EV_READ, &timeout);

        return DISP_STOP;
      case NETWORK_SOCKET_ERROR_RETRY:
      case NETWORK_SOCKET_ERROR:
        g_critical("%s: network_mysqld_read error", G_STRLOC);
        con->prev_state = con->state;
        con->state = ST_ERROR;
        return DISP_CONTINUE;
      }

      if (con->state != ostate) {
        break;
      }

      GQueue *chunks = recv_sock->recv_queue->chunks;
      last_packet.data = g_queue_peek_tail(chunks);
    } while (last_packet.data->len == (PACKET_LEN_MAX + NET_HEADER_SIZE));
  } else {
    g_debug("%s:wait server.", G_STRLOC);
  }

  /* check for tracing some problems and it will be removed later */
  if (con->client->recv_queue->chunks->head == NULL) {
    g_critical("%s:client recv queue head is nil", G_STRLOC);
  }

  g_debug("%s:call read query:%s", G_STRLOC, con->orig_sql->str);
  network_socket_retval_t ret = plugin_call(srv, con, con->state);
  switch (ret) {
  case NETWORK_SOCKET_WAIT_FOR_EVENT:
    return DISP_STOP;
  case NETWORK_SOCKET_SUCCESS:
    if (con->retry_serv_cnt > 0 && con->is_wait_server) {
      g_message("%s: wait successful:%d, con:%p", G_STRLOC, con->retry_serv_cnt,
                con);
      handle_query_wait_stats(con);
    }
    con->is_wait_server = 0;
    con->retry_serv_cnt = 0;
    break;
  case NETWORK_SOCKET_ERROR_RETRY:
    if (con->retry_serv_cnt < con->max_retry_serv_cnt) {
      if (con->retry_serv_cnt % 8 == 0) {
        network_connection_pool_create_conn(con);
      }
      con->retry_serv_cnt++;
      con->is_wait_server = 1;
      timeout = network_mysqld_con_retry_timeout(con);

      g_debug(G_STRLOC ": wait again:%d, con:%p, l:%d", con->retry_serv_cnt,
              con, (int)timeout.tv_usec);
      WAIT_FOR_EVENT(con->client, EV_TIMEOUT, &timeout);
      return DISP_STOP;
    }
    /* fall through */
  default:
    g_critical("%s: wait failed and no server backend for user:%s, ret:%d",
               G_STRLOC, con->client->response->username->str, ret);

    handle_query_wait_stats(con);
    process_service_unavailable(con);
    break;
  }

  /**
   * there should be 3 possible next states from here:
   *
   * - ST_ERROR
   *   (if something went wrong and we want to
   *   close the connection
   * - ST_SEND_QUERY
   *   (if we want to send data to the con->server)
   * - ST_SEND_QUERY_RESULT (if we want to send data
   *   to the con->client)
   *
   * @todo verify this with a clean switch ()
   */

  /* reset the tracked command
   */
  if (con->state == ST_SEND_QUERY) {
    network_mysqld_con_reset_command_response_state(con);
    g_debug("%s: call reset_command_response_state for con:%p", G_STRLOC, con);
  }
  return DISP_CONTINUE;
}

static int process_rw_write(network_mysqld_con *con,
                            network_mysqld_con_state_t ostate, int *disp_flag) {
  if (!con->server->do_compress || con->server->write_uncomplete == 0) {
    g_debug("%s: conn:%p, server charset code:%d, charset:%s, client charset "
            "code:%d, charset:%s",
            G_STRLOC, con, con->server->charset_code, con->server->charset->str,
            con->client->charset_code, con->client->charset->str);
    /* Add check for abnormal response processing */
    if (con->srv->is_fast_stream_enabled && (!con->server->do_compress)) {
      if (con->server->recv_queue_raw->chunks->length > 0) {
        g_warning("%s: server raw recv queue has contents:%d for con:%p when "
                  "writing sql to server",
                  G_STRLOC, con->server->recv_queue_raw->chunks->length, con);
      }
    }

    if (con->server->send_queue->offset == 0) {
      /* only parse the packets once */
      network_packet packet;
      GQueue *chunks = con->server->send_queue->chunks;
      packet.data = g_queue_peek_head(chunks);
      packet.offset = 0;

      if (network_mysqld_con_command_states_init(con, &packet)) {
        g_warning("%s: track mysql proto states failed", G_STRLOC);
        con->prev_state = con->state;
        con->state = ST_ERROR;

        return DISP_CONTINUE;
      }
    }

    con->server->resp_len = 0;
    con->server->compressed_packet_id = 0xFF;

    if (con->client->last_packet_id > 0) {
      g_warning("%s: last packet id:%d for con:%p", G_STRLOC,
                con->client->last_packet_id, con);
    }

    if (con->client->send_queue->chunks->length > 0) {
      g_warning("%s: client-send-queue-len = %d", G_STRLOC,
                con->client->send_queue->chunks->length);
    }
  }

  con->server->write_uncomplete = 0;
  switch (network_mysqld_write(con->server)) {
  case NETWORK_SOCKET_SUCCESS:
    break;
  case NETWORK_SOCKET_WAIT_FOR_EVENT:
    con->server->write_uncomplete = 1;
    g_debug("%s:write wait for con:%p", G_STRLOC, con);
    WAIT_FOR_EVENT(con->server, EV_WRITE, &con->write_timeout);
    *disp_flag = DISP_STOP;
    return 0;
  case NETWORK_SOCKET_ERROR_RETRY:
  case NETWORK_SOCKET_ERROR:
    g_debug("%s:write(SEND_QUERY) error", G_STRLOC);

    /**
     * write() failed, close the connections
     */
    con->prev_state = con->state;
    con->state = ST_ERROR;
    con->server_to_be_closed = 1;
    break;
  }

  if (con->state != ostate) {
    *disp_flag = DISP_CONTINUE;
    return 0;
  }

  /* some statements don't have a server response */
  switch (con->parse.command) {
  case COM_STMT_SEND_LONG_DATA: /* not acked */
  case COM_STMT_CLOSE:
    if (!con->server_to_be_closed) {
      g_debug("%s: set ST_READ_QUERY for con:%p", G_STRLOC, con);
      con->state = ST_READ_QUERY;
    } else {
      g_debug("%s: set ST_CLOSE_SERVER for con:%p", G_STRLOC, con);
      con->state = ST_CLOSE_SERVER;
    }

    network_mysqld_queue_reset(con->client);
    network_mysqld_queue_reset(con->server);

    if (con->prepare_stmt_count > 0) {
      con->prepare_stmt_count--;
    } else {
      g_warning("%s: prepare_stmt_count is zero for con:%p", G_STRLOC, con);
    }
    g_debug("%s: conn:%p, sub, now prepare_stmt_count:%d", G_STRLOC, con,
            con->prepare_stmt_count);

    if (con->prepare_stmt_count == 0) {
      if (!con->is_in_transaction) {
        if (network_pool_add_conn(con, 0)) {
          g_message("%s,con:%p:->pool failed", G_STRLOC, con);
        }
      }
    }
    break;
  default:
    con->state = ST_READ_QUERY_RESULT;
    break;
  }

  return 1;
}

static int handle_send_query_to_server(network_mysqld_con *con,
                                       network_mysqld_con_state_t ostate) {
  int disp_flag = 0;

  con->analysis_next_pos = 0;
  con->cur_resp_len = 0;
  con->eof_met_cnt = 0;
  con->eof_last_met = 0;
  con->fast_stream_last_exec_index = 0;
  con->fast_stream_need_more = 0;
  con->partically_record_left_cnt = 0;

  /*
   * send the query to the server
   * this state will loop until all the packets
   * from the send-queue are flushed
   */
  if (!process_rw_write(con, ostate, &disp_flag)) {
    return disp_flag;
  }

  return DISP_CONTINUE;
}

void send_part_content_to_client(network_mysqld_con *con) {
  g_debug(
      "%s: call send_part_content_to_client, and queue len:%llu, con client:%p",
      G_STRLOC, (unsigned long long)con->client->send_queue->chunks->length,
      con->client);
  switch (network_mysqld_write(con->client)) {
  case NETWORK_SOCKET_SUCCESS:
    break;
  case NETWORK_SOCKET_WAIT_FOR_EVENT:
    g_debug("%s: write wait for event", G_STRLOC);
    break;
  case NETWORK_SOCKET_ERROR_RETRY:
  case NETWORK_SOCKET_ERROR:
    con->prev_state = con->state;
    con->state = ST_ERROR;
    g_debug("%s, con:%p:state is set ST_ERROR", G_STRLOC, con);
    break;
  }

  g_debug("%s: call send_part_content_to_client over, and queue len:%llu, con "
          "client:%p",
          G_STRLOC, (unsigned long long)con->client->send_queue->chunks->length,
          con->client);
}

static int send_result_to_client(network_mysqld_con *con,
                                 network_mysqld_con_state_t ostate) {
  chassis *srv = con->srv;
  struct timeval timeout;

  g_debug("%s: send server result to client", G_STRLOC);
  /**
   * send the query result-set to the client
   */
  switch (network_mysqld_write(con->client)) {
  case NETWORK_SOCKET_SUCCESS:
    break;
  case NETWORK_SOCKET_WAIT_FOR_EVENT:
    g_debug("%s: write wait and add event", G_STRLOC);
    timeout = con->write_timeout;

    WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout);

    return DISP_STOP;
  case NETWORK_SOCKET_ERROR_RETRY:
  case NETWORK_SOCKET_ERROR:
    /**
     * client is gone away
     *
     * close the connection and clean up
     */
    con->prev_state = con->state;
    con->state = ST_ERROR;
    g_message("%s: client is gone away for con:%p", G_STRLOC, con);
    break;
  }

  /* if the write failed, don't call the plugin handlers */
  if (con->state != ostate) {
    return DISP_CONTINUE;
  }

  switch (plugin_call(srv, con, con->state)) {
  case NETWORK_SOCKET_SUCCESS:
    break;
  default:
    con->prev_state = con->state;
    con->state = ST_ERROR;
    g_debug("%s, con:%p:state is set ST_ERROR", G_STRLOC, con);
    break;
  }

  gettimeofday(&(con->resp_send_time), NULL);
  handle_query_time_stats(con);

  con->client->update_time = srv->current_time;
  if (!con->is_admin_client && !con->client->is_server_conn_reserved) {
    con->client->is_need_q_peek_exec = 1;
    g_debug("%s: set is_need_q_peek_exec true, state:%d", G_STRLOC, con->state);
  } else {
    con->client->is_need_q_peek_exec = 0;
    g_debug("%s: set is_need_q_peek_exec false", G_STRLOC);
  }

  if (con->slave_conn_shortaged) {
    if (con->last_check_conn_supplement_time != srv->current_time) {
      g_debug("%s: slave conn shortaged, try to add more conns ", G_STRLOC);
      network_connection_pool_create_conn(con);
      con->last_check_conn_supplement_time = srv->current_time;
    } else {
      g_debug("%s: slave conn shortaged, but time is the same", G_STRLOC);
    }
  }

  return DISP_CONTINUE;
}

static gboolean fast_analyze_stream(network_mysqld_con *con,
                                    network_socket *server, int *send_flag) {
  int total_output = 0;
  GList *chunk;
  gboolean need_more = FALSE;
  network_queue *queue = server->recv_queue_raw;

  g_debug("%s: fast_analyze_stream here:%d for con:%p, "
          "con->partically_record_left_cnt:%d",
          G_STRLOC, (int)con->last_payload_len, con,
          (int)con->partically_record_left_cnt);

  int last_eof_cnt = con->eof_met_cnt;
  GString *last_payload = NULL;

  for (chunk = queue->chunks->head; chunk; chunk = chunk->next) {
    GString *s = chunk->data;
    last_payload = s;

    if (con->partically_record_left_cnt) {
      con->partically_record_left_cnt--;
      g_debug("%s: continue  here:%d for con:%p, s->len:%d", G_STRLOC,
              con->last_payload_len, con, (int)s->len);
      con->fast_stream_last_exec_index = 1;
      continue;
    }

    int diff, packet_len = NET_HEADER_SIZE;
    unsigned char *header, *end;
    int complete_record_len = 0;
    guchar last_packet_id = 0;

    if (con->last_payload_len > 0) {
      int aggr_packet_len = con->last_payload_len + s->len;
      if (aggr_packet_len < NET_HEADER_SIZE) {
        memcpy(con->last_payload + con->last_payload_len, s->str, s->len);
        con->last_payload_len = con->last_payload_len + s->len;
        con->cur_resp_len += s->len;
        g_debug("%s: padding here:%d for con:%p", G_STRLOC,
                con->last_payload_len, con);
        con->fast_stream_last_exec_index = 2;
        continue;
      }
    }

    if (con->analysis_next_pos < con->cur_resp_len) {
      diff = con->cur_resp_len - con->analysis_next_pos;

      guchar pkt_type = 0;
      switch (con->last_payload_len) {
      case 1:
        packet_len +=
            ((con->last_payload[0]) | (s->str[0] << 8) | (s->str[1] << 16));
        last_packet_id = s->str[2];
        pkt_type = s->str[3];
        if (pkt_type == MYSQLD_PACKET_EOF) {
          con->eof_met_cnt++;
        } else if (pkt_type == MYSQLD_PACKET_ERR) {
          con->eof_met_cnt++;
          con->eof_met_cnt++;
        }
        break;
      case 2:
        packet_len += ((con->last_payload[0]) | (con->last_payload[1] << 8) |
                       (s->str[0] << 16));
        last_packet_id = s->str[1];
        pkt_type = s->str[2];
        if (pkt_type == MYSQLD_PACKET_EOF) {
          con->eof_met_cnt++;
        } else if (pkt_type == MYSQLD_PACKET_ERR) {
          con->eof_met_cnt++;
          con->eof_met_cnt++;
        }
        break;
      case 3:
        packet_len += ((con->last_payload[0]) | (con->last_payload[1] << 8) |
                       (con->last_payload[2] << 16));
        last_packet_id = s->str[0];
        pkt_type = s->str[1];
        if (pkt_type == MYSQLD_PACKET_EOF) {
          con->eof_met_cnt++;
        } else if (pkt_type == MYSQLD_PACKET_ERR) {
          con->eof_met_cnt++;
          con->eof_met_cnt++;
        }
        break;
      case 4:
        packet_len += ((con->last_payload[0]) | (con->last_payload[1] << 8) |
                       (con->last_payload[2] << 16));
        last_packet_id = con->last_payload[3];
        pkt_type = s->str[0];
        if (pkt_type == MYSQLD_PACKET_EOF) {
          con->eof_met_cnt++;
        } else if (pkt_type == MYSQLD_PACKET_ERR) {
          con->eof_met_cnt++;
          con->eof_met_cnt++;
        }
        break;
      default:
        g_critical("%s: not expected here:%d for con:%p", G_STRLOC,
                   con->last_payload_len, con);
        break;
      }

      header = s->str - diff + packet_len;
      end = s->str + s->len;

      if (header <= end) {
        complete_record_len = packet_len - con->last_payload_len;
      } else {
        con->last_payload_len = 0;
        con->cur_resp_len += s->len;
        con->analysis_next_pos += packet_len;
        g_debug("%s:continue here:%d for con:%p, packet_len:%d, s->len:%d, "
                "cur_resp_len:%d,analysis_next_pos:%d",
                G_STRLOC, (int)con->last_payload_len, con, packet_len,
                (int)s->len, (int)con->cur_resp_len,
                (int)con->analysis_next_pos);
        con->fast_stream_last_exec_index = 3;
        continue;
      }
      g_debug("%s:  packet len:%d, last_payload_len:%d, diff:%d for con:%p",
              G_STRLOC, packet_len, (int)con->last_payload_len, diff, con);
    } else {
      diff = con->analysis_next_pos - con->cur_resp_len;
      header = s->str + diff;
      end = s->str + s->len;
      if (header >= end) {
        con->cur_resp_len += s->len;
        con->last_payload_len = 0;
        g_debug("%s:continue here:%d for con:%p, cur_resp_len:%d, "
                "analysis_next_pos:%d, s->len:%d",
                G_STRLOC, con->last_payload_len, con, (int)con->cur_resp_len,
                (int)con->analysis_next_pos, (int)s->len);
        con->fast_stream_last_exec_index = 4;
        continue;
      } else if (header >= (end - NET_HEADER_SIZE)) {
        con->cur_resp_len += s->len;
        memcpy(con->last_payload, header, end - header);
        con->last_payload_len = end - header;
        g_warning("%s: not enough info, analysis_next_pos:%d, header:%p, "
                  "end:%p for con:%p, last_payload_len:%d",
                  G_STRLOC, (int)con->analysis_next_pos, header, end, con,
                  (int)con->last_payload_len);
        continue;
      }
      packet_len = NET_HEADER_SIZE +
                   ((header[0]) | (header[1] << 8) | (header[2] << 16));
      last_packet_id = header[NET_HEADER_SIZE - 1];
      if (header[NET_HEADER_SIZE] == MYSQLD_PACKET_EOF) {
        con->eof_met_cnt++;
      } else if (header[NET_HEADER_SIZE] == MYSQLD_PACKET_ERR) {
        con->eof_met_cnt++;
        con->eof_met_cnt++;
      }
      header = header + packet_len;
      if (header <= end) {
        complete_record_len = diff + packet_len;
      } else {
        con->last_payload_len = 0;
        con->cur_resp_len += s->len;
        con->analysis_next_pos += packet_len;
        g_debug("%s:continue here:%d for con:%p, s->len:%d, packet_len:%d",
                G_STRLOC, con->last_payload_len, con, (int)s->len, packet_len);
        con->fast_stream_last_exec_index = 5;
        continue;
      }
    }

    con->analysis_next_pos += packet_len;
    con->cur_resp_len += s->len;
    con->last_payload_len = 0;

    g_debug("%s: complete_record_len:%d for con:%p ", G_STRLOC,
            complete_record_len, con);

    if (header < end) {
      do {
        if (header < (end - NET_HEADER_SIZE)) {
          packet_len = NET_HEADER_SIZE +
                       ((header[0]) | (header[1] << 8) | (header[2] << 16));
          last_packet_id = header[NET_HEADER_SIZE - 1];
          if (header[NET_HEADER_SIZE] == MYSQLD_PACKET_EOF) {
            con->eof_met_cnt++;
          } else if (header[NET_HEADER_SIZE] == MYSQLD_PACKET_ERR) {
            con->eof_met_cnt++;
            con->eof_met_cnt++;
          }
          header = header + packet_len;
          con->analysis_next_pos += packet_len;
          if (header < end) {
            con->client->last_packet_id = last_packet_id;
            complete_record_len += packet_len;
          } else if (header == end) {
            con->client->last_packet_id = last_packet_id;
            complete_record_len += packet_len;
            break;
          } else {
            break;
          }
        } else {
          memcpy(con->last_payload, header, end - header);
          con->last_payload_len = end - header;
          g_debug("%s: not enough info, analysis_next_pos:%d, header:%p, "
                  "end:%p for con:%p, last_payload_len:%d",
                  G_STRLOC, (int)con->analysis_next_pos, header, end, con,
                  (int)con->last_payload_len);
          break;
        }
      } while (TRUE);
    } else if (header == end) {
      con->client->last_packet_id = last_packet_id;
    }

    total_output += complete_record_len;

    g_debug("%s: cur resp len:%d, analysis_next_pos:%d, packet len:%d, "
            "s->len:%d for con:%p",
            G_STRLOC, (int)con->cur_resp_len, (int)con->analysis_next_pos,
            packet_len, (int)s->len, con);
    if (con->analysis_next_pos != con->cur_resp_len) {
      need_more = TRUE;
      con->fast_stream_need_more = 1;
      if (s->len > RECORD_PACKET_LEN) {
        memcpy(con->record_last_payload, s->str + s->len - RECORD_PACKET_LEN,
               RECORD_PACKET_LEN);
        con->last_record_payload_len = RECORD_PACKET_LEN;
      } else {
        memcpy(con->record_last_payload, s->str, s->len);
        con->last_record_payload_len = s->len;
      }
      int partially_diff = 0;
      if (complete_record_len > 0) {
        partially_diff = s->len - complete_record_len;
        g_debug("%s: partially_diff:%d for con:%p", G_STRLOC, partially_diff,
                con);
        GString *remainder =
            g_string_sized_new(calculate_alloc_len(partially_diff));
        g_string_append_len(remainder, s->str + complete_record_len,
                            partially_diff);
        s->len = complete_record_len;
        queue->len -= partially_diff;
        network_queue_append(server->recv_queue, remainder);
      } else {
        GString *raw_packet = g_queue_pop_tail(queue->chunks);
        queue->len -= raw_packet->len;
        network_queue_append(server->recv_queue, raw_packet);
      }
      con->partically_record_left_cnt++;
      g_debug("%s: wait more response, analysis_next_pos:%d, cur_resp_len:%d, "
              "diff:%d, complete_record_len:%d for con:%p",
              G_STRLOC, (int)con->analysis_next_pos, (int)con->cur_resp_len,
              partially_diff, complete_record_len, con);
      con->fast_stream_last_exec_index = 6;
      break;
    }
    con->fast_stream_last_exec_index = 7;
  }

  if (con->eof_met_cnt != last_eof_cnt) {
    con->eof_last_met = 1;
  }

  if (!need_more) {
    if (last_payload->len > RECORD_PACKET_LEN) {
      memcpy(con->record_last_payload,
             last_payload->str + last_payload->len - RECORD_PACKET_LEN,
             RECORD_PACKET_LEN);
      con->last_record_payload_len = RECORD_PACKET_LEN;
    } else {
      memcpy(con->record_last_payload, last_payload->str, last_payload->len);
      con->last_record_payload_len = last_payload->len;
    }
  }

  if (chunk && chunk->next != NULL) {
    g_message("%s: still has packets, execute here for con:%p", G_STRLOC, con);
    chunk = chunk->next;
    g_queue_unlink(queue->chunks, chunk);
    int len = 0;
    do {
      GString *packet = chunk->data;
      len += packet->len;
      network_queue_append(server->recv_queue, packet);
      chunk = chunk->next;
    } while (chunk);

    queue->len -= len;
  }

  g_debug("%s: execute here, last_payload_len:%d for con:%p", G_STRLOC,
          con->last_payload_len, con);

  if (total_output > 0) {
    *send_flag = 1;
  }

  if (con->partically_record_left_cnt > 1) {
    g_warning("%s: partically_record_left_cnt:%d for con:%p", G_STRLOC,
              con->partically_record_left_cnt, con);
  }

  if (con->eof_met_cnt > 1 && !need_more) {
    g_debug("%s: finished true for con:%p, eof_met_cnt:%d", G_STRLOC, con,
            con->eof_met_cnt);
    return TRUE;
  }

  return FALSE;
}

static network_socket_retval_t
network_mysqld_process_select_resp(network_mysqld_con *con,
                                   network_socket *server, int *finish_flag,
                                   int *disp_flag) {
  int send_flag = 0;
  gboolean is_finished = fast_analyze_stream(con, server, &send_flag);

  network_queue *queue = con->client->send_queue;
  if (!g_queue_is_empty(queue->chunks)) {
    int len = 0;
    GString *raw_packet;
    while ((raw_packet = g_queue_pop_head(server->recv_queue_raw->chunks)) !=
           NULL) {
      len += raw_packet->len;
      g_queue_push_tail(queue->chunks, raw_packet);
    }

    queue->len += len;
    server->recv_queue_raw->len = 0;
    g_message(
        "%s: append raw packets to send queue for con:%p, len:%d, queue len:%d",
        G_STRLOC, con, len, (int)queue->len);
    network_queue *reserved_queue = server->recv_queue_raw;
    server->recv_queue_raw = server->recv_queue;
    server->recv_queue = reserved_queue;

  } else {
    network_queue *reserved_queue = con->client->send_queue;
    con->client->send_queue = server->recv_queue_raw;
    server->recv_queue_raw = server->recv_queue;
    server->recv_queue = reserved_queue;
  }

  if (is_finished) {
    if (finish_flag) {
      *finish_flag = 1;
    }

    if (server->recv_queue_raw->chunks->length > 0) {
      g_warning("%s: server raw recv queue still has contents:%d for con:%p",
                G_STRLOC, server->recv_queue_raw->chunks->length, con);
    }

    con->state = ST_SEND_QUERY_RESULT;
    if (con->is_calc_found_rows) {
      con->client->is_server_conn_reserved = 1;
      g_debug("%s: set is_server_conn_reserved true for con:%p", G_STRLOC, con);
    } else {
      if (!con->is_prepared && !con->is_in_sess_context &&
          !con->last_warning_met) {
        con->client->is_server_conn_reserved = 0;
        g_debug("%s: set is_server_conn_reserved false", G_STRLOC);
      } else {
        con->client->is_server_conn_reserved = 1;
        g_debug("%s: set is_server_conn_reserved true", G_STRLOC);
      }
    }

    proxy_plugin_con_t *st = con->plugin_con_state;
    network_injection_queue_reset(st->injected.queries);
    network_queue_clear(con->client->recv_queue);
    network_mysqld_queue_reset(con->client);
    if (disp_flag) {
      *disp_flag = DISP_CONTINUE;
    }
  } else {
    if (server->resp_len > con->srv->max_resp_len) {
      return NETWORK_SOCKET_WAIT_FOR_EVENT;
    } else {
      if (send_flag) {
        send_part_content_to_client(con);
      }
      WAIT_FOR_EVENT(server, EV_READ, &(con->read_timeout));
      if (disp_flag) {
        *disp_flag = DISP_STOP;
      }
    }
  }

  return NETWORK_SOCKET_SUCCESS;
}

network_socket_retval_t network_mysqld_read_rw_resp(network_mysqld_con *con,
                                                    network_socket *server,
                                                    int *disp_flag) {
  chassis *chas = con->srv;

  int read_len = server->to_read;

  network_socket_retval_t ret = network_socket_read(server);
  switch (ret) {
  case NETWORK_SOCKET_WAIT_FOR_EVENT:
    return NETWORK_SOCKET_WAIT_FOR_EVENT;
  case NETWORK_SOCKET_ERROR:
    return NETWORK_SOCKET_ERROR;
  case NETWORK_SOCKET_SUCCESS:
    break;
  case NETWORK_SOCKET_ERROR_RETRY:
    g_error("NETWORK_SOCKET_ERROR_RETRY wasn't expected");
    break;
  }

  server->resp_len += read_len;

  if (!server->do_compress) {
    if (read_len > 0 && !con->resultset_is_needed &&
        con->candidate_fast_streamed) {
      g_debug("%s: visit network_mysqld_process_select_resp for con:%p",
              G_STRLOC, con);
      return network_mysqld_process_select_resp(con, server, NULL, disp_flag);
    }
    ret = network_mysqld_con_get_packet(chas, server);
  } else {
    network_mysqld_con_get_uncompressed_packet(chas, server);
    ret = network_mysqld_con_get_packet(chas, server);
  }

  while (ret == NETWORK_SOCKET_SUCCESS) {
    network_packet packet;
    GList *chunk;

    chunk = server->recv_queue->chunks->tail;
    packet.data = chunk->data;
    packet.offset = 0;

    int is_finished = network_mysqld_proto_get_query_result(&packet, con);
    if (is_finished == 1) {
      g_debug("%s:packets read finished, default db:%s, server db:%s", G_STRLOC,
              con->client->default_db->str, server->default_db->str);
      if (con->parse.command == COM_QUERY) {
        network_mysqld_com_query_result_t *query = con->parse.data;
        if (query && query->warning_count > 0) {
          g_debug("%s warning flag from server:%s is met:%s", G_STRLOC,
                  server->dst->name->str, con->orig_sql->str);
          con->last_warning_met = 1;
        }
      }
      break;
    }

    ret = network_mysqld_con_get_packet(chas, server);

    if (ret == NETWORK_SOCKET_WAIT_FOR_EVENT) {
      break;
    }
  }

  return ret;
}

static int normal_read_query_result(network_mysqld_con *con,
                                    network_mysqld_con_state_t ostate) {
  struct timeval timeout;
  chassis *srv = con->srv;
  /* read all packets of the resultset
   *
   * depending on the backend we may forward the data
   * to the client right away
   */
  network_socket *recv_sock;

  recv_sock = con->server;

  if (recv_sock == NULL) {
    con->prev_state = con->state;
    con->state = ST_ERROR;
    g_debug("%s, con:%p:state is set ST_ERROR", G_STRLOC, con);
    return DISP_CONTINUE;
  }

  do {
    g_debug("%s: call network_mysqld_read_rw_resp:%d, to read:%d", G_STRLOC,
            (int)recv_sock->resp_len, (int)recv_sock->to_read);

    int resp_len = recv_sock->resp_len;
    int disp_flag = 0;
    switch (network_mysqld_read_rw_resp(con, recv_sock, &disp_flag)) {
    case NETWORK_SOCKET_SUCCESS:
      g_debug("%s: network_mysqld_read_rw_resp return success:%d for con:%p",
              G_STRLOC, (int)recv_sock->resp_len, con);
      if (disp_flag == DISP_STOP) {
        return DISP_STOP;
      }
      if (disp_flag == DISP_CONTINUE) {
        return DISP_CONTINUE;
      } else {
        break;
      }
    case NETWORK_SOCKET_WAIT_FOR_EVENT:
      timeout = con->read_timeout;
      g_debug(
          "%s: set read query timeout, already read:%d, sql len:%d for con:%p",
          G_STRLOC, (int)recv_sock->resp_len, (int)con->orig_sql->len, con);
      if (resp_len != recv_sock->resp_len) {
        if (g_queue_is_empty(con->client->send_queue->chunks)) {
          g_debug("%s: exchange queue:%p", G_STRLOC, con);
          network_queue *queue = con->client->send_queue;
          con->client->send_queue = con->server->recv_queue;
          con->server->recv_queue = queue;
          GString *packet = g_queue_peek_tail(con->client->send_queue->chunks);
          if (packet) {
            con->client->last_packet_id =
                network_mysqld_proto_get_packet_id(packet);
          }
        } else {
          g_debug("%s: client send queue is not empty for con:%p", G_STRLOC,
                  con);
          GString *packet;
          while ((packet = g_queue_pop_head(recv_sock->recv_queue->chunks)) !=
                 NULL) {
            network_mysqld_queue_append_raw(con->client,
                                            con->client->send_queue, packet);
          }
        }
      }
      if (con->candidate_tcp_streamed &&
          !g_queue_is_empty(con->client->send_queue->chunks)) {
        g_debug("%s: send_part_content_to_client:%p", G_STRLOC, con);
        send_part_content_to_client(con);
      }
      WAIT_FOR_EVENT(con->server, EV_READ, &timeout);
      return DISP_STOP;
    case NETWORK_SOCKET_ERROR_RETRY:
    case NETWORK_SOCKET_ERROR:
      g_critical("%s: read(READ_QUERY_RESULT) error:%p, sql:%s", G_STRLOC, con,
                 con->orig_sql->str);
      con->prev_state = con->state;
      con->state = ST_ERROR;
      break;
    }

    switch (plugin_call(srv, con, con->state)) {
    case NETWORK_SOCKET_SUCCESS:
      break;
    case NETWORK_SOCKET_ERROR:
      /*
       * something nasty happend,
       * let's close the connection
       */
      con->prev_state = con->state;
      con->state = ST_ERROR;
      g_debug("%s, con:%p:state is set ST_ERROR", G_STRLOC, con);
      break;
    default:
      g_critical("%s: ...", G_STRLOC);
      con->prev_state = con->state;
      con->state = ST_ERROR;
      g_debug("%s, con:%p:state is set ST_ERROR", G_STRLOC, con);
      break;
    }
  } while (con->state == ST_READ_QUERY_RESULT);

  return DISP_CONTINUE;
}

static void process_read_event(network_mysqld_con *con, int event_fd) {
  int b = -1;

  /**
   * check how much data there is to read
   *
   * ioctl()
   * - returns 0 if connection is closed
   * - or -1 and ECONNRESET on solaris
   *   or -1 and EPIPE on HP/UX
   */
  if (ioctl(event_fd, FIONREAD, &b)) {
    g_critical("ioctl(%d, FIONREAD, ...) failed: %s", event_fd,
               g_strerror(errno));
    con->prev_state = con->state;
    con->state = ST_ERROR;
  } else if (b != 0) {
    if (event_fd == con->client->fd) {
      con->client->to_read = b;
      g_debug("%s:client to read:%d for con:%p", G_STRLOC, b, con);
    } else if (con->server && event_fd == con->server->fd) {
      con->server->to_read = b;
      g_debug("%s:server to read:%d for con:%p", G_STRLOC, b, con);
    } else {
      g_error("%s: neither nor", G_STRLOC);
    }
  } else { /* Linux */
    if (event_fd == con->client->fd) {
      /*
       * the client closed the connection,
       * let's keep the server side open
       */
      con->prev_state = con->state;
      con->state = ST_CLOSE_CLIENT;
      g_debug("%s:client needs to be closed for con:%p", G_STRLOC, con);
    } else if (con->server && event_fd == con->server->fd &&
               con->com_quit_seen) {
      con->state = ST_CLOSE_SERVER;
    } else {
      g_message("%s:server closed prematurely, op: %s", G_STRLOC,
                network_mysqld_con_st_name(con->state));

      network_mysqld_con_send_error_full(con->client,
                                         C("server closed prematurely"),
                                         ER_CETUS_UNKNOWN, "HY000");
      con->server_to_be_closed = 1;
      con->state = ST_SEND_QUERY_RESULT;
    }
  }
}

static void process_timeout_event(network_mysqld_con *con) {
  if (con->is_wait_server) {
    g_debug("%s:now get a chance to get server connection", G_STRLOC);
  } else {
    /*
     * if we got a timeout on ST_CONNECT_SERVER
     * we should pick another backend
     */
    switch (plugin_call_timeout(con->srv, con)) {
    case NETWORK_SOCKET_SUCCESS:
      /* the plugin did set a reasonable next state */
      break;
    default:
      con->prev_state = con->state;
      con->state = ST_ERROR;
      g_debug("%s, con:%p:state is set ST_ERROR", G_STRLOC, con);
      break;
    }
  }
}

/**
 * handle the different states of the MySQL protocol
 *
 * @param event_fd     fd on which the event was fired
 * @param events       the event that was fired
 * @param user_data    the connection handle
 */
void network_mysqld_con_handle(int event_fd, short events, void *user_data) {
  g_debug("%s:visit network_mysqld_con_handle", G_STRLOC);
  network_mysqld_con_state_t ostate;
  network_mysqld_con *con = user_data;
  chassis *srv = con->srv;
  int retval;

  if (events == EV_READ) {
    process_read_event(con, event_fd);
  } else if (events == EV_TIMEOUT) {
    process_timeout_event(con);
  }

  /**
   * loop on the same connection as long as we don't end up in a stable state
   */

  do {
    struct timeval timeout;

    ostate = con->state;
#if NETWORK_DEBUG_TRACE_STATE_CHANGES
    /*
     * if you need the state-change information without dtrace,
     * enable this
     */
    g_debug("%s: %s, con:%p", G_STRLOC, network_mysqld_con_st_name(con->state),
            con);
#endif
    switch (con->state) {
    case ST_ERROR:
      /* we can't go on, close the connection */
      con->server_to_be_closed = 1;
      plugin_call_cleanup(srv, con);
      g_debug("%s: client conn %p released", G_STRLOC, con);
      network_mysqld_con_free(con);
      return;
    case ST_CLOSE_CLIENT:
    case ST_CLIENT_QUIT:
    case ST_CLOSE_SERVER:
      /* FIXME: this comment has nothing to do with reality...
       * the server connection is still fine,
       * let's keep it open for reuse */
      plugin_call_cleanup(srv, con);
      g_debug("%s: client conn %p released, state:%d", G_STRLOC, con,
              con->state);

      network_mysqld_con_free(con);

      con = NULL;

      return;
    case ST_INIT:
      /*
       * if we are a proxy ask the remote server
       * for the hand-shake packet
       * if not, we generate one
       */
      switch (plugin_call(srv, con, con->state)) {
      case NETWORK_SOCKET_SUCCESS:
        break;
      default:
        /**
         * no luck, let's close the connection
         */
        g_critical("%s: ST_INIT not successful", G_STRLOC);

        con->prev_state = con->state;
        con->state = ST_ERROR;

        break;
      }

      break;
    case ST_CONNECT_SERVER:
      switch ((retval = plugin_call(srv, con, con->state))) {
      case NETWORK_SOCKET_SUCCESS:

        /**
         * hmm, if this is success and we have something
         * in the clients send-queue
         * we just send it out ... who needs a server ?
         */

        if (con->client->send_queue->chunks->length > 0 &&
            con->server == NULL) {
          /* we want to send something to the client */
          con->state = ST_SEND_HANDSHAKE;
        }

        break;
      default:
        g_critical("%s: hook for CONNECT_SERVER invalid: %d", G_STRLOC, retval);

        con->prev_state = con->state;
        con->state = ST_ERROR;

        break;
      }

      break;
    case ST_SEND_HANDSHAKE:
      /* send the hand-shake to the client and
       * wait for a response
       */
      switch (network_mysqld_write(con->client)) {
      case NETWORK_SOCKET_SUCCESS:
        break;
      case NETWORK_SOCKET_WAIT_FOR_EVENT:
        timeout = con->write_timeout;

        WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout);

        return;
      case NETWORK_SOCKET_ERROR_RETRY:
      case NETWORK_SOCKET_ERROR:
        /**
         * writing failed, closing connection
         */
        con->prev_state = con->state;
        con->state = ST_ERROR;
        g_debug("%s, con:%p:state is set ST_ERROR", G_STRLOC, con);
        break;
      }

      if (con->state != ostate)
        break;

      switch (plugin_call(srv, con, con->state)) {
      case NETWORK_SOCKET_SUCCESS:
        break;
      default:
        g_critical("%s: plugin_call(SEND_HANDSHAKE) failed", G_STRLOC);
        con->prev_state = con->state;
        con->state = ST_ERROR;
        break;
      }
      break;
    case ST_READ_AUTH: {
      /* read auth from client */
      network_socket *recv_sock;

      recv_sock = con->client;

      g_assert(events == 0 || event_fd == recv_sock->fd);

      switch (network_mysqld_read(srv, recv_sock)) {
      case NETWORK_SOCKET_SUCCESS:
        break;
      case NETWORK_SOCKET_WAIT_FOR_EVENT:
        timeout = con->read_timeout;
        g_debug("%s: set read query timeout for con:%p", G_STRLOC, con);

        WAIT_FOR_EVENT(con->client, EV_READ, &timeout);

        return;
      case NETWORK_SOCKET_ERROR_RETRY:
      case NETWORK_SOCKET_ERROR:
        con->state = ST_ERROR;
        g_message("%s: ST_READ_AUTH: read error for con:%p", G_STRLOC, con);
        break;
      }

      if (con->state != ostate)
        break;

      switch (plugin_call(srv, con, con->state)) {
      case NETWORK_SOCKET_SUCCESS:
        break;
      case NETWORK_SOCKET_ERROR:
        con->state = ST_SEND_ERROR;
        break;
      default:
        g_critical("%s: plugin_call(READ_AUTH) failed", G_STRLOC);
        con->prev_state = con->state;
        con->state = ST_ERROR;
        break;
      }
      break;
    }
#ifdef HAVE_OPENSSL
    case ST_FRONT_SSL_HANDSHAKE:
      g_debug(G_STRLOC " %p con_handle -> ST_FRONT_SSL_HANDSHAKE", con);
      if (events & EV_READ) {
        switch (network_socket_read(con->client)) {
        case NETWORK_SOCKET_SUCCESS:
          break;
        case NETWORK_SOCKET_WAIT_FOR_EVENT:
          timeout = con->read_timeout;
          WAIT_FOR_EVENT(con->client, EV_READ, &timeout);
          return;
        case NETWORK_SOCKET_ERROR_RETRY:
        case NETWORK_SOCKET_ERROR:
          con->state = ST_ERROR;
          g_warning("%s: ST_FRONT_SSL_HANDSHAKE: read error con:%p", G_STRLOC,
                    con);
          break;
        }
      }
      switch (network_ssl_handshake(con->client)) {
      case NETWORK_SOCKET_SUCCESS:
        con->state = ST_READ_AUTH;
        break;
      case NETWORK_SOCKET_WAIT_FOR_EVENT:
        timeout = con->read_timeout;
        WAIT_FOR_EVENT(con->client, EV_READ, &timeout);
        g_debug(G_STRLOC " %p WAIT_FOR_EVENT, return", con);
        return;
      case NETWORK_SOCKET_WAIT_FOR_WRITABLE:
        timeout = con->write_timeout;
        WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout);
        return;
      case NETWORK_SOCKET_ERROR:
        con->state = ST_ERROR;
        g_debug("%s, con:%p:state is set ST_ERROR", G_STRLOC, con);
        break;
      }
      break;
#endif
    case ST_SEND_AUTH_RESULT:
      switch (network_mysqld_write(con->client)) {
      case NETWORK_SOCKET_SUCCESS:
        break;
      case NETWORK_SOCKET_WAIT_FOR_EVENT:
        timeout = con->write_timeout;
        WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout);
        return;
      case NETWORK_SOCKET_ERROR_RETRY:
      case NETWORK_SOCKET_ERROR:
        g_debug("%s: write(AUTH_RESULT) error", G_STRLOC);
        con->prev_state = con->state;
        con->state = ST_ERROR;
        break;
      }

      if (con->state != ostate)
        break;

      switch (plugin_call(srv, con, con->state)) {
      case NETWORK_SOCKET_SUCCESS:
        break;
      default:
        g_critical("%s: ...", G_STRLOC);
        con->prev_state = con->state;
        con->state = ST_ERROR;
        break;
      }

      break;
    case ST_READ_QUERY:
      g_debug(G_STRLOC " %p con_handle -> ST_READ_QUERY", con);

      CHECK_PENDING_EVENT(&(con->client->event));

      if (events & EV_READ) {
        if (events != EV_READ) {
          g_critical(G_STRLOC " events:%d, unexpected events", events);
        }
      } else if (events & EV_WRITE) {
        g_critical(G_STRLOC "write events:%d, unexpected events", events);
      } else if (events && events != EV_TIMEOUT) {
        g_critical(G_STRLOC "not rw events:%d, unexpected events", events);
      }

      /* TODO If config is reloaded, close all current cons */
      g_assert(events == 0 || event_fd == con->client->fd);
      if (handle_read_query(con, ostate) == DISP_STOP) {
        return;
      }
      break;
    case ST_SEND_QUERY:
      if (handle_send_query_to_server(con, ostate) == DISP_STOP) {
        return;
      }
      break;
    case ST_READ_QUERY_RESULT:
      if (normal_read_query_result(con, ostate) == DISP_STOP) {
        return;
      }
      break;
    case ST_SEND_QUERY_RESULT:
      g_debug("%s: send query result for con:%p", G_STRLOC, con);
      if (send_result_to_client(con, ostate) == DISP_STOP) {
        return;
      }
      break;
    case ST_SEND_ERROR:
      /**
       * send error to the client
       * and close the connections afterwards
       */
      switch (network_mysqld_write(con->client)) {
      case NETWORK_SOCKET_SUCCESS:
        break;
      case NETWORK_SOCKET_WAIT_FOR_EVENT:
        timeout = con->write_timeout;

        WAIT_FOR_EVENT(con->client, EV_WRITE, &timeout);
        return;
      case NETWORK_SOCKET_ERROR_RETRY:
      case NETWORK_SOCKET_ERROR:
        g_critical("%s: write(SEND_ERROR) error", G_STRLOC);

        con->prev_state = con->state;
        con->state = ST_ERROR;
        break;
      }

      con->prev_state = con->state;
      con->state = ST_CLOSE_CLIENT;
      g_debug("%s:client needs to closed for con:%p", G_STRLOC, con);

      break;
    default:
      con->prev_state = con->state;
      con->state = ST_ERROR;
      g_debug("%s, con:%p:state is set ST_ERROR", G_STRLOC, con);
      break;
    }

    event_fd = -1;
    events = 0;
  } while (ostate != con->state);

  return;
}

static gboolean update_accept_event(network_mysqld_con *con,
                                    const int new_flags) {
  g_assert(con != NULL);
  struct event *ev = &(con->server->event);
  struct event_base *base = ev->ev_base;
  if (ev->ev_flags == new_flags)
    return TRUE;
  if (event_del(ev) == -1)
    return FALSE;
  event_set(ev, con->server->fd, new_flags, network_mysqld_con_accept, con);
  event_base_set(base, ev);
  event_add(ev, 0);
  return TRUE;
}

static void accept_new_conns(chassis *chas, const gboolean do_accept);

static struct event maxconnsevent;
static void maxconns_handler(const int fd, const short which, void *arg) {
  struct timeval t = {.tv_sec = 0, .tv_usec = 10000};

  chassis *chas = arg;
  if (fd == -42 || chas->allow_new_conns == FALSE) {
    /* reschedule in 10ms if we need to keep polling */
    evtimer_set(&maxconnsevent, maxconns_handler, chas);
    event_base_set(chas->event_base, &maxconnsevent);
    evtimer_add(&maxconnsevent, &t);
  } else {
    evtimer_del(&maxconnsevent);
    accept_new_conns(chas, TRUE);
    g_message("Got vacant fd, start accept");
  }
}

/*
 * Sets whether we are listening for new connections or not.
 */
static void accept_new_conns(chassis *chas, const gboolean do_accept) {
  GList *l;
  for (l = chas->priv->listen_conns; l; l = l->next) {
    network_mysqld_con *con = l->data;
    if (con->server == NULL) {
      continue;
    }
    if (do_accept) {
      update_accept_event(con, EV_READ | EV_PERSIST);
      if (listen(con->server->fd, 128) != 0) {
        g_warning("listen errno: %d", errno);
      }
    } else {
      update_accept_event(con, 0);
      if (listen(con->server->fd, 0) != 0) {
        g_warning("listen errno: %d", errno);
      }
    }
  }
  if (!do_accept) {
    chas->allow_new_conns = FALSE;
    maxconns_handler(-42, 0, chas);
  }
}

/**
 * accept a connection
 *
 * event handler for listening connections
 *
 * @param event_fd     fd on which the event was fired
 * @param events       the event that was fired
 * @param user_data    the listening connection handle
 * 
 */
void network_mysqld_con_accept(int G_GNUC_UNUSED event_fd, short events,
                               void *user_data) {
  network_mysqld_con *listen_con = user_data;
  network_mysqld_con *client_con;
  network_socket *client;

  g_assert(events == EV_READ);
  g_assert(listen_con->server);
  int reason = 0;
  client = network_socket_accept(listen_con->server, &reason);
  if (!client) {
    if (reason == EMFILE) { /* if reach max fd, stop accepting */
      g_warning("EMFILE (Too many open files), stop accept");
      accept_new_conns(listen_con->srv, FALSE);
    }
    return;
  }

  /* looks like we open a client connection */
  client_con = network_mysqld_con_new();
  client_con->client = client;

  network_mysqld_add_connection(listen_con->srv, client_con, FALSE);

  g_debug("%s: accept a new client connection", G_STRLOC);

  /**
   * inherit the config to the new connection
   */

  client_con->plugins = listen_con->plugins;
  client_con->config = listen_con->config;

  network_mysqld_con_handle(-1, 0, client_con);

  return;
}

/**
 * @TODO move to network_mysqld_proto
 */
int network_mysqld_con_send_resultset(network_socket *con, GPtrArray *fields,
                                      GPtrArray *rows) {
  GString *s;
  gsize i, j;

  g_assert(fields->len > 0);

  s = g_string_new(NULL);

  /* - len = 99
   *  \1\0\0\1
   *    \1 - one field
   *  \'\0\0\2
   *    \3def
   *    \0
   *    \0
   *    \0
   *    \21@@version_comment
   *    \0            - org-name
   *    \f            - filler
   *    \10\0         - charset
   *    \34\0\0\0     - length
   *    \375          - type
   *    \1\0          - flags
   *    \37           - decimals
   *    \0\0          - filler
   *  \5\0\0\3
   *    \376\0\0\2\0
   *  \35\0\0\4
   *    \34MySQL Community Server (GPL)
   *  \5\0\0\5
   *    \376\0\0\2\0
   */

  /* the field-count */
  network_mysqld_proto_append_lenenc_int(s, fields->len);
  network_mysqld_queue_append(con, con->send_queue, S(s));

  for (i = 0; i < fields->len; i++) {
    MYSQL_FIELD *field = fields->pdata[i];

    g_string_truncate(s, 0);

    network_mysqld_proto_append_lenenc_str(s, field->catalog ? field->catalog
                                                             : "def");
    network_mysqld_proto_append_lenenc_str(s, field->db ? field->db : "");
    network_mysqld_proto_append_lenenc_str(s, field->table ? field->table : "");
    network_mysqld_proto_append_lenenc_str(
        s, field->org_table ? field->org_table : "");
    network_mysqld_proto_append_lenenc_str(s, field->name ? field->name : "");
    network_mysqld_proto_append_lenenc_str(s, field->org_name ? field->org_name
                                                              : "");

    /* length of the following block, 12 byte */
    g_string_append_c(s, '\x0c');
    g_string_append_len(s, "\x08\x00", 2);              /* charset */
    g_string_append_c(s, (field->length >> 0) & 0xff);  /* len */
    g_string_append_c(s, (field->length >> 8) & 0xff);  /* len */
    g_string_append_c(s, (field->length >> 16) & 0xff); /* len */
    g_string_append_c(s, (field->length >> 24) & 0xff); /* len */
    g_string_append_c(s, field->type);                  /* type */
    g_string_append_c(s, field->flags & 0xff);          /* flags */
    g_string_append_c(s, (field->flags >> 8) & 0xff);   /* flags */
    g_string_append_c(s, 0);                            /* decimals */
    g_string_append_len(s, "\x00\x00", 2);              /* filler */
    network_mysqld_queue_append(con, con->send_queue, S(s));
  }

  g_string_truncate(s, 0);

  /* EOF */
  g_string_append_len(s, "\xfe", 1);     /* EOF */
  g_string_append_len(s, "\x00\x00", 2); /* warning count */
  g_string_append_len(s, "\x02\x00", 2); /* flags */

  network_mysqld_queue_append(con, con->send_queue, S(s));

  for (i = 0; i < rows->len; i++) {
    GPtrArray *row = rows->pdata[i];

    g_string_truncate(s, 0);

    for (j = 0; j < row->len; j++) {
      network_mysqld_proto_append_lenenc_str(s, row->pdata[j]);
    }

    network_mysqld_queue_append(con, con->send_queue, S(s));
  }

  g_string_truncate(s, 0);

  /* EOF */
  g_string_append_len(s, "\xfe", 1);     /* EOF */
  g_string_append_len(s, "\x00\x00", 2); /* warning count */
  g_string_append_len(s, "\x02\x00", 2); /* flags */

  network_mysqld_queue_append(con, con->send_queue, S(s));
  network_mysqld_queue_reset(con);

  g_string_free(s, TRUE);

  return 0;
}

int network_mysqld_con_send_current_date(network_socket *con, char *name) {
  GPtrArray *fields = network_mysqld_proto_fielddefs_new();

  MYSQL_FIELD *field = network_mysqld_proto_fielddef_new();
  field->name = name;
  field->type = MYSQL_TYPE_VAR_STRING;
  g_ptr_array_add(fields, field);

  char date[32] = {0};
  time_t tepoch = time(0);
  struct tm tsep = {0};
  localtime_r(&tepoch, &tsep);
  strftime(date, sizeof(date), "%Y-%m-%d", &tsep);

  GPtrArray *rows = g_ptr_array_new_with_free_func(
      (void *)network_mysqld_mysql_field_row_free);
  GPtrArray *row = g_ptr_array_new();
  g_ptr_array_add(row, date);
  g_ptr_array_add(rows, row);

  network_mysqld_con_send_resultset(con, fields, rows);

  network_mysqld_proto_fielddefs_free(fields);
  g_ptr_array_free(rows, TRUE);

  return 0;
}

int network_mysqld_con_send_cetus_version(network_socket *con) {
  GPtrArray *fields = g_ptr_array_new_with_free_func(
      (void *)network_mysqld_proto_fielddef_free);
  MYSQL_FIELD *field = network_mysqld_proto_fielddef_new();
  field->name = g_strdup("cetus version");
  field->type = MYSQL_TYPE_VAR_STRING;
  g_ptr_array_add(fields, field);

  char version[128] = {0};
#ifdef CHASSIS_BUILD_TAG
  snprintf(version, sizeof(version), "%s (build:%s)", PACKAGE_STRING,
           CHASSIS_BUILD_TAG);
#else
  strncpy(version, PACKAGE_STRING, sizeof(version));
#endif
  GPtrArray *rows = g_ptr_array_new_with_free_func(
      (void *)network_mysqld_mysql_field_row_free);
  GPtrArray *row = g_ptr_array_new();
  g_ptr_array_add(row, version);
  g_ptr_array_add(rows, row);

  network_mysqld_con_send_resultset(con, fields, rows);
  g_ptr_array_free(fields, TRUE);
  g_ptr_array_free(rows, TRUE);
  return 0;
}

static retval_t proxy_self_read_handshake(chassis *srv,
                                          server_connection_state_t *con) {
  /* server_connection_state_t *con */
  int err = 0;
  guint8 status = 0;
  network_packet packet;
  network_socket *recv_sock;
  network_mysqld_auth_challenge *challenge;

  recv_sock = con->server;

  packet.data = g_queue_peek_tail(recv_sock->recv_queue->chunks);
  packet.offset = 0;

  err = err || network_mysqld_proto_skip_network_header(&packet);
  if (err)
    return RET_ERROR;

  err = err || network_mysqld_proto_peek_int8(&packet, &status);
  if (err)
    return RET_ERROR;

  if (status == 0xff) {
    return RET_ERROR;
  }

  challenge = network_mysqld_auth_challenge_new();
  if (network_mysqld_proto_get_auth_challenge(&packet, challenge)) {
    g_string_free(g_queue_pop_tail(recv_sock->recv_queue->chunks), TRUE);

    network_mysqld_auth_challenge_free(challenge);

    return RET_ERROR;
  }

  if (!con->srv->client_found_rows) {
    challenge->capabilities &= ~(CLIENT_FOUND_ROWS);
  }

  if (!con->srv->compress_support) {
    challenge->capabilities &= ~(CLIENT_COMPRESS);
  }

  con->server->challenge = challenge;
  if (con->backend->server_version->len == 0) {
    g_string_append(con->backend->server_version,
                    challenge->server_version_str);
  }
  return RET_SUCCESS;
}

static retval_t proxy_self_create_kill_query(server_connection_state_t *con) {
  char buffer[32];

  GString *packet = g_string_sized_new(32);
  packet->len = NET_HEADER_SIZE;
  g_string_append_c(packet, (char)COM_QUERY);
  sprintf(buffer, "KILL QUERY %d", con->query_id_to_be_killed);
  g_string_append(packet, buffer);

  network_mysqld_proto_set_packet_len(packet, 1 + strlen(buffer));

  network_mysqld_proto_set_packet_id(packet, 0);

  g_queue_push_tail(con->server->send_queue->chunks, packet);

  return RET_SUCCESS;
}

static retval_t proxy_self_create_auth(chassis *srv,
                                       server_connection_state_t *con) {
  network_socket *send_sock = con->server;

  const network_mysqld_auth_challenge *challenge = send_sock->challenge;
  network_mysqld_auth_response *auth =
      network_mysqld_auth_response_new(challenge->capabilities);

  auth->client_capabilities = CETUS_DEFAULT_FLAGS;

  if (srv->is_back_compressed) {
    auth->client_capabilities |= CLIENT_COMPRESS;
  }

  if (send_sock->default_db->len == 0) {
    auth->client_capabilities &= ~CLIENT_CONNECT_WITH_DB;
  }
  if (!srv->client_found_rows) {
    auth->client_capabilities &= ~CLIENT_FOUND_ROWS;
  }
  auth->client_capabilities &= ~CLIENT_PLUGIN_AUTH;

  auth->max_packet_size = 0x01000000;
  auth->charset = con->charset_code;
  con->is_multi_stmt_set = 1;
  g_debug("%s:set multi stmt true for con:%p", G_STRLOC, con);

  g_string_truncate(auth->auth_plugin_data, 0);
  network_mysqld_proto_password_scramble(auth->auth_plugin_data,
                                         S(challenge->auth_plugin_data),
                                         S(con->hashed_pwd));

  g_string_append_len(auth->database, S(send_sock->default_db));
  g_string_assign_len(auth->username, S(send_sock->username));
  g_debug("%s:username: %s ", G_STRLOC, send_sock->username->str);

  GString *packet = g_string_new(NULL);
  network_mysqld_proto_append_auth_response(packet, auth);
  send_sock->last_packet_id = 0;
  network_mysqld_queue_append(send_sock, send_sock->send_queue, S(packet));
  g_string_free(packet, TRUE);

  send_sock->response = auth;
  return RET_SUCCESS;
}

server_connection_state_t *network_mysqld_self_con_init(chassis *srv) {
  server_connection_state_t *con;

  con = g_new0(server_connection_state_t, 1);

  con->srv = srv;
  con->server = network_socket_new();
  con->state = ST_ASYNC_CONN;
  con->hashed_pwd = g_string_new(0);

  return con;
}

void network_mysqld_self_con_free(server_connection_state_t *con) {
  if (!con)
    return;

  if (con->server) {
    network_socket_send_quit_and_free(con->server);
    g_debug("%s: connection server free:%p", G_STRLOC, con);
    con->server = NULL;
  } else {
    g_debug("%s: connections server is null:%p", G_STRLOC, con);
  }
  g_string_free(con->hashed_pwd, TRUE);
  g_debug("%s: connections free :%p", G_STRLOC, con);

  g_free(con);
}

#define ASYNC_WAIT_FOR_EVENT(sock, ev_type, timeout, user_data)                \
  event_set(&(sock->event), sock->fd, ev_type, network_mysqld_self_con_handle, \
            user_data);                                                        \
  chassis_event_add_with_timeout(srv, &(sock->event), timeout);

static int process_self_event(server_connection_state_t *con, int events,
                              int event_fd) {
  g_debug("%s:events:%d, ev:%p, state:%d", G_STRLOC, events,
          (&con->server->event), con->state);
  if (events == EV_READ) {
    g_debug("%s:EV_READ, ev:%p, state:%d", G_STRLOC, (&con->server->event),
            con->state);
    int b = -1;
    if (ioctl(con->server->fd, FIONREAD, &b)) {
      g_warning("ioctl(%d, FIONREAD, ...) failed: %s", event_fd,
                strerror(errno));
      con->state = ST_ASYNC_ERROR;
    } else if (b != 0) {
      con->server->to_read = b;
    } else {
      if (errno == 0 || errno == EWOULDBLOCK) {
        return 0;
      } else {
        g_warning(
            "%s:ERROR EV_READ errno=%d error:%s, state:%d, con:%p, server:%p",
            G_STRLOC, errno, strerror(errno), con->state, con, con->server);
        con->state = ST_ASYNC_ERROR;
      }
    }
  } else if (events == EV_TIMEOUT) {
    g_debug("%s:timeout, ev:%p, state:%d", G_STRLOC, (&con->server->event),
            con->state);
    if (con->state == ST_ASYNC_CONN) {
      g_message("%s: self conn timeout, state:%d, con:%p, server:%p", G_STRLOC,
                con->state, con, con->server);
      con->state = ST_ASYNC_ERROR;
      if (con->backend->type != BACKEND_TYPE_RW) {
        if (con->srv->disable_threads) {
          con->backend->state = BACKEND_STATE_DOWN;
          g_get_current_time(&(con->backend->state_since));
          g_critical("%s: set backend:%p down", G_STRLOC, con->backend);
        }
      } else {
        g_critical("%s: get conn timeout from master", G_STRLOC);
      }
    }
  }

  return 1;
}

static int process_self_server_read(server_connection_state_t *con) {
  chassis *srv = con->srv;
  switch (network_mysqld_read(con->srv, con->server)) {
  case NETWORK_SOCKET_SUCCESS:
    g_debug("%s:NETWORK_SOCKET_SUCCESS here:%d", G_STRLOC, con->state);
    break;
  case NETWORK_SOCKET_WAIT_FOR_EVENT: {
    g_debug("%s:NETWORK_SOCKET_WAIT_FOR_EVENT:%d here", G_STRLOC,
            con->retry_cnt);
    con->retry_cnt++;
    if (!con->query_id_to_be_killed) {
      if (con->retry_cnt >= MAX_TRY_NUM) {
        con->state = ST_ASYNC_ERROR;
        break;
      }
    }
    struct timeval timeout;
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    g_debug("%s: set timeout:%d for new conn:%p", G_STRLOC, (int)timeout.tv_sec,
            con);
    /* call us again when you have a event */
    ASYNC_WAIT_FOR_EVENT(con->server, EV_READ, &timeout, con);
    return 0;
  }
  case NETWORK_SOCKET_ERROR:
    g_warning("%s:plugin_call(ASYNC_READ_HANDSHAKE) error", G_STRLOC);
    con->state = ST_ASYNC_ERROR;
    break;
  default:
    g_warning("%s:unexpected state", G_STRLOC);
    con->state = ST_ASYNC_ERROR;
    break;
  }

  return 1;
}

static int process_self_read_auth_result(server_connection_state_t *con) {

  if (!process_self_server_read(con)) {
    return 0;
  }

  if (con->state == ST_ASYNC_ERROR) {
    g_warning("%s: con:%p auth failed,crazy here", G_STRLOC, con);
    return 1;
  }

  GString *packet = g_queue_peek_head(con->server->recv_queue->chunks);
  guchar type = packet->str[NET_HEADER_SIZE];
  switch (type) {
  case MYSQLD_PACKET_OK:
    break;
  case MYSQLD_PACKET_ERR:
    g_warning("%s: error send AUTH_RESULT: %02x", G_STRLOC,
              packet->str[NET_HEADER_SIZE]);
    con->state = ST_ASYNC_ERROR;
    break;
  case MYSQLD_PACKET_EOF:
    con->state = ST_ASYNC_ERROR;
    g_warning("%s: the MySQL 4.0 hash in a MySQL 4.1+ connection", G_STRLOC);
    break;
  default: {
    network_packet pkt;
    pkt.data = packet;
    pkt.offset = NET_HEADER_SIZE;
    network_mysqld_err_packet_t *err_packet;
    err_packet = network_mysqld_err_packet_new();
    if (!network_mysqld_proto_get_err_packet(&pkt, err_packet)) {
      g_warning("%s:READ_AUTH_RESULT:%d, server:%s, errinfo:%s", G_STRLOC, type,
                con->server->response->username->str, err_packet->errmsg->str);
    }
    network_mysqld_err_packet_free(err_packet);
    con->state = ST_ASYNC_ERROR;
    break;
  }
  }

  if (con->state != ST_ASYNC_ERROR) {
    con->backend->connected_clients--;
    g_debug("%s: connected_clients sub, now:%d for con:%p", G_STRLOC,
            con->backend->connected_clients, con);
    g_debug("%s: backend:%s, new connection:%p, query id:%d", G_STRLOC,
            con->backend->addr->name->str, con->server,
            con->query_id_to_be_killed);
    network_mysqld_queue_reset(con->server);
    network_queue_clear(con->server->recv_queue);
    con->server->is_multi_stmt_set = con->is_multi_stmt_set;
    if (con->srv->is_back_compressed) {
      con->server->do_compress = 1;
    }
    CHECK_PENDING_EVENT(&(con->server->event));
    if (con->query_id_to_be_killed) {
      con->state = ST_ASYNC_SEND_QUERY;
      return 1;
    } else {
      if (con->srv->server_conn_refresh_time <= con->server->create_time) {
        network_pool_add_idle_conn(con->pool, con->srv, con->server);
      } else {
        network_socket_send_quit_and_free(con->server);
        con->srv->complement_conn_flag = 1;
        g_message("%s: old connection for con:%p", G_STRLOC, con);
      }

      con->server = NULL; /* tell _self_con_free we succeed */
      network_mysqld_self_con_free(con);
      return 0;
    }
  }

  return 1;
}

static int process_self_read_query_result(server_connection_state_t *con) {

  if (!process_self_server_read(con)) {
    g_debug("%s:call process_self_server_read for con:%p", G_STRLOC, con);
    return 0;
  }

  g_debug("%s:after process_self_server_read for con:%p", G_STRLOC, con);
  GString *packet = g_queue_peek_head(con->server->recv_queue->chunks);
  guchar type = packet->str[NET_HEADER_SIZE];
  switch (type) {
  case MYSQLD_PACKET_OK:
    con->state = ST_ASYNC_OVER;
    break;
  case MYSQLD_PACKET_ERR:
    g_warning("%s: error read query result: %02x", G_STRLOC,
              packet->str[NET_HEADER_SIZE]);
    con->state = ST_ASYNC_ERROR;
    break;
  case MYSQLD_PACKET_EOF:
    con->state = ST_ASYNC_ERROR;
    g_warning("%s: the MySQL 4.0 hash in a MySQL 4.1+ connection", G_STRLOC);
    break;
  default: {
    network_packet pkt;
    pkt.data = packet;
    pkt.offset = NET_HEADER_SIZE;
    network_mysqld_err_packet_t *err_packet;
    err_packet = network_mysqld_err_packet_new();
    if (!network_mysqld_proto_get_err_packet(&pkt, err_packet)) {
      g_warning("%s:READ_AUTH_RESULT:%d, server:%s, errinfo:%s", G_STRLOC, type,
                con->server->response->username->str, err_packet->errmsg->str);
    }
    network_mysqld_err_packet_free(err_packet);
    con->state = ST_ASYNC_ERROR;
    break;
  }
  }

  return 1;
}

static void network_mysqld_self_con_handle(int event_fd, short events,
                                           void *user_data) {
  g_debug("%s:visit network_mysqld_self_con_handle", G_STRLOC);
  int ostate;
  server_connection_state_t *con = (server_connection_state_t *)user_data;
  chassis *srv = con->srv;

  if (!process_self_event(con, events, event_fd)) {
    return;
  }

  do {
    ostate = con->state;

    switch (con->state) {
    case ST_ASYNC_ERROR:
      con->backend->connected_clients--;
      g_debug("%s: connected_clients sub, now:%d for con:%p", G_STRLOC,
              con->backend->connected_clients, con);
      network_mysqld_self_con_free(con);
      return;
    case ST_ASYNC_CONN:
      switch (network_socket_connect_finish(con->server)) {
      case NETWORK_SOCKET_SUCCESS:
        if (con->srv->disable_threads) {
          if (con->backend->state != BACKEND_STATE_UP &&
              srv->group_replication_mode == 0) {
            con->backend->state = BACKEND_STATE_UP;
            g_get_current_time(&(con->backend->state_since));
            g_message(G_STRLOC ": set backend: %s (%p) up",
                      con->backend->addr->name->str, con->backend);
          }
        }
        con->state = ST_ASYNC_READ_HANDSHAKE;
        break;
      default:
        con->state = ST_ASYNC_ERROR;
        if (con->backend->type != BACKEND_TYPE_RW) {
          if (con->srv->disable_threads) {
            con->backend->state = BACKEND_STATE_DOWN;
            g_get_current_time(&(con->backend->state_since));
            g_critical(G_STRLOC ": set backend: %s (%p) down",
                       con->backend->addr->name->str, con->backend);
          }
        }
        break;
      }
      break;
    case ST_ASYNC_READ_HANDSHAKE:
      g_assert(events == 0 || event_fd == con->server->fd);

      g_debug("%s: ST_ASYNC_READ_HANDSHAKE for con:%p, connection %s and %s",
              G_STRLOC, con, con->server->src->name->str,
              con->server->dst->name->str);

      if (!process_self_server_read(con)) {
        return;
      }

      if (con->state == ST_ASYNC_ERROR) {
        break;
      }

      switch (proxy_self_read_handshake(srv, con)) {
      case RET_SUCCESS:
        break;
      default:
        con->state = ST_ASYNC_ERROR;
        g_warning("%s: ...", G_STRLOC);
        break;
      }

      if (con->state != ST_ASYNC_ERROR) {
        con->state = ST_ASYNC_SEND_AUTH;
      }
      break;
    case ST_ASYNC_SEND_AUTH:
      proxy_self_create_auth(srv, con);
      network_queue_clear(con->server->recv_queue);

      switch (network_mysqld_write(con->server)) {
      case NETWORK_SOCKET_SUCCESS:
        con->state = ST_ASYNC_READ_AUTH_RESULT;
        break;
      case NETWORK_SOCKET_WAIT_FOR_EVENT: {
        ASYNC_WAIT_FOR_EVENT(con->server, EV_WRITE, NULL, con);
        return;
      }
      case NETWORK_SOCKET_ERROR:
        con->state = ST_ASYNC_ERROR;
        break;
      default:
        g_warning("%s:unexpected state", G_STRLOC);
        break;
      }
      break;
    case ST_ASYNC_READ_AUTH_RESULT:
      if (!process_self_read_auth_result(con)) {
        return;
      }
      break;
    case ST_ASYNC_SEND_QUERY:
      g_debug("%s:call ST_ASYNC_SEND_QUERY for con:%p", G_STRLOC, con);
      proxy_self_create_kill_query(con);
      network_queue_clear(con->server->recv_queue);

      switch (network_mysqld_write(con->server)) {
      case NETWORK_SOCKET_SUCCESS:
        con->state = ST_ASYNC_READ_QUERY_RESULT;
        break;
      case NETWORK_SOCKET_WAIT_FOR_EVENT: {
        ASYNC_WAIT_FOR_EVENT(con->server, EV_WRITE, NULL, con);
        return;
      }
      case NETWORK_SOCKET_ERROR:
        con->state = ST_ASYNC_ERROR;
        break;
      default:
        g_warning("%s:unexpected state", G_STRLOC);
        break;
      }

      break;
    case ST_ASYNC_READ_QUERY_RESULT:
      process_self_read_query_result(con);
      break;
    case ST_ASYNC_OVER:
      con->backend->connected_clients--;
      CHECK_PENDING_EVENT(&(con->server->event));
      g_debug("%s: connected_clients sub, now:%d for con:%p", G_STRLOC,
              con->backend->connected_clients, con);
      network_mysqld_self_con_free(con);
      return;
    }

    event_fd = -1;
    events = 0;
  } while (ostate != con->state);

  return;
}

void network_connection_pool_create_conn(network_mysqld_con *con) {
  chassis *srv = con->srv;

  if (srv->maintain_close_mode) {
    return;
  }

  chassis_private *g = srv->priv;

  int i;
  char *username;

  g_debug("%s: call network_connection_pool_create_conn", G_STRLOC);

  if (con->client->response == NULL) {
    username = srv->default_username;
  } else {
    username = con->client->response->username->str;
  }

  if (!cetus_users_contains(g->users, username)) {
    g_message("%s: hashed password is null for user:%s", G_STRLOC, username);
    return;
  }

  time_t cur = time(0);

  int backends_count = network_backends_count(g->backends);
  for (i = 0; i < backends_count; i++) {
    network_backend_t *backend = network_backends_get(g->backends, i);
    if (backend != NULL) {

      if (backend->state != BACKEND_STATE_UP) {
        if (backend->state != BACKEND_STATE_UNKNOWN) {
          continue;
        }
        if (backend->last_check_time == cur) {
          g_debug("%s: omit create, backend:%d state:%d", G_STRLOC, i,
                  backend->state);
          continue;
        }
        backend->last_check_time = cur;
      } else {
        if (cur == backend->last_check_time) {
          continue;
        }
      }

      network_connection_pool *pool = backend->pool;
      int max_allowed_conn_num;
      if (backend->config) {
        if (pool->max_idle_connections > backend->config->max_conn_pool) {
          backend->config->max_conn_pool = pool->max_idle_connections;
          g_message("%s: set max conn pool size:%d", G_STRLOC,
                    backend->config->max_conn_pool);
        }
        max_allowed_conn_num = backend->config->max_conn_pool;
      } else {
        max_allowed_conn_num = pool->max_idle_connections;
      }

      int total = network_backend_conns_count(backend);
      g_debug("%s: backend ndx:%d total conn:%d, max allowed:%d", G_STRLOC, i,
              total, max_allowed_conn_num);

      if (total >= max_allowed_conn_num) {
        g_message("%s: backend ndx:%d reach max conn num:%d", G_STRLOC, i,
                  max_allowed_conn_num);
        backend->last_check_time = cur;
        continue;
      } else if (total >= pool->mid_idle_connections) {
        int idle_conn = total - backend->connected_clients;
        if (idle_conn > backend->connected_clients) {
          g_debug("%s: idle conn num is enough:%d, %d", G_STRLOC, idle_conn,
                  backend->connected_clients);
          continue;
        }
        int is_need_to_create = 0;
        switch (backend->type) {
        case BACKEND_TYPE_RW:
          if (con->master_conn_shortaged) {
            is_need_to_create = 1;
          } else {
            g_message("%s: master_conn_shortaged false", G_STRLOC);
          }
          break;
        case BACKEND_TYPE_RO:
          if (con->slave_conn_shortaged) {
            is_need_to_create = 1;
          } else {
            g_message("%s: slave_conn_shortaged false", G_STRLOC);
          }
          break;
        default:
          g_warning("%s: unknown type:%d", G_STRLOC, backend->type);
          break;
        }
        if (!is_need_to_create) {
          g_message("%s: is_need_to_create false", G_STRLOC);
          continue;
        }
      }

      server_connection_state_t *scs = network_mysqld_self_con_init(srv);

      g_debug("%s: create %s connection for backend ndx:%d, ptr:%p", G_STRLOC,
              username, i, backend);

      scs->charset_code = con->client->charset_code;
      if (srv->disable_dns_cache)
        network_address_set_address(scs->server->dst, backend->address->str);
      else
        network_address_copy(scs->server->dst, backend->addr);

      scs->pool = backend->pool;
      scs->backend = backend;
      cetus_users_get_hashed_server_pwd(con->srv->priv->users, username,
                                        scs->hashed_pwd);

      /*  Avoid the event base's time cache problems */
      scs->connect_timeout.tv_sec = 60;
      scs->connect_timeout.tv_usec = 0;

      g_string_append(scs->server->username, username);

      if (con->client->default_db && con->client->default_db->len > 0) {
        g_string_append(scs->server->default_db, con->client->default_db->str);
        g_debug("%s:set server default db:%s for con:%p", G_STRLOC,
                scs->server->default_db->str, con);
      }

      scs->backend->connected_clients++;
      g_debug("%s: connected_clients add, backend ndx:%d, for server:%p, faked "
              "con:%p",
              G_STRLOC, i, scs->server, scs);

      switch (network_socket_connect(scs->server)) {
      case NETWORK_SOCKET_ERROR_RETRY: {
        scs->state = ST_ASYNC_CONN;
        struct timeval timeout = scs->connect_timeout;
        g_debug("%s: set timeout:%d for new conn", G_STRLOC,
                (int)scs->connect_timeout.tv_sec);
        ASYNC_WAIT_FOR_EVENT(scs->server, EV_WRITE, &timeout, scs);
        break;
      }
      case NETWORK_SOCKET_SUCCESS:
        if (scs->srv->disable_threads && backend->state != BACKEND_STATE_UP) {
          backend->state = BACKEND_STATE_UP;
          g_get_current_time(&(backend->state_since));
          g_message("%s: set backend:%p, ndx:%d up", G_STRLOC, backend, i);
        }
        ASYNC_WAIT_FOR_EVENT(scs->server, EV_READ, 0, scs);
        scs->state = ST_ASYNC_READ_HANDSHAKE;
        break;
      default:
        scs->backend->connected_clients--;
        if (scs->srv->disable_threads) {
          if (scs->backend->type != BACKEND_TYPE_RW) {
            backend->state = BACKEND_STATE_DOWN;
            g_message("%s: set backend ndx:%d down", G_STRLOC, i);
          }
          g_get_current_time(&(backend->state_since));
        }
        network_mysqld_self_con_free(scs);
        break;
      }
    }
  }
}

void network_connection_pool_create_conns(chassis *srv) {
  int i, j;
  chassis_private *g = srv->priv;

  int backends_count = network_backends_count(g->backends);
  for (i = 0; i < backends_count; i++) {
    network_backend_t *backend = network_backends_get(g->backends, i);
    if (backend != NULL) {
      if (backend->state != BACKEND_STATE_UP &&
          backend->state != BACKEND_STATE_UNKNOWN) {
        continue;
      }
      int allowd_conn_num = backend->config->mid_conn_pool;

      int total =
          backend->pool->cur_idle_connections + backend->connected_clients;

      if (total == 0) {
        if (backend->last_conn_num) {
          if (!backend->candidate_down) {
            g_warning(
                "%s: backend:%s has no active connections, candidate dead",
                G_STRLOC, backend->addr->name->str);
          }
          backend->candidate_down = 1;
        }
      } else {
        backend->candidate_down = 0;
      }

      backend->last_conn_num = total;
      if (total >= allowd_conn_num) {
        continue;
      }

      allowd_conn_num = allowd_conn_num - total;

      if (allowd_conn_num > srv->connections_created_per_time) {
        allowd_conn_num = srv->connections_created_per_time;
      }

      if (allowd_conn_num > 0) {
        srv->is_need_to_create_conns = 1;
      }

      for (j = 0; j < allowd_conn_num; j++) {
        server_connection_state_t *scs = network_mysqld_self_con_init(srv);
        if (srv->disable_dns_cache)
          network_address_set_address(scs->server->dst, backend->address->str);
        else
          network_address_copy(scs->server->dst, backend->addr);

        scs->backend = backend;
        scs->pool = backend->pool;
        scs->charset_code = backend->config->charset;
        g_string_append(scs->server->username,
                        backend->config->default_username->str);
        cetus_users_get_hashed_server_pwd(g->users, scs->server->username->str,
                                          scs->hashed_pwd);

        scs->connect_timeout.tv_sec = 3;
        scs->connect_timeout.tv_usec = 0;

        if (backend->config->default_db &&
            backend->config->default_db->len > 0) {
          g_string_append(scs->server->default_db,
                          backend->config->default_db->str);
          g_debug("%s:set server default db:%s for con:%p", G_STRLOC,
                  scs->server->default_db->str, scs);
        }

        g_debug("%s: connected_clients add, backend ndx:%d, for server:%p, "
                "faked con:%p, charset:%d",
                G_STRLOC, i, scs->server, scs, scs->charset_code);

        scs->backend->connected_clients++;
        int create_err = 0;

        switch (network_socket_connect(scs->server)) {
        case NETWORK_SOCKET_ERROR_RETRY: {
          scs->state = ST_ASYNC_CONN;
          struct timeval timeout = scs->connect_timeout;
          ASYNC_WAIT_FOR_EVENT(scs->server, EV_WRITE, &timeout, scs);
          break;
        }
        case NETWORK_SOCKET_SUCCESS:
          if (scs->srv->disable_threads && backend->state != BACKEND_STATE_UP) {
            backend->state = BACKEND_STATE_UP;
            g_message("%s: set backend:%p, ndx:%d up", G_STRLOC, backend, i);
            g_get_current_time(&(backend->state_since));
          }
          ASYNC_WAIT_FOR_EVENT(scs->server, EV_READ, 0, scs);
          scs->state = ST_ASYNC_READ_HANDSHAKE;
          g_debug("%s: set backend conn:%p read handshake", G_STRLOC, scs);
          break;
        default:
          create_err = 1;
          scs->backend->connected_clients--;
          network_mysqld_self_con_free(scs);
          if (scs->srv->disable_threads) {
            if (scs->backend->type != BACKEND_TYPE_RW) {
              backend->state = BACKEND_STATE_DOWN;
              g_message("%s: set backend ndx:%d down, connected_clients sub",
                        G_STRLOC, i);
            }
            g_get_current_time(&(backend->state_since));
          }
          break;
        }

        if (create_err) {
          break;
        }
      }
    }
  }
}

void update_time_func(int fd, short what, void *arg) {
  chassis *chas = arg;

  chas->current_time = time(0);

  g_debug("%s: update time", G_STRLOC);
  struct timeval update_time_interval = {1, 0};
  chassis_event_add_with_timeout(chas, &chas->update_timer_event,
                                 &update_time_interval);
}

static void check_old_server_connection(gpointer data, gpointer user_data) {
  network_connection_pool_entry *entry = data;

  network_connection_pool_remove(entry);
  g_message("%s: call check_old_server_connection", G_STRLOC);
}

static void close_old_server_connetions(chassis *chas) {
  chas->current_time = time(0);
  chas->server_conn_refresh_time = chas->current_time;

  chassis_private *g = chas->priv;
  int i;
  int backends_count = network_backends_count(g->backends);
  for (i = 0; i < backends_count; i++) {
    network_backend_t *backend = network_backends_get(g->backends, i);
    if (backend != NULL) {
      if (backend->state != BACKEND_STATE_UP &&
          backend->state != BACKEND_STATE_UNKNOWN) {
        continue;
      }

      network_connection_pool *pool = backend->pool;
      GHashTable *users = pool->users;
      if (users != NULL) {
        GHashTableIter iter;
        GString *key;
        GQueue *queue;
        g_hash_table_iter_init(&iter, users);
        /* count all users' pooled connections */
        while (g_hash_table_iter_next(&iter, (void **)&key, (void **)&queue)) {
          g_queue_foreach(queue, check_old_server_connection, chas);
        }
      }
    }
  }
}

void check_and_create_conns_func(int fd, short what, void *arg) {
  chassis *chas = arg;

  if (chas->need_to_refresh_server_connections) {
    close_old_server_connetions(chas);
    chas->need_to_refresh_server_connections = 0;
    chas->is_need_to_create_conns = 1;
  }

  if (!chas->maintain_close_mode) {
    if (chas->is_need_to_create_conns) {
      chas->is_need_to_create_conns = 0;
      network_connection_pool_create_conns(chas);
    } else {
      if (chas->complement_conn_flag) {
        network_connection_pool_create_conns(chas);
        chas->complement_conn_flag = 0;
      }
    }
  }

  g_debug("%s: check_and_create_conns_func", G_STRLOC);
  struct timeval check_interval = {2, 0};
  chassis_event_add_with_timeout(chas, &chas->auto_create_conns_event,
                                 &check_interval);
}

