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

#include "network-backend.h"

#include <string.h>
#include <glib.h>

#include "chassis-plugin.h"
#include "glib-ext.h"
#include "network-mysqld-proto.h"
#include "character-set.h"
#include "cetus-util.h"
#include "cetus-users.h"

const char *backend_state_t_str[] = {"unknown", "online", "down", "maintaining",
                                     "deleted"};

const char *backend_type_t_str[] = {"unknown", "read/write", "readonly"};

network_backend_t *network_backend_new() {
  network_backend_t *b;

  b = g_new0(network_backend_t, 1);

  b->pool = network_connection_pool_new();
  b->addr = network_address_new();
  b->address = g_string_new(NULL);
  b->server_version = g_string_new(NULL);

  return b;
}

void network_backend_free(network_backend_t *b) {
  if (!b)
    return;

  network_connection_pool_free(b->pool);

  network_address_free(b->addr);
  g_string_free(b->server_version, TRUE);

  if (b->config) {
    if (b->config->default_username) {
      g_string_free(b->config->default_username, TRUE);
    }

    if (b->config->default_db) {
      g_string_free(b->config->default_db, TRUE);
    }

    g_free(b->config);
  }

  g_string_free(b->address, TRUE);
  g_debug("%s: call network_backend_free end", G_STRLOC);
  g_free(b);
}

int network_backend_init_extra(network_backend_t *b, chassis *chas) {
  if (chas->max_idle_connections != 0) {
    b->pool->max_idle_connections = chas->max_idle_connections;
  }

  if (chas->mid_idle_connections != 0) {
    b->pool->mid_idle_connections = chas->mid_idle_connections;
  }

  return 0;
}

int network_backend_conns_count(network_backend_t *b) {
  int in_use = b->connected_clients;
  int pooled = network_connection_pool_total_conns_count(b->pool);
  return in_use + pooled;
}

network_backends_t *network_backends_new() {
  network_backends_t *bs;

  bs = g_new0(network_backends_t, 1);

  bs->backends = g_ptr_array_new();
  return bs;
}

void network_backends_free(network_backends_t *bs) {
  gsize i;

  if (!bs)
    return;

  g_message("%s: call network_backends_free", G_STRLOC);

  for (i = 0; i < bs->backends->len; i++) {
    network_backend_t *backend = bs->backends->pdata[i];
    network_backend_free(backend);
  }
  g_ptr_array_free(bs->backends, TRUE);
  g_free(bs);
}

static void set_backend_config(network_backend_t *backend, chassis *srv) {
  if (!backend->config) {
    backend->config = g_new0(backend_config, 1);
  } else {
    if (backend->config->default_username) {
      g_string_free(backend->config->default_username, TRUE);
    }

    if (backend->config->default_db) {
      g_string_free(backend->config->default_db, TRUE);
    }
  }

  backend->config->default_username = g_string_new(NULL);
  g_string_append(backend->config->default_username, srv->default_username);

  if (srv->default_db != NULL && strlen(srv->default_db) > 0) {
    backend->config->default_db = g_string_new(NULL);
    g_string_append(backend->config->default_db, srv->default_db);
  }

  backend->config->charset = charset_get_number(srv->default_charset);

  backend->config->mid_conn_pool = srv->mid_idle_connections;
  backend->config->max_conn_pool = srv->max_idle_connections;
}

/*
 * FIXME: 1) remove _set_address, make this function callable with result of same
 *        2) differentiate between reasons for "we didn't add" (now -1 in all cases)
 */
int network_backends_add(network_backends_t *bs, const gchar *address,
                         backend_type_t type, backend_state_t state,
                         chassis *srv) {
  network_backend_t *new_backend = network_backend_new();
  new_backend->type = type;
  new_backend->state = state;
  new_backend->pool->srv = srv;

  g_string_assign(new_backend->address, address);

  if (0 != network_address_set_address(new_backend->addr,
                                       new_backend->address->str)) {
    network_backend_free(new_backend);
    return BACKEND_OPERATE_NETERR;
  }

  guint i;
  /* check if this backend is already known */
  for (i = 0; i < bs->backends->len; i++) {
    network_backend_t *old_backend = g_ptr_array_index(bs->backends, i);

    if (strleq(S(old_backend->addr->name), S(new_backend->addr->name))) {
      network_backend_free(new_backend);

      g_critical("backend %s is already known!", address);
      return BACKEND_OPERATE_DUPLICATE;
    }
  }

  if (type == BACKEND_TYPE_RW && network_backend_check_available_rw(bs)) {
    return BACKEND_OPERATE_2MASTER;
  }

  g_ptr_array_add(bs->backends, new_backend);
  if (type == BACKEND_TYPE_RO) {
    bs->ro_server_num += 1;
  }

  set_backend_config(new_backend, srv);
  srv->is_need_to_create_conns = 1;
  g_message("added %s backend: %s, state: %s", backend_type_t_str[type],
            address, backend_state_t_str[state]);

  return BACKEND_OPERATE_SUCCESS;
}

/**
 * we just change the state to deleted
 */
int network_backends_remove(network_backends_t *bs, guint index) {
  network_backend_t *b = bs->backends->pdata[index];
  if (b != NULL) {
    if (b->type == BACKEND_TYPE_RO && bs->ro_server_num > 0) {
      bs->ro_server_num -= 1;
    }

    return network_backends_modify(bs, index, BACKEND_TYPE_UNKNOWN,
                                   BACKEND_STATE_DELETED, NO_PREVIOUS_STATE);
  }
  return 0;
}

/**
 * updated the _DOWN state to _UNKNOWN if the backends were
 * down for at least 4 seconds
 *
 * we only check once a second to reduce the overhead on connection setup
 *
 * @returns   number of updated backends
 */
int network_backends_check(network_backends_t *bs) {
  GTimeVal now;
  guint i;
  int backends_woken_up = 0;
  gint64 t_diff;

  g_get_current_time(&now);
  ge_gtimeval_diff(&bs->backend_last_check, &now, &t_diff);

  /* check max(once a second) */
  /* this also covers the "time went backards" case */
  if (t_diff < G_USEC_PER_SEC) {
    if (t_diff < 0) {
      g_message("%s: time went backwards (%" G_GINT64_FORMAT " usec)!",
                G_STRLOC, t_diff);
      bs->backend_last_check.tv_usec = 0;
      bs->backend_last_check.tv_sec = 0;
    }
    return 0;
  }

  bs->backend_last_check = now;

  for (i = 0; i < bs->backends->len; i++) {
    network_backend_t *cur = bs->backends->pdata[i];

    if (cur->state != BACKEND_STATE_DOWN)
      continue;

    /* check if a backend is marked as down for more than 4 sec */
    if (now.tv_sec - cur->state_since.tv_sec > 4) {
      g_debug("%s: backend %s was down for more than 4 secs, waking it up",
              G_STRLOC, cur->addr->name->str);

      cur->state = BACKEND_STATE_UNKNOWN;
      cur->state_since = now;
      backends_woken_up++;
    }
  }

  return backends_woken_up;
}

/**
 * modify the backends to new type and new state.
 *
 * @returns   0 for success -1 for error.
 */

int network_backends_modify(network_backends_t *bs, guint ndx,
                            backend_type_t type, backend_state_t state,
                            backend_state_t oldstate) {
  GTimeVal now;
  g_get_current_time(&now);
  if (ndx >= network_backends_count(bs))
    return -1;

  network_backend_t *cur = bs->backends->pdata[ndx];

  guint is_change = 0;

  if (oldstate == NO_PREVIOUS_STATE) {
    oldstate = cur->state;
  }
  if (cur->state != state) {
    if (__sync_bool_compare_and_swap(&(cur->state), oldstate, state)) {
      cur->state_since = now;
      if (state == BACKEND_STATE_UP || state == BACKEND_TYPE_UNKNOWN) {
        if (cur->pool->srv) {
          chassis *srv = cur->pool->srv;
          srv->is_need_to_create_conns = 1;
        }
      }
      is_change++;
    } else {
      g_debug("there might be conflict, network_backends_modify failed.");
      return -1;
    }
  }

  if (cur->type != type) {
    cur->type = type;
    if (type == BACKEND_TYPE_RO) {
      bs->ro_server_num += 1;
    } else {
      bs->ro_server_num -= 1;
    }
    is_change++;
  }

  if (is_change) {
    g_message(
        "change backend: %s from type: %s, state: %s to type: %s, state: %s",
        cur->addr->name->str, backend_type_t_str[cur->type],
        backend_state_t_str[cur->state], backend_type_t_str[type],
        backend_state_t_str[state]);
  }

  g_debug("%s: backend state:%d for backend:%p", G_STRLOC, cur->state, cur);

  return 0;
}

network_backend_t *network_backends_get(network_backends_t *bs, guint ndx) {
  if (ndx >= network_backends_count(bs))
    return NULL;

  /* FIXME: shouldn't we copy the backend or add ref-counting ? */
  return bs->backends->pdata[ndx];
}

guint network_backends_count(network_backends_t *bs) {
  guint len;

  len = bs->backends->len;

  return len;
}

gboolean network_backends_load_config(network_backends_t *bs, chassis *srv) {
  if (!cetus_users_contains(srv->priv->users, srv->default_username)) {
    g_critical("%s: no required password here for user:%s", G_STRLOC,
               srv->default_username);
    return -1;
  }
  int i;
  int count = network_backends_count(bs);
  for (i = 0; i < count; i++) {
    network_backend_t *backend = network_backends_get(bs, i);
    if (backend) {
      set_backend_config(backend, srv);
    }
  }
  return 0;
}

/* round robin choose read only backend */
int network_backends_get_ro_ndx(network_backends_t *bs)
{
  GArray *active_ro_indices = g_array_sized_new(FALSE, TRUE, sizeof(int), 4);
  int count = network_backends_count(bs);
  int i = 0;
  for (i = 0; i < count; i++) {
    network_backend_t *backend = network_backends_get(bs, i);
    if ((backend->type == BACKEND_TYPE_RO) &&
        (backend->state == BACKEND_STATE_UP ||
         backend->state == BACKEND_STATE_UNKNOWN)) {
      g_array_append_val(active_ro_indices, i);
    }
  }
  int num = active_ro_indices->len;
  int result = -1;
  if (num > 0) {
    result = g_array_index(active_ro_indices, int, (bs->read_count++) % num);
  }
  g_array_free(active_ro_indices, TRUE);
  return result;
}

int network_backends_get_rw_ndx(network_backends_t *bs) {
  int i = 0;
  int count = network_backends_count(bs);
  for (i = 0; i < count; i++) {
    network_backend_t *backend = network_backends_get(bs, i);
    if ((BACKEND_TYPE_RW == backend->type) &&
        (backend->state == BACKEND_STATE_UP ||
         backend->state == BACKEND_STATE_UNKNOWN)) {
      break;
    }
  }
  return i < count ? i : -1;
}

int network_backends_find_address(network_backends_t *bs, const char *ipport) {
  int count = network_backends_count(bs);
  int i = 0;
  for (i = 0; i < count; i++) {
    network_backend_t *backend = network_backends_get(bs, i);
    if (strcmp(backend->addr->name->str, ipport) == 0) {
      return i;
    }
  }
  return -1;
}

void network_backends_server_version(network_backends_t *bs, GString* version)
{
  network_backend_t *b = network_backends_get(bs, 0);
  if (b)
    g_string_assign_len(version, b->server_version->str,
                        b->server_version->len);
}

int network_backends_idle_conns(network_backends_t *bs) {
  int sum = 0;
  int count = network_backends_count(bs);
  int i;
  for (i = 0; i < count; i++) {
    network_backend_t *b = network_backends_get(bs, i);
    int pooled = network_connection_pool_total_conns_count(b->pool);
    sum += pooled;
  }
  return sum;
}

int network_backends_used_conns(network_backends_t *bs) {
  int sum = 0;
  int count = network_backends_count(bs);
  int i;
  for (i = 0; i < count; i++) {
    network_backend_t *b = network_backends_get(bs, i);
    int in_use = b->connected_clients;
    sum += in_use;
  }
  return sum;
}

int network_backend_check_available_rw(network_backends_t *bs) {
  int i = 0;
  int count = network_backends_count(bs);
  for (i = 0; i < count; i++) {
    network_backend_t *backend = network_backends_get(bs, i);
    if ((BACKEND_TYPE_RW == backend->type) &&
        backend->state != BACKEND_STATE_MAINTAINING &&
        backend->state != BACKEND_STATE_DELETED) {
      break;
    }
  }
  return i < count ? 1 : 0;
}
