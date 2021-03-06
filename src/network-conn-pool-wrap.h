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

#ifndef __NETWORK_CONN_POOL_LUA_H__
#define __NETWORK_CONN_POOL_LUA_H__

#include "network-socket.h"
#include "network-mysqld.h"

#include "network-exports.h"

NETWORK_API int network_pool_add_conn(network_mysqld_con *con, int is_swap);
NETWORK_API int network_pool_add_idle_conn(network_connection_pool *pool, chassis *srv, network_socket *server);
NETWORK_API network_socket *network_connection_pool_swap(network_mysqld_con *con, int backend_ndx);

#endif
