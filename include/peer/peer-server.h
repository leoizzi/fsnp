/*
 *  This file is part of fsnp.
 *
 *  fsnp is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  fsnp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with fsnp. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef FSNP_PEER_SERVER_H
#define FSNP_PEER_SERVER_H

#include <arpa/inet.h>
#include "fsnp/fsnp_types.h"

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Spawn a new thread for communicating with a server located in addr, asking
 * to it a list of superpeers
 */
void launch_query_server_sp(const struct sockaddr_in *addr);

/*
 * Contact the server used by the peer to join the P2P network for ask to add
 * this superpeer to its list.
 * Return 0 on success, -1 otherwise
 */
int add_sp_to_server(void);

/*
 * Remove this superpeer from the server's list
 */
void rm_sp_from_server(void);

/*
 * Establish a connection with the boot_server to remove a dead superpeer
 */
void rm_dead_sp_from_server(struct fsnp_peer *dead_sp);

FSNP_END_DECL

#endif //FSNP_PEER_SERVER_H
