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

#ifndef FSNP_PEER_MAIN_H
#define FSNP_PEER_MAIN_H

#include <stdbool.h>
#include <sys/socket.h>

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Main peer function
 */
int peer_main(bool localhost);

/*
 * Add to poll the peer socket
 */
void add_peer_sock(int sock);

/*
 * Get the peer's socket. If the socket is unset the function will return 0
 */
int get_peer_sock(void);

/*
 * Remove from the poll the peer's socket. The descriptor will be closed
 */
void rm_peer_sock(void);

/*
 * Add to poll the superpeer sockets
 */
void add_sp_socks(int udp_sock, int tcp_sock);

/*
 * Remove from the poll the superpeers socket. The descriptors will
 * be closed.
 */
void rm_sp_socks(void);

/*
 * Get the TCP superpeer's socket. If the socket is unset the function will
 * return 0
 */
int get_sp_tcp_sock(void);

/*
 * Get the UDP superpeer's socket. If the socket is unset the function will
 * return 0
 */
int get_sp_udp_sock(void);

/*
 * Return true if the peer is also a superpeer, false otherwise
 */
bool is_superpeer(void);

/*
 * Return true if the executable was started with the option --localhost, false
 * otherwise
 */
bool is_localhost(void);

/*
 * Get the superpeer TCP port used for communicating with the peers
 */
in_port_t get_tcp_sp_port(void);

/*
 * Set the superpeer TCP port used for communicating with the peers
 */
void set_tcp_sp_port(in_port_t port);

/*
 * Get the UDP port used for communicating with others superpeers
 */
in_port_t get_udp_sp_port(void);

/*
 * Set the UDP port used for communicating with others superpeers
 */
void set_udp_sp_port(in_port_t port);

/*
 * Exit the peer
 */
void quit_peer(void);

FSNP_END_DECL

#endif //FSNP_PEER_MAIN_H
