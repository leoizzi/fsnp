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
#include <stdio.h>

#include "compiler.h"

#include "fsnp/fsnp_types.h"

FSNP_BEGIN_DECL

#define PRINT_PEER printf("\nPeer: "); fflush(stdout)

/*
 * Main peer function
 */
int peer_main(bool localhost);

/*
 * Add to poll the superpeer TCP socket
 */
void add_poll_sp_sock(int tcp_sock);

/*
 * Remove from the poll the superpeer's socket. The descriptor will
 * be closed.
 */
void rm_poll_sp_sock(void);

/*
 * Get the TCP superpeer's socket. If the socket is unset the function will
 * return 0
 */
int get_tcp_sp_sock(void);

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
 * Get the download port
 */
in_port_t get_dw_port(void);

/*
 * Set the download port
 */
void set_dw_port(in_port_t dw_port);

/*
 * Set the address of the last bootstrap server contacted by the peer.
 */
void set_server_addr(const struct fsnp_peer *addr);

/*
 * Get the address of the last bootstrap server contacted by the peer.
 * If the address and the port are all set to 0 no server is known
 */
void get_server_addr(struct fsnp_peer *addr);

/*
 * Set the IP address of this peer (in little endian format)
 */
void set_peer_ip(in_addr_t peer_ip);

/*
 * Get the IP address of this peer (in little endian format)
 */
in_addr_t get_peer_ip(void);

/*
 * Exit the peer
 */
void quit_peer(void);

FSNP_END_DECL

#endif //FSNP_PEER_MAIN_H
