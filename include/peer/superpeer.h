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

#ifndef FSNP_SUPERPEER_H
#define FSNP_SUPERPEER_H

#include <stdbool.h>
#include <arpa/inet.h>

#include "fsnp/fsnp.h"

#include "compiler.h"

FSNP_BEGIN_DECL

struct peer_info {
	int sock;
	struct fsnp_peer addr;
};

/*
 * Enter the superpeer mode.
 * Here will be done all the initializations steps needed for being a superpeer
 */
bool enter_sp_mode(void);

/*
 * Exit the superpeer mode, freeing all the resources previously allocated.
 */
void exit_sp_mode(void);

/*
 * Respond to an event occurred on the TCP socket
 */
void sp_tcp_sock_event(short revents);

/*
 * Respond to an event occurred on the UDP socket
 */
void sp_udp_sock_event(short revents);

FSNP_END_DECL

#endif //FSNP_SUPERPEER_H
