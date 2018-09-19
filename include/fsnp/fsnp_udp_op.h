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

#ifndef FSNP_FSNP_UDP_OP_H
#define FSNP_FSNP_UDP_OP_H

#include <stdbool.h>
#include <sys/socket.h>

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Create a UDP socket
 */
EXPORT int fsnp_create_udp_sock(void);

/*
 * Create a UDP socket and bind it to a specific port, so that others host can
 * send messages to it
 */
EXPORT int fsnp_create_bind_udp_sock(in_port_t *port, bool localhost);

FSNP_END_DECL

#endif //FSNP_FSNP_UDP_OP_H
