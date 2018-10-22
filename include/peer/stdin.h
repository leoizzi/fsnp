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

#ifndef FSNP_STDIN_H
#define FSNP_STDIN_H

#include <stdbool.h>
#include <arpa/inet.h>

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Initialize the stdin subsystem
 */
void init_stdin(void);

/*
 * Close the stdin subsystem
 */
void close_stdin(void);

/*
 * Handle a user request from the stdin
 */
void stdin_event(void);

/*
 * Called by others thread when they need the stdin, so that it is not possible
 * that the main thread can empty it for a mistake
 */
void block_stdin(void);

/*
 * Unlock the stdin for the main thread
 */
void release_stdin(void);

/*
 * Ask the user to give us an IP address and a port
 */
bool request_user_ip_port(struct sockaddr_in *addr);

FSNP_END_DECL

#endif //FSNP_STDIN_H
