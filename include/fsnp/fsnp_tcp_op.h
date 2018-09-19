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

/*
 * This is only the peer/superpeer side of the library. The server part is
 * implemented in its own source code
 */

#ifndef FSNP_FSNP_OP_H
#define FSNP_FSNP_OP_H

#include <stdbool.h>
#include <sys/socket.h>
#include <stdint.h>

#include "fsnp/fsnp_types.h"
#include "fsnp/fsnp_err.h"
#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Create a TCP socket and bind it to a specific port, so that others
 * peers can connect to it.
 *
 * If the port passed as input was not available, but it was another, the port
 * used will be stored in 'port'
 */
EXPORT int fsnp_create_bind_tcp_sock(in_port_t *port, bool localhost);

/*
 * Create a TCP socket and connect it to a specific ip:port, so that it's
 * possible to start a communication with the given peer.
 *
 * NOTE: ip and port must be passed in little-endian format, as required by the
 * protocol. It is its job to do an endianness conversion when needed.
 */
EXPORT int fsnp_create_connect_tcp_sock(struct in_addr ip, in_port_t port);

/*
 * fsnp wrapper of read
 */
EXPORT ssize_t fsnp_read(int sock, void *buf, size_t bytes);

/*
 * fsnp wrapper of write
 */
EXPORT ssize_t fsnp_write(int sock, const void *buf, size_t bytes);

/*
 * fsnp wrapper of read with a timer associated.
 */
EXPORT ssize_t fsnp_timed_read(int sock, void *buf, size_t bytes,
							   uint16_t timeout, fsnp_err_t *err);

/*
 * fsnp wrapper of write with a timer associated. If the timer fires
 * FSNP_TIMED_OUT is returned
 */
EXPORT ssize_t fsnp_timed_write(int sock, const void *buf, size_t bytes,
                                uint16_t timeout, fsnp_err_t *err);

/*
 * Read an fsnp message from a TCP socket and return a pointer to it.
 * If an error occurs the return value is NULL
 * The timeout is expressed in ms. Passing 0 means that the function will use
 * the standard fsnp timeout
 * In r, on output, is saved how much bytes were read from the socket. If you
 * don't care about this value you can safely pass NULL
 *
 * The caller is responsible for the memory deallocation.
 */
EXPORT struct fsnp_msg *fsnp_read_msg_tcp(int sock, uint16_t timeout,
										  ssize_t *r, fsnp_err_t *err);

/*
 * Write an fsnp message to a TCP socket and return how many bites were written.
 * If an error occurs the return value is -1
 * The timeout is expressed in ms. Passing 0 means that the function will use
 * the standard fsnp timeout
 */
EXPORT ssize_t fsnp_write_msg_tcp(int sock, uint16_t timeout,
                                  const struct fsnp_msg *msg, fsnp_err_t *err);

FSNP_END_DECL

#endif //FSNP_FSNP_OP_H
