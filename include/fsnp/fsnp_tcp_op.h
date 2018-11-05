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
 * fsnp wrapper of write with a timer associated.
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



/*
 * From now on the are some convenience functions for sending to another peer
 * standard messages. They all use the standard fsnp timeout. If a different
 * timeout is needed use fsnp_write_msg_tcp instead.
 */

/*
 * Send a query message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_query(int sock, const struct fsnp_query *query);

/*
 * Send a query_res message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_query_res(int sock,
									  const struct fsnp_query_res *query_res);
/*
 * Send an add_sp message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_add_sp(int sock, const struct fsnp_add_sp *add_sp);

/*
 * Send a rm_sp message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_rm_sp(int sock, const struct fsnp_rm_sp *rm_sp);

/*
 * Send a join message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_join(int sock, const struct fsnp_join *join);

/*
 * Send an ack message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_tcp_ack(int sock, const struct fsnp_ack *ack);

/*
 * Send a leave message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_tcp_leave(int sock, const struct fsnp_leave *leave);

/*
 * Send a file_req message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_file_req(int sock, const struct fsnp_file_req *req);

/*
 * Send a file_res message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_file_res(int sock, const struct fsnp_file_res *res);

/*
 * Send an update message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_update(int sock, const struct fsnp_update *update);

/*
 * Send an alive message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_tcp_alive(int sock, const struct fsnp_alive *alive);

/*
 * Send a get_file message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_get_file(int sock,
                                     const struct fsnp_get_file *get_file);

/*
 * Send an error message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_error(int sock, const struct fsnp_error *error);

/*
 * Send a download message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_download(int sock,
                                     const struct fsnp_download *download);

/*
 * Send a promote message.
 * Return an fsnp_err_t indicating the success or the failure
 */
EXPORT fsnp_err_t fsnp_send_promote(int sock,
                                    const struct fsnp_promote *promote);

FSNP_END_DECL

#endif //FSNP_FSNP_OP_H
