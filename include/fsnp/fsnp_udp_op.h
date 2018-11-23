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
#include <stdint.h>

#include "fsnp/fsnp_types.h"
#include "fsnp/fsnp_err.h"

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Maximum size, in bytes, for a fsnp_msg going over UDP.
 * The reason behind this number is that it's a must to avoid packet fragmentation,
 * otherwise UDP would discard the packet, and in the protocol there isn't any
 * mechanism of retransmission.
 *
 * So, in order to avoid fragmentation, a packet can have (at limit) a size of 508
 * bytes (572 is the maximum packet size that can be atomically sent, -60 bytes
 * used by a full-optional IP packet, -8 bytes used by UDP).
 *
 * Why the protocol doesn't limit the packet size to 508 bytes then?
 * Because it's useless! The biggest packet that the protocol would send over
 * UDP is a
 */
#define MAX_UDP_PKT_SIZE 256

/*
 * Create a UDP socket
 */
EXPORT int fsnp_create_udp_sock(void);

/*
 * Create a UDP socket and bind it to a specific port, so that others host can
 * send messages to it
 */
EXPORT int fsnp_create_bind_udp_sock(in_port_t *port, bool localhost);

/*
 * fsnp wrapper for sendto. The timeout is expressed in ms. If 0 is passed the
 * standard fsnp timeout will be used
 */
EXPORT fsnp_err_t fsnp_sendto(int sock, const struct fsnp_msg *msg,
							  const struct fsnp_peer *peer);

/*
 * fsnp wrapper for recvfrom
 */
EXPORT struct fsnp_msg *fsnp_recvfrom(int sock, struct fsnp_peer *peer,
									  fsnp_err_t *err);

/*
 * fsnp wrapper for sendto with a timer associated.
 * The timeout is expressed in ms. If 0 is passed the standard fsnp timeout will
 * be used.
 */
EXPORT fsnp_err_t fsnp_timed_sendto(int sock, uint16_t timeout,
									const struct fsnp_msg *msg,
									const struct fsnp_peer *peer);

/*
 * fsnp wrapper for recvfrom with a timer associated.
 * The timeout is expressed in ms. If 0 is passed the standard fsnp timeout will
 * be used.
 * If backoff is true the function will perform a backoff algorithm in
 * case the timeout fires. The backoff will be performed for 4 times before
 * returning to the caller
 */
EXPORT struct fsnp_msg *fsnp_timed_recvfrom(int sock, uint16_t timeout, struct fsnp_peer *peer,
                                            fsnp_err_t *err);

/*
 * Send an ACK msg to 'peer'
 */
EXPORT fsnp_err_t fsnp_send_udp_ack(int sock, uint16_t timeout,
									const struct fsnp_ack *ack,
									const struct fsnp_peer *peer);
/*
 * Send a LEAVE msg to 'peer'
 */
EXPORT fsnp_err_t fsnp_send_udp_leave(int sock, uint16_t timeout,
                                      const struct fsnp_leave *leave,
                                      const struct fsnp_peer *peer);

/*
 * Send a PROMOTED msg to 'peer'
 */
EXPORT fsnp_err_t fsnp_send_promoted(int sock, uint16_t timeout,
                                     const struct fsnp_promoted *promoted,
                                     const struct fsnp_peer *peer);

/*
 * Send a NEXT msg to 'peer'
 */
EXPORT fsnp_err_t fsnp_send_next(int sock, uint16_t timeout,
                                 const struct fsnp_next *next,
                                 const struct fsnp_peer *peer);

/*
 * Send a WHOSNEXT msg to 'peer'
 */
EXPORT fsnp_err_t fsnp_send_whosnext(int sock, uint16_t timeout,
                                     const struct fsnp_whosnext *whosnext,
                                     const struct fsnp_peer *peer);

EXPORT fsnp_err_t fsnp_send_whohas(int sock, uint16_t timeout,
								   const struct fsnp_whohas *whohas,
								   const struct fsnp_peer *peer);
FSNP_END_DECL

#endif //FSNP_FSNP_UDP_OP_H
