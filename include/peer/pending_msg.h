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

#ifndef FSNP_PENDING_MSG_H
#define FSNP_PENDING_MSG_H

#include <stdbool.h>
#include <time.h>

#include "peer/superpeer-superpeer.h"

#include "fsnp/fsnp_types.h"

union pending_func {
	void (*next)(const struct sp_udp_state *sus, const struct fsnp_peer *next);
	void (*whohas)(const struct sp_udp_state *sus, const struct fsnp_whohas *whohas,
	               bool next);
};

struct pending_whohas {
	struct fsnp_whohas whohas;
	bool send_to_next;
};

union pending_func_data {
	struct fsnp_peer old_peer; // if set to 0 will be considered as NULL
	struct pending_whohas pw;
};

struct pending_msg {
	fsnp_type_t type; // type of the msg sent
	fsnp_type_t expected; // type expected of the msg sent by the sp
	struct fsnp_peer sp;
	char pretty_addr[32];
	struct timespec last_send;
	unsigned retry;
	union pending_func f;
	union pending_func_data pfd;
};

/*
 * Free callback for pending_msgs linked list
 */
void free_pending_msg(void *data);

/*
 * Add a next pending_msg to the list
 */
void add_pending_next(struct sp_udp_state *sus, const struct fsnp_peer *sp,
                      const struct fsnp_peer *old_next);

/*
 * Add a whohas pending_msg to the list
 */
void add_pending_whohas(struct sp_udp_state *sus, const struct fsnp_peer *sp,
                        const struct fsnp_whohas *whohas, bool send_to_next);

/*
 * Look if the message received is pending. If so remove it from the list of
 * pending msgs.
 */
void is_pending(struct sp_udp_state *sus, struct fsnp_msg *msg,
                struct sender *sender);

/*
 * Look if a pending_request has timed out. If has timeout less than 4 times try
 * to send the message again, otherwise remove it from the list and handle this
 * failure accordingly to its time
 */
void check_pm_timeout(struct sp_udp_state *sus);

#endif //FSNP_PENDING_MSG_H
