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

#ifndef FSNP_SUPERPEER_SUPERPEER_H
#define FSNP_SUPERPEER_SUPERPEER_H

#include <stdbool.h>

#include "compiler.h"

#include "peer/neighbors.h"

#include "fsnp/fsnp_types.h"
#include "fsnp/sha-256.h"

#include "struct/linklist.h"
#include "struct/hashtable.h"

FSNP_BEGIN_DECL

struct sp_udp_state {
	int sock;
	int r_pipe[2];
	int w_pipe[2];
	struct neighbors *nb;
	struct timespec last;
	hashtable_t *reqs; // key: sha256_t     value: request
	linked_list_t *pending_msgs;
	bool wait_snd_res;
	bool next_validated;
	bool should_exit;
};

struct sender {
	struct fsnp_peer addr;
	char pretty_addr[32];
};

/*
 * Enter the superpeers' overlay network with the 'udp' socket.
 * If n == 0 the superpeer will know to be the first one in the network
 * If n == 1 in sps it will find the address of the peer who has promoted him
 * If n == 2 in sps it will find:
 *      - in the first position the address of the peer who has promoted him
 *      - in the second position the address of the prev of its promoter
 * Return 0 on success, -1 otherwise
 */
int enter_sp_network(int udp, const struct fsnp_peer *sps, unsigned n);

/*
 * Send a NEXT msg to the next sp. Pass NULL in 'old' if the next doesn't have
 * to change its next.
 */
void send_next(const struct sp_udp_state *sus, const struct fsnp_peer *old);

/*
 * Send a WHOHAS msg.
 * If next is true this message will be sent to the next, otherwise will be sent
 * to the peer who has started the request.
 */
void send_whohas(const struct sp_udp_state *sus,const struct fsnp_whohas *whohas,
                 bool next);

/*
 * Send a WHOSNEXT msg to s
 */
void send_whosnext(const struct sp_udp_state *sus,
                   const struct fsnp_whosnext *whosnext, const struct sender *s);

/*
 * Ask in the overlay network who has a file
 */
int ask_whohas(const sha256_t file_hash, const struct fsnp_peer *requester);

/*
 * Get a copy of the prev's address. The address is to be considered valid
 * only if the function has returned true.
 * This is done so that we don't get a copy of this superpeer's address in case
 * it doesn't have a prev.
 */
bool get_prev_addr(struct fsnp_peer *prev);

struct sp_nb_addr {
	char self[32];
	char prev[32];
	char next[32];
	char snd_next[32];
};

/*
 * Ask to the superpeer's thread a copy of all the sp addresses he knows as
 * string
 */
int get_neighbors_addresses(struct sp_nb_addr *sna);

/*
 * Exit the superpeer's overlay network. The socket passed when entered the
 * network will be closed.
 */
void exit_sp_network(void);

FSNP_END_DECL

#endif //FSNP_SUPERPEER_SUPERPEER_H
