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
	int pipefd[2];
	struct fsnp_peer addr;
	/* 'joined' is used to check if the peer has respected the protocol by
	 * sending a join message as first message. If not the superpeer will shut
	 * down the communication with him */
	bool joined;
	unsigned int timeouts;
	char pretty_addr[32]; // for printing and logging purposes
};

#define PIPE_WHOHAS 0
#define PIPE_QUIT 1
#define PIPE_PROMOTE 2
#define PIPE_FILE_RES 3

/*
 * Enter the superpeer mode.
 * Here will be done all the initializations steps needed for being a superpeer
 */
bool enter_sp_mode(struct fsnp_peer *sps, unsigned n);

/*
 * Exit the superpeer mode, freeing all the resources previously allocated.
 */
void exit_sp_mode(void);

/*
 * Respond to an event occurred on the TCP socket
 */
void sp_tcp_sock_event(short revents);

/*
 * Quit every peer connected to the superpeer
 */
void quit_all_peers(void);

/*
 * Tell the server lo remove us from its list and leave all the peers
 */
void prepare_exit_sp_mode(void);

/*
 * Remove the peer passed in input from the list of known peer.
 */
void rm_peer_from_list(struct fsnp_peer *peer);

FSNP_END_DECL

#endif //FSNP_SUPERPEER_H
