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

#ifndef FSNP_PEER_SUPERPEER_H
#define FSNP_PEER_SUPERPEER_H

#include "fsnp/fsnp.h"
#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Ask the user which superpeer he wants to join, then join him
 */
void join_sp(const struct fsnp_query_res *query_res, bool auto_join);

/*
 * Send a message to the thread who's talking with the superpeer to search for
 * a file.
 * In filename put the name of the file, in size the size of filename
 */
void peer_ask_file(const char *filename, size_t size);

/*
 * Handler called when a FILE_RES msg is received.
 */
void file_res_rcvd(struct fsnp_file_res *file_res);

/*
 * If a file request is already in progress return true, otherwise false
 */
bool file_already_asked(void);

/*
 * Get the peer's socket. If the socket is unset the function will return 0
 */
int get_peer_sock(void);

/*
 * Tell the superpeer that the user is leaving and release all the resources
 * used
 */
void leave_sp(void);

FSNP_END_DECL

#endif //FSNP_PEER_SUPERPEER_H
