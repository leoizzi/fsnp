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

#ifndef FSNP_PEER_PEER_H
#define FSNP_PEER_PEER_H

#include "fsnp/fsnp_types.h"
#include "fsnp/sha-256.h"

/*
 * Handle an event on the download socket
 */
void dw_sock_event(short revents);

/*
 * Start a download session with 'peer' for file 'file_hash'
 */
void dw_from_peer(const struct fsnp_peer *peer, const char filename[FSNP_NAME_MAX]);

#endif //FSNP_PEER_PEER_H
