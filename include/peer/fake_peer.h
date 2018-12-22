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

#include "peer/superpeer.h"

#ifndef FSNP_FAKE_PEER_H
#define FSNP_FAKE_PEER_H

/*
 * Create the fake peer.
 */
struct peer_info *create_fake_peer_info(void);

/*
 * Entry point for the fake-peer-info thread
 */
void fake_peer_info_thread(void *data);

/*
 * Tell to the fake peer thread that the user wants to search for a file
 *
 * In filename put the name of the file, in size the size of filename
 */
void fake_peer_ask_file(struct peer_info *fake_peer, const char *filename,
                        size_t size);

#endif //FSNP_FAKE_PEER_H
