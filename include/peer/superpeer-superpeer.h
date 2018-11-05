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

#include "compiler.h"

#include "fsnp/fsnp_types.h"

FSNP_BEGIN_DECL

/*
 * Enter the superpeers' overlay network with the 'udp' socket.
 * If n == 0 the superpeer will know to be the first one in the network
 * If n == 1 in sps it will find the address of the peer who has promoted him
 * If n == 2 in sps it will find:
 *      - in the first position the address of the peer who has promoted him
 *      - in the second position the address of who will be his next
 * Return 0 on success, -1 otherwise
 */
int enter_sp_network(int udp, struct fsnp_peer *sps, unsigned n);

/*
 * Exit the superpeer's overlay network. The socket passed when entered will be
 * closed.
 */
void exit_sp_network(void);

FSNP_END_DECL

#endif //FSNP_SUPERPEER_SUPERPEER_H
