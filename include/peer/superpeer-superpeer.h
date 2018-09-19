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

FSNP_BEGIN_DECL

/*
 * Enter the superpeers' overlay network with the 'udp' socket.
 * Return 0 on success, -1 otherwise
 */
int enter_sp_network(int udp);

/*
 * Exit the superpeer's overlay network. The socket passed when entered will be
 * closed.
 */
void exit_sp_network(void);

FSNP_END_DECL

#endif //FSNP_SUPERPEER_SUPERPEER_H
