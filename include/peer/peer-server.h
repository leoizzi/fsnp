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

#ifndef FSNP_PEER_SERVER_H
#define FSNP_PEER_SERVER_H

#include <arpa/inet.h>
#include "fsnp/fsnp_types.h"

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Spawn a new thread for communicating with a server located in addr, asking
 * to it a list of superpeers
 */
void launch_query_server_sp(const struct sockaddr_in *addr);

FSNP_END_DECL

#endif //FSNP_PEER_SERVER_H
