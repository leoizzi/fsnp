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

/*
 * Server side implementation of the fsnp protocol
 */

#ifndef FSNP_SERVER_FSNP_H
#define FSNP_SERVER_FSNP_H

#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "compiler.h"
#include "fsnp/fsnp_types.h"

FSNP_BEGIN_DECL

#define FSNP_BACKLOG 128

struct fsnp_server_sp {
	struct in_addr addr;
	in_port_t p_port;
	in_port_t sp_port;
};

FSNP_END_DECL

#endif //FSNP_SERVER_FSNP_H
