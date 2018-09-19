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

#ifndef FSNP_FSNP_ERR_H
#define FSNP_FSNP_ERR_H

#include <limits.h>

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Error enum of fsnp.
 * Used in situations where multiple types of error can occur and a more
 * fine-grained error handling can be useful.
 *
 * E_ERRNO: check errno for the error
 * E_TIMEOUT: the connection's timer was fired
 * E_NOT_FSNP_MSG: what arrived on the socket wasn't a protocol message
 * E_OUT_OF_MEM: the system is out of memory
 */
enum fsnp_err {
	E_ERRNO = -1,
	E_TIMEOUT = -2,
	E_NOT_FSNP_MSG = -3,
	E_OUT_OF_MEM = -4,
	E_PEER_DISCONNECTED = -5,
	E_UNKNOWN = -INT_MAX
};

typedef enum fsnp_err fsnp_err_t;

/*
 * Utility function that prints on the standard error a message that explains
 * the error (of fsnp_err_t type) received by the system
 */
EXPORT void fsnp_print_err_msg(fsnp_err_t err);

FSNP_END_DECL

#endif //FSNP_FSNP_ERR_H
