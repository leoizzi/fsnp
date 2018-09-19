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

#ifndef FSNP_SERVER_SOCK_HANDLER_H
#define FSNP_SERVER_SOCK_HANDLER_H

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Handler for a socket event
 */
void server_socket_handler(int main_sock, short revents);

FSNP_END_DECL

#endif //FSNP_SERVER_SOCK_HANDLER_H
