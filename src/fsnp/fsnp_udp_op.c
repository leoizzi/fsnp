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

#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <memory.h>
#include <unistd.h>
#include <limits.h>

#include "fsnp/fsnp.h"

int fsnp_create_udp_sock(void)
{
	int sock = 0;

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	return sock; // the caller will check for the error (if any)
}

int fsnp_create_bind_udp_sock(in_port_t *port, bool localhost)
{
	int sock = 0;
	int ret = 0;
	struct sockaddr_in addr;

	sock = fsnp_create_udp_sock();
	if (sock < 0) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (localhost) {
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	} else {
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	while (*port <= USHRT_MAX - 1) {
		addr.sin_port = htons(*port);
		ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
		if (!ret) {
			break;
		} else {
			(*port)++; // Let's try with another port
		}
	}

	/*
	 * If ret is still -1 when we're outside the loop the SO was unable to bind
	 * the socket.
	 */
	if (ret < 0) {
		close(sock);
		return -1;
	}

	return sock;
}