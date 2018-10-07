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

#include <poll.h>
#include <memory.h>
#include <stdbool.h>

#include "peer/superpeer-peer.h"
#include "peer/superpeer.h"

#define READ_END 0
#define WRITE_END 1

#define SOCK 0
#define PIPE 1

#define POLLFD_NUM 2

/*
 * Fill the pollfd struct
 */
static void setup_poll(struct pollfd *pollfd, int p, int s)
{
	memset(pollfd, 0, sizeof(struct pollfd) * POLLFD_NUM);

	pollfd[SOCK].fd = s;
	pollfd[SOCK].events = POLLIN | POLLPRI;
	pollfd[PIPE].fd = p;
	pollfd[PIPE].events = POLLIN | POLLPRI;
}

void sp_tcp_thread(void *data)
{
	struct peer_info *info = (struct peer_info *)data;
	struct pollfd pollfd[POLLFD_NUM];
	bool should_exit = false;
	int ret = 0;

	setup_poll(pollfd, info->pipefd[READ_END], info->sock);
	while (!should_exit) {
		ret = poll(pollfd, POLLFD_NUM, -1);
		// TODO: continue from here
	}
}

#undef READ_END
#undef WRITE_END
#undef SOCK
#undef PIPE
#undef POLLFD_NUM