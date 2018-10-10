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

static bool should_exit = false;

/*
 * Read a message on the pipe and:
 * - if is a PIPE_PROMOTE message promote the peer
 * - if is a PIPE_QUIT message tell the peer we're leaving
 */
static void read_pipe_msg(struct peer_info *info)
{
	ssize_t r = 0;
	int msg = 0;
	struct fsnp_promote promote;

	r = fsnp_read(info->pipefd[READ_END], &msg, sizeof(int));
	if (r < 0) {
		/* something wrong happened in the pipe, it's likely possible that the
		 * thread will not be able to communicate with the main thread again.
		 * Let's quit */
		should_exit = true;
		return;
	}

	if (msg == PIPE_PROMOTE) {
		// TODO: promote the peer. Before going on here the superpeer-superpeer file has to be completed, since we need to communicate to the peer who's being promoted other sps' addresses
	} else { // msg = PIPE_QUIT
		should_exit = true;
	}
}

/*
 * Handle an event on the pipe
 */
static void pipe_event(short revents, struct peer_info *info)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		read_pipe_msg(info);
	} else {
		should_exit = true;
	}
}

/*
 * Handle an event on the socket
 */
static void sock_event(short revents, struct peer_info *info)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {

	} else if (revents & POLLHUP) {

	} else {
		should_exit = true;
	}
}

void sp_tcp_thread(void *data)
{
	struct peer_info *info = (struct peer_info *)data;
	struct pollfd pollfd[POLLFD_NUM];
	int ret = 0;

	setup_poll(pollfd, info->pipefd[READ_END], info->sock);
	while (!should_exit) {
		ret = poll(pollfd, POLLFD_NUM, -1);
		if (ret > 0) {
			if (pollfd[PIPE].revents) {
				pipe_event(pollfd[PIPE].revents, info);
			}

			if (pollfd[SOCK].revents) {
				sock_event(pollfd[SOCK].revents, info);
			}
		} else {
			should_exit = true;
		}
	}
}

#undef READ_END
#undef WRITE_END
#undef SOCK
#undef PIPE
#undef POLLFD_NUM