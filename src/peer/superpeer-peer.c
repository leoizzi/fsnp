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
#include "peer/peer.h"
#include "peer/file_cache.h"

#include "fsnp/fsnp.h"

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

/*
 * Read a message on the pipe and:
 * - if is a PIPE_PROMOTE message promote the peer
 * - if is a PIPE_QUIT message tell the peer we're leaving
 */
static void read_pipe_msg(struct peer_info *info, bool *should_exit)
{
	ssize_t r = 0;
	int msg = 0;
	struct fsnp_promote promote;

	r = fsnp_read(info->pipefd[READ_END], &msg, sizeof(int));
	if (r < 0) {
		/* something wrong happened in the pipe, it's likely possible that the
		 * thread will not be able to communicate with the main thread again.
		 * Let's quit */
		*should_exit = true;
		return;
	}

	if (msg == PIPE_PROMOTE) {
		// TODO: promote the peer. Before going on here the superpeer-superpeer file has to be completed, since we need to communicate to the peer who's being promoted the other sps' addresses
	} else { // msg = PIPE_QUIT
		*should_exit = true;
	}
}

/*
 * Handle an event on the pipe
 */
static void pipe_event(short revents, struct peer_info *info, bool *should_exit)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		read_pipe_msg(info, should_exit);
	} else {
		*should_exit = true;
	}
}

/*
 * Send an error message to the peer.
 * Return 0 on success, -1 if an error has occurred
 */
static int send_fsnp_error(int sock)
{
	struct fsnp_error error;
	ssize_t w = 0;
	fsnp_err_t err;

	fsnp_init_error(&error);
	w = fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)&error, &err);
	if (w < 0) {
		fsnp_print_err_msg(err);
		return -1;
	}

	return 0;
}

/*
 * Join a peer, adding all of its files to the file cache and sending an ACK to
 * him
 */
static void join_rcvd(struct fsnp_join *join, struct peer_info *info,
					  bool *should_exit)
{
	int ret = 0;
	struct in_addr addr;
	ssize_t w = 0;
	fsnp_err_t err;
	struct fsnp_ack ack;

	if (info->joined) {
		ret = send_fsnp_error(info->sock);
		if (ret < 0) {
			*should_exit = true;
			return;
		}
	}

	info->joined = true;
	if (join->num_files == 0) {
		return;
	}

	ret = cache_add_files(join->num_files, join->files_hash, &info->addr);
	if (ret < 0) {
		addr.s_addr = htonl(info->addr.ip);
		fprintf(stderr, "Unable to add the files of peer %s:%hu to the file"
				        " cache\n", inet_ntoa(addr), htons(info->addr.port));
	}

	fsnp_init_ack(&ack);
	w = fsnp_write_msg_tcp(info->sock, 0, (const struct fsnp_msg *)&ack, &err);
	if (w < 0) {
		cache_rm_files(&info->addr);
		fsnp_print_err_msg(err);
		info->joined = false;
		*should_exit = true;
	}
}

/*
 * Read a fsnp_msg from the socket and dispatch it to the right handler
 */
static void read_sock_msg(struct peer_info *info, bool *should_exit)
{
	struct fsnp_msg *msg = NULL;
	ssize_t r = 0;
	fsnp_err_t err;

	msg = fsnp_read_msg_tcp(info->sock, 0, &r, &err);

	if (!msg) {
		fsnp_print_err_msg(err);
		if (err == E_PEER_DISCONNECTED) {
			*should_exit = true;
		}

		return;
	}

	/* shut down the communication if so, as explained in the field 'joined' of
	 * the peer_info struct */
	if (!info->joined && msg->msg_type != JOIN) {
		*should_exit = true;
	}

	switch (msg->msg_type) {
		case JOIN:
			join_rcvd((struct fsnp_join *)msg, info, should_exit);
			break;

		case FILE_REQ:
			break;

		case UPDATE:
			break;

		case ALIVE:
			break;

		case LEAVE:
			break;

		default:
			fprintf(stderr, "Unexpected message type: %d\n", msg->msg_type);
			PRINT_PEER;
			break;
	}
}

/*
 * Handle an event on the socket
 */
static void sock_event(short revents, struct peer_info *info, bool *should_exit)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		read_sock_msg(info, should_exit);
	} else if (revents & POLLHUP) {

	} else {
		*should_exit = true;
	}
}

void sp_tcp_thread(void *data)
{
	struct peer_info *info = (struct peer_info *)data;
	struct pollfd pollfd[POLLFD_NUM];
	int ret = 0;
	bool should_exit = false;

	setup_poll(pollfd, info->pipefd[READ_END], info->sock);
	while (!should_exit) {
		ret = poll(pollfd, POLLFD_NUM, -1);
		if (ret > 0) {
			if (pollfd[PIPE].revents) {
				pipe_event(pollfd[PIPE].revents, info, &should_exit);
			}

			if (pollfd[SOCK].revents) {
				sock_event(pollfd[SOCK].revents, info, &should_exit);
			}
		} else {
			should_exit = true;
		}
	}

	/*
	 * Be careful while exiting if the peer was NOT joined
	 */
}

#undef READ_END
#undef WRITE_END
#undef SOCK
#undef PIPE
#undef POLLFD_NUM