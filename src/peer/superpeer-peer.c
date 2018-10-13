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
#include "peer/keys_cache.h"

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
 * Send an error message to the peer.
 * Return 0 on success, -1 if an error has occurred
 */
static int send_error_msg(int sock)
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
 * Send an alive message to the peer.
 * Return 0 on success, -1 otherwise
 */
static int send_alive_msg(struct peer_info *info)
{
	struct fsnp_alive alive;
	ssize_t w = 0;
	fsnp_err_t err;

	fsnp_init_alive(&alive);
	w = fsnp_write_msg_tcp(info->sock, 0, (const struct fsnp_msg *)&alive, &err);
	if (w < 0 && err != E_TIMEOUT) {
		fsnp_print_err_msg(err);
		return -1;
	}

	info->timeouts++;
	return 0;
}

/*
 * Send a leave message to the peer
 */
static void send_leave_msg(int sock)
{
	struct fsnp_leave leave;
	fsnp_err_t err;

	fsnp_init_leave(&leave);
	// don't care about the return here... we're closing the comm away anyway
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)&leave, &err);
}

/*
 * Send an ACK message to the peer
 * Return 0 on success, -1 otherwise
 */
static int send_ack_msg(int sock)
{
	struct fsnp_ack ack;
	ssize_t w = 0;
	fsnp_err_t err;

	fsnp_init_ack(&ack);
	w = fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)&ack, &err);
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
		ret = send_error_msg(info->sock);
		if (ret < 0) {
			*should_exit = true;
			return;
		}
	}

	info->joined = true;
	if (join->num_files == 0) {
		return;
	}

	ret = cache_add_keys(join->num_files, join->files_hash, &info->addr);
	if (ret < 0) {
		addr.s_addr = htonl(info->addr.ip);
		fprintf(stderr, "Unable to add the files of peer %s:%hu to the file"
				        " cache\n", inet_ntoa(addr), htons(info->addr.port));
	}

	fsnp_init_ack(&ack);
	w = fsnp_write_msg_tcp(info->sock, 0, (const struct fsnp_msg *)&ack, &err);
	if (w < 0) {
		cache_rm_keys(&info->addr);
		fsnp_print_err_msg(err);
		info->joined = false;
		*should_exit = true;
	}
}

static void update_rcvd(struct fsnp_update *update, struct peer_info *info)
{
	int ret = 0;
	struct in_addr addr;

	cache_rm_keys(&info->addr);
	ret = cache_add_keys(update->num_files, update->files_hash, &info->addr);
	if (ret < 0) {
		addr.s_addr = htonl(info->addr.ip);
		fprintf(stderr, "Unable to add the files of peer %s:%hu to the file"
		                " cache\n", inet_ntoa(addr), htons(info->addr.port));
		PRINT_PEER;
	}
}

/*
 * Read a fsnp_msg from the socket and dispatch it to the right handler
 */
static void read_sock_msg(struct peer_info *info, bool leaving,
						  bool *should_exit)
{
	struct fsnp_msg *msg = NULL;
	ssize_t r = 0;
	fsnp_err_t err;
	int ret = 0;

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
			// TODO: before going on with FILE_REQ a working implementation of the superpeers' network is needed
			info->timeouts = 0;
			break;

		case UPDATE:
			update_rcvd((struct fsnp_update *)msg, info);
			info->timeouts = 0;
			break;

		case ALIVE:
			ret = send_ack_msg(info->sock);
			if (ret < 0) {
				PRINT_PEER; // we printed with fsnp_print_error
			}

			info->timeouts = 0;
			break;

		case LEAVE:
			send_ack_msg(info->sock); // don't care about the return... just quit
			*should_exit = true;
			info->timeouts = 0;
			break;

		case ACK:
			if (leaving) {
				*should_exit = true;
			} else {
				info->timeouts = 0;
			}

			break;

		default:
			fprintf(stderr, "Unexpected message type: %d\n", msg->msg_type);
			PRINT_PEER;
			info->timeouts = 0;
			break;
	}
}

/*
 * Handle an event on the socket
 */
static void sock_event(short revents, struct peer_info *info, bool leaving,
					   bool *should_exit)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		read_sock_msg(info, leaving, should_exit);
	} else if (revents & POLLHUP) {

	} else {
		*should_exit = true;
	}
}

/*
 * Read a message on the pipe and:
 * - if is a PIPE_PROMOTE message promote the peer
 * - if is a PIPE_QUIT message tell the peer we're leaving
 */
static void read_pipe_msg(const struct peer_info *info, bool *leaving,
						  bool *should_exit)
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
		send_leave_msg(info->sock);
		*leaving = true;
	}
}

/*
 * Handle an event on the pipe
 */
static void pipe_event(short revents, const struct peer_info *info,
                       bool *leaving, bool *should_exit)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		read_pipe_msg(info, leaving, should_exit);
	} else {
		*should_exit = true;
	}
}

#define POLL_ALIVE_TIMEOUT 30000 // ms
void sp_tcp_thread(void *data)
{
	struct peer_info *info = (struct peer_info *)data;
	struct pollfd pollfd[POLLFD_NUM];
	int ret = 0;
	bool should_exit = false;
	bool leaving = false;

	setup_poll(pollfd, info->pipefd[READ_END], info->sock);
	while (!should_exit) {
		ret = poll(pollfd, POLLFD_NUM, POLL_ALIVE_TIMEOUT);
		if (ret > 0) {
			if (pollfd[PIPE].revents) {
				pipe_event(pollfd[PIPE].revents, info, &leaving, &should_exit);
			}

			if (pollfd[SOCK].revents) {
				sock_event(pollfd[SOCK].revents, info, leaving, &should_exit);
			}
		} else if (ret == 0) {
			if (info->timeouts > 4) {
				// we didn't listen the peer for more than 2 minutes. Let's quit
				should_exit = true;
			} else {
				send_alive_msg(info);
			}
		} else {
			should_exit = true;
		}
	}

	if (info->joined) {
		cache_rm_keys(&info->addr);
	}

	/*
	 * Be careful while exiting if the peer was NOT joined
	 *
	 * Besides, if we need to tell the peer something but timeouts is >= 4 skip
	 * that part
	 */

	/*
	 * Do not free the peer_info struct, it will be done by the thread_manager.
	 * That said, we need to tell the list to remove us from there
	 */
	rm_peer_from_list(&info->addr);
	PRINT_PEER;
}

#undef POLL_ALIVE_TIMEOUT
#undef READ_END
#undef WRITE_END
#undef SOCK
#undef PIPE
#undef POLLFD_NUM