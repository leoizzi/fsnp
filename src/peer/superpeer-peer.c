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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "peer/superpeer-peer.h"
#include "peer/superpeer.h"
#include "peer/superpeer-superpeer.h"
#include "peer/peer.h"
#include "peer/keys_cache.h"

#include "fsnp/fsnp.h"

#include "slog/slog.h"

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
 * Send an ACK msg to the peer
 */
static int send_ack(const struct peer_info *info)
{
	struct fsnp_ack ack;
	fsnp_err_t err;

	fsnp_init_ack(&ack);
	// don't really care about any error here, just log it
	slog_info(FILE_LEVEL, "Sending an ACK msg to peer %s", info->pretty_addr);
	err = fsnp_send_tcp_ack(info->sock, &ack);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
		return -1;
	}

	return 0;
}

/*
 * Senf a FILE_RES msg to the peer
 */
static void send_file_res(const struct peer_info *info,
						  const struct fsnp_file_res *file_res)
{
	fsnp_err_t err;

	slog_info(FILE_LEVEL, "Sending a FILE_RES msg to peer %s", info->pretty_addr);
	err = fsnp_send_file_res(info->sock, file_res);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Send a PROMOTE msg to the peer
 */
static void send_promote(const struct peer_info *info,
						 const struct fsnp_promote *promote)
{
	fsnp_err_t err;

	slog_info(FILE_LEVEL, "Sending a PROMOTE msg to peer %s", info->pretty_addr);
	err = fsnp_send_promote(info->sock, promote);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Send an error msg to the peer
 */
static void send_error(const struct peer_info *info)
{
	struct fsnp_error error;
	fsnp_err_t err;

	fsnp_init_error(&error);
	slog_info(FILE_LEVEL, "Sending an error msg to peer %s", info->pretty_addr);
	err = fsnp_send_error(info->sock, &error);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Send a leave msg to the peer
 */
static void send_leave(const struct peer_info *info)
{
	struct fsnp_leave leave;
	fsnp_err_t err;

	fsnp_init_leave(&leave);
	slog_info(FILE_LEVEL, "Sending a LEAVE msg to peer %s",
	          info->pretty_addr);
	err = fsnp_send_tcp_leave(info->sock, &leave);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Join a peer, adding all of its files to the file cache and sending an ACK to
 * him
 */
static void join_rcvd(struct fsnp_join *join, struct peer_info *info,
					  bool *should_exit)
{
	int ret = 0;

	if (info->joined) {
		slog_warn(FILE_LEVEL, "Peer %s has asked to join again",
		          info->pretty_addr);
		send_error(info);
		*should_exit = true;
		return;
	}

	slog_debug(FILE_LEVEL, "Joining peer %s", info->pretty_addr);
	info->joined = true;
	info->dw_port = join->dw_port;
	if (join->num_files == 0) {
		slog_info(FILE_LEVEL, "Peer %s is not sharing any file", info->pretty_addr);
	} else {
		ret = cache_add_keys(join->num_files, join->files_hash, &info->addr,
				info->dw_port);
		if (ret < 0) {
			slog_error(FILE_LEVEL, "Unable to add peer %s's files to the file "
						  "cache",
			           info->pretty_addr);
		}
	}

	ret = send_ack(info);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Leaving the peer %s", info->pretty_addr);
		cache_rm_keys(&info->addr, info->dw_port);
		info->joined = false;
		*should_exit = true;
	}
}

/*
 * Update the value cached for the peer and send him an ACK
 */
static void update_rcvd(struct fsnp_update *update, struct peer_info *info)
{
	int ret = 0;

	cache_rm_keys(&info->addr, info->dw_port);
	ret = cache_add_keys(update->num_files, update->files_hash, &info->addr,
			info->dw_port);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to add the files of peer %s to the file"
		                " cache after update", info->pretty_addr);
	}

	send_ack(info); // don't care about errors here
}

/*
 * Ask in behalf of the peer who has a file in the network
 */
static void file_req_rcvd(const struct fsnp_file_req *file_req,
						  const struct peer_info *info)
{
	int ret = 0;
	char key_str[SHA256_STR_BYTES];

	stringify_hash(key_str, file_req->hash);
	ret = ask_whohas(file_req->hash, &info->addr);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to ask in the overlay network a file for"
						 " peer %s", info->pretty_addr);
		send_error(info);
		return;
	}

	send_ack(info); // don't care about errors here
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
	struct fsnp_ack ack;

	msg = fsnp_read_msg_tcp(info->sock, 0, &r, &err);

	if (!msg) {
		fsnp_log_err_msg(err, false);
		slog_error(FILE_LEVEL, "Unable to read a message from peer %s",
				info->pretty_addr);
		if (err == E_PEER_DISCONNECTED) {
			*should_exit = true;
		}

		return;
	}

	/* shut down the communication if so, as explained in the field 'joined' of
	 * the peer_info struct */
	if (!info->joined && msg->msg_type != JOIN) {
		slog_warn(FILE_LEVEL, "Peer %s sent a message before joining this sp",
				info->pretty_addr);
		*should_exit = true;
	}

	switch (msg->msg_type) {
		case JOIN:
			slog_info(FILE_LEVEL, "Peer %s sent a JOIN msg", info->pretty_addr);
			join_rcvd((struct fsnp_join *)msg, info, should_exit);
			break;

		case FILE_REQ:
			slog_info(FILE_LEVEL, "Peer %s sent a FILE_REQ msg. Timeouts before "
						 "this: %u", info->pretty_addr, info->timeouts);
			file_req_rcvd((const struct fsnp_file_req *)msg, info);
			info->timeouts = 0;
			break;

		case UPDATE:
			slog_info(FILE_LEVEL, "%Peer s sent an UPDATE msg. Timeouts before "
			                      "this: %u", info->pretty_addr, info->timeouts);
			update_rcvd((struct fsnp_update *)msg, info);
			info->timeouts = 0;
			break;

		case ALIVE:
			slog_info(FILE_LEVEL, "Peer %s sent an ALIVE msg. Timeouts before "
			                      "this: %u", info->pretty_addr, info->timeouts);
			fsnp_init_ack(&ack);
			slog_info(FILE_LEVEL, "Sending an ACK msg to %s", info->pretty_addr);
			err = fsnp_send_tcp_ack(info->sock, &ack);
			if (err != E_NOERR) {
				fsnp_log_err_msg(err, false);
			}

			info->timeouts = 0;
			break;

		case LEAVE:
			slog_info(FILE_LEVEL, "Peer %s sent a LEAVE msg. Timeouts before "
			                      "this: %u", info->pretty_addr, info->timeouts);
			fsnp_init_ack(&ack);
			// don't care about the return... just quit
			slog_info(FILE_LEVEL, "Sending the last ACK to peer %s. If an error"
						 " occurred is not checked", info->pretty_addr);
			fsnp_send_tcp_ack(info->sock, &ack);
			*should_exit = true;
			info->timeouts = 0;
			break;

		case ACK:
			slog_info(FILE_LEVEL, "Peer %s sent an ACK msg. Timeouts before "
			                      "this: %u", info->pretty_addr, info->timeouts);
			if (leaving) {
				slog_debug(FILE_LEVEL, "The ACK was sent for a LEAVE msg");
				*should_exit = true;
			} else {
				slog_debug(FILE_LEVEL, "The ACK was sent for an ALIVE msg");
				info->timeouts = 0;
			}

			break;

		default:
			slog_warn(FILE_LEVEL, "Peer %s sent an unexpected message type: %d",
					info->pretty_addr, msg->msg_type);
			info->timeouts = 0;
			break;
	}

	free(msg);
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
		slog_warn(FILE_LEVEL, "Peer %s revents: POLLHUP", info->pretty_addr);
	} else {
		slog_error(FILE_LEVEL, "Peer %s sock revents: %d", info->pretty_addr,
				revents);
		*should_exit = true;
	}
}

/*
 * Handler called when a PIPE_FILE_RES msg type is read from the pipe
 *
 * Send the result of the search to the peer
 */
static void pipe_file_res_rvcd(const struct peer_info *info)
{
	ssize_t r = 0;
	fsnp_err_t err;
	struct fsnp_whohas whohas;
	struct fsnp_file_res *file_res = NULL;

	r = fsnp_timed_read(info->pipefd[READ_END], &whohas,
			sizeof(struct fsnp_whohas), FSNP_TIMEOUT, &err);
	if (r < 0) {
		slog_error(FILE_LEVEL, "Unable to read whohas msg from the pipe of peer"
						 " %s", info->pretty_addr);
		fsnp_log_err_msg(err, false);
		return;
	}

	file_res = fsnp_create_file_res(whohas.num_peers, whohas.owners);
	if (!file_res) {
		slog_error(FILE_LEVEL, "Unable to create fsnp_file_res");
		return;
	}

	send_file_res(info, file_res);
	free(file_res);
}

/*
 * Handler called when a PIPE_PROMOTE msg type is read from the pipe
 *
 * Promote the peer to superpeer
 */
static void pipe_promote_rcvd(struct peer_info *info, bool *leaving) {
	bool is_valid = false;
	struct fsnp_peer prev;
	in_port_t self;
	struct fsnp_promote promote;

	self = get_udp_sp_port();
	is_valid = get_prev_addr(&prev);
	if (!is_valid) {
		slog_info(FILE_LEVEL, "Prev not valid during the promotion of peer %s",
				info->pretty_addr);
		fsnp_init_promote(&promote, self, NULL);
	} else {
		fsnp_init_promote(&promote, self, &prev);
	}

	send_promote(info, &promote);
	*leaving = true;
}

/*
 * Handler called when a PIPE_ERROR msg type is read from the pipe
 *
 * Send an error to the peer
 */
static void pipe_error_rcvd(const struct peer_info *info)
{
	send_error(info);
}

/*
 * Handler called when a PIPE_LEAVE msg type is read from the pipe
 *
 * Leave the peer
 */
static void pipe_leave_rcvd(const struct peer_info *info, bool *leaving)
{
	send_leave(info);
	*leaving = true;
}

/*
 * Read a message on the pipe and:
 * - if is a PIPE_PROMOTE message promote the peer
 * - if is a PIPE_QUIT message tell the peer we're leaving
 */
static void read_pipe_msg(struct peer_info *info, bool *leaving,
						  bool *should_exit)
{
	ssize_t r = 0;
	int msg = 0;

	slog_debug(FILE_LEVEL, "Reading a msg for peer %s from the pipe",
			info->pretty_addr);
	r = fsnp_read(info->pipefd[READ_END], &msg, sizeof(int));
	if (r < 0) {
		/* something wrong happened in the pipe, it's likely possible that the
		 * thread will not be able to communicate with the main thread again.
		 * Let's quit */
		slog_error(FILE_LEVEL, "The pipe for communicating with peer %s is broken",
				info->pretty_addr);
		*should_exit = true;
		return;
	}

	if (msg == PIPE_PROMOTE) {
		slog_info(FILE_LEVEL, "Read from the pipe to promote peer %s",
		          info->pretty_addr);
		pipe_promote_rcvd(info, leaving);
	} else if (msg == PIPE_FILE_RES) {
		slog_info(FILE_LEVEL, "Read from the pipe to send file_res to peer %s",
		          info->pretty_addr);
		pipe_file_res_rvcd(info);
	} else if (msg == PIPE_ERROR) {
		slog_info(FILE_LEVEL, "Read from the pipe to send error to peer %s",
				info->pretty_addr);
		pipe_error_rcvd(info);
	} else { // msg = PIPE_QUIT
		slog_info(FILE_LEVEL, "Read from the pipe to leave peer %s",
				info->pretty_addr);
		pipe_leave_rcvd(info, leaving);
	}
}

/*
 * Handle an event on the pipe
 */
static void pipe_event(short revents, struct peer_info *info, bool *leaving,
					   bool *should_exit)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		read_pipe_msg(info, leaving, should_exit);
	} else {
		slog_error(FILE_LEVEL, "peer %s pipe revents: %d", info->pretty_addr,
				revents);
		*should_exit = true;
	}
}

/*
 * Check if the peer is still alive. If not close the communications and quit
 * the thread
 */
static void is_alive(struct peer_info *info, bool *should_exit)
{
	fsnp_err_t err;
	struct fsnp_alive alive;

	info->timeouts++;
	slog_debug(FILE_LEVEL, "The sp_tcp_thread's poll for peer %s has fired its "
						"timeout timer. Now the timeouts are %u",
						info->pretty_addr, info->timeouts);
	if (info->timeouts > 4) {
		// the peer didn't contacted us for more than 2 minutes
		slog_warn(FILE_LEVEL, "Peer %s didn't show any sign of life for more "
						"then 2 minutes. Leaving it.", info->pretty_addr);
		*should_exit = true;
		return;
	}

	fsnp_init_alive(&alive);
	slog_info(FILE_LEVEL, "Sending an ALIVE msg to peer %s", info->pretty_addr);
	err = fsnp_send_tcp_alive(info->sock, &alive);
	if (err == E_PEER_DISCONNECTED) {
		fsnp_log_err_msg(err, false);
		*should_exit = true;
	}
}

void sp_tcp_thread(void *data)
{
	struct peer_info *info = (struct peer_info *)data;
	struct pollfd pollfd[POLLFD_NUM];
	int ret = 0;
	bool should_exit = false;
	bool leaving = false;

	slog_info(FILE_LEVEL, "sp_tcp_thread for peer %s is operative",
			info->pretty_addr);
	setup_poll(pollfd, info->pipefd[READ_END], info->sock);
	while (!should_exit) {
		ret = poll(pollfd, POLLFD_NUM, FSNP_POLL_TIMEOUT);
		if (ret > 0) {
			if (pollfd[PIPE].revents) {
				pipe_event(pollfd[PIPE].revents, info, &leaving, &should_exit);
			}

			if (pollfd[SOCK].revents) {
				sock_event(pollfd[SOCK].revents, info, leaving, &should_exit);
			}
		} else if (ret == 0) {
			is_alive(info, &should_exit);
		} else {
			slog_error(FILE_LEVEL, "sp_tcp_thread poll for peer %s has returned"
						  " -1. Error: %d", info->pretty_addr, errno);
			should_exit = true;
		}
	}

	slog_info(FILE_LEVEL, "Leaving peer %s", info->pretty_addr);
	if (info->joined) {
		cache_rm_keys(&info->addr, info->dw_port);
	}

	slog_info(FILE_LEVEL, "Removing peer %s from the known_peer list",
			info->pretty_addr);
	rm_peer_from_list(&info->addr);
	slog_info(FILE_LEVEL, "Leaving procedure for peer %s completed",
			info->pretty_addr);
	close(info->sock);
	close(info->pipefd[READ_END]);
	close(info->pipefd[WRITE_END]);
	/*
	 * Do not free the peer_info struct, it will be done by the thread_manager.
    */
}

#undef READ_END
#undef WRITE_END
#undef SOCK
#undef PIPE
#undef POLLFD_NUM