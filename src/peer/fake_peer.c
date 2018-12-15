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

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#include "peer/fake_peer.h"
#include "peer/superpeer.h"
#include "peer/peer.h"
#include "peer/pipe_macro.h"
#include "peer/peer-superpeer.h"
#include "peer/superpeer-superpeer.h"

#include "slog/slog.h"

/*
 * Handler called when a PIPE_FILE_RES msg is read from the pipe
 */
static void fake_peer_file_res_rcvd(struct peer_info *fake_peer,
		bool *already_asked, bool *should_exit)
{
	ssize_t r = 0;
	fsnp_err_t err;
	struct fsnp_whohas whohas;
	struct fsnp_file_res *file_res = NULL;

	r = fsnp_timed_read(fake_peer->pipefd[READ_END], &whohas,
	                    sizeof(struct fsnp_whohas), FSNP_TIMEOUT, &err);
	if (r < 0) {
		slog_error(FILE_LEVEL, "fake-peer unable to read whohas msg from the "
		                       "pipe");
		fsnp_log_err_msg(err, false);
		*should_exit = true;
		return;
	}

	file_res = fsnp_create_file_res(whohas.num_peers, whohas.owners);
	if (!file_res) {
		slog_error(FILE_LEVEL, "Unable to create fsnp_file_res");
		return;
	}

	file_res_rcvd(file_res);
	*already_asked = false;
	free(file_res);
}

/*
 * Handler called when a PIPE_WHOHAS msg is read from the pipe
 */
static void fake_peer_whohas_rcvd(struct peer_info *fake_peer,
		bool *already_asked, bool *should_exit)
{
	ssize_t r = 0;
	fsnp_err_t err;
	sha256_t file_hash;
	int ret = 0;

	r = fsnp_timed_read(fake_peer->pipefd[READ_END], file_hash, sizeof(sha256_t),
	                    FSNP_TIMEOUT, &err);
	if (r < 0) {
		slog_error(FILE_LEVEL, "Unable to read file_hash from the pipe");
		fsnp_log_err_msg(err, false);
		*should_exit = true;
	}

	if (*already_asked == true) {
		slog_warn(STDOUT_LEVEL, "You're already searching for a file. Wait for"
		                        " its response before searching for another one");
		PRINT_PEER;
		return;
	}


	ret = ask_whohas(file_hash, &fake_peer->addr);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to ask into the overlay network a file");
		*should_exit = true;
		return;
	}

	*already_asked = true;
}

/*
 * Read a msg from the pipe and call the right handler
 */
static void fake_peer_read_pipe_msg(struct peer_info *fake_peer, bool *already_asked,
                                    bool *should_exit)
{
	int msg = 0;
	ssize_t r = 0;

	r = fsnp_read(fake_peer->pipefd[READ_END], &msg, sizeof(int));
	if (r < 0) {
		slog_error(FILE_LEVEL, "fsnp_read error %d while reading from the pipe",
		           errno);
		*should_exit = true;
		return;
	}

	switch (msg) {
		case PIPE_WHOHAS:
			fake_peer_whohas_rcvd(fake_peer, already_asked, should_exit);
			break;

		case PIPE_FILE_RES:
			fake_peer_file_res_rcvd(fake_peer, already_asked, should_exit);
			break;

		case PIPE_QUIT:
			slog_info(FILE_LEVEL, "fake peer has received pipe_quit");
			*should_exit = true;
			break;

		default:
			slog_error(FILE_LEVEL, "Unexpected pipe msg: %d", msg);
			break;
	}
}

/*
 * handler called when an event on the pipe occurs
 */
static void fake_peer_pipe_event(short revents, struct peer_info *fake_peer,
                                 bool *already_asked, bool *should_exit)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		fake_peer_read_pipe_msg(fake_peer, already_asked, should_exit);
	} else {
		slog_error(FILE_LEVEL, "pipe revents: %d", revents);
		*should_exit = true;
	}
}

void fake_peer_info_thread(void *data)
{
	bool should_exit = false;
	bool already_asked = false;
	struct peer_info *fake_peer = (struct peer_info *)data;
	struct pollfd fd;
	int ret = 0;

	fd.fd = fake_peer->pipefd[READ_END];
	fd.events = POLLIN | POLLPRI;
	fd.revents = 0;

	slog_info(FILE_LEVEL, "fake-peer-info-thread is successfully initialized");
	while (!should_exit) {
		ret = poll(&fd, 1, -1);
		if (ret > 0) {
			if (fd.revents) {
				fake_peer_pipe_event(fd.revents, fake_peer, &already_asked,
				                     &should_exit);
			}
		} else {
			should_exit = true;
		}
	}

	slog_info(FILE_LEVEL, "fake-peer-info-thread is exiting...");
	close(fake_peer->pipefd[READ_END]);
	close(fake_peer->pipefd[WRITE_END]);
}


struct peer_info *create_fake_peer_info(void)
{
	int ret = 0;
	struct in_addr a;
	struct peer_info *fake_peer = NULL;

	fake_peer = malloc(sizeof(struct peer_info));
	if (!fake_peer) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		return NULL;
	}

	fake_peer->sock = -1;
	fake_peer->addr.ip = get_peer_ip();
	fake_peer->addr.port = get_tcp_sp_port();
	fake_peer->joined = fake_peer;
	fake_peer->timeouts = 0;
	ret = pipe(fake_peer->pipefd);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to create a pipe for the fake thread");
		free(fake_peer);
		return NULL;
	}

	a.s_addr = htonl(fake_peer->addr.ip);
	snprintf(fake_peer->pretty_addr, sizeof(char) * 32, "%s:%hu", inet_ntoa(a),
	         fake_peer->addr.port);

	return fake_peer;
}
