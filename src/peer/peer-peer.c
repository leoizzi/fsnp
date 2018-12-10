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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <memory.h>
#include <errno.h>
#include <unistd.h>

#include "peer/peer.h"
#include "peer/peer-peer.h"
#include "peer/thread_manager.h"
#include "peer/file_manager.h"

#include "fsnp/fsnp.h"

#include "slog/slog.h"

#define DW_CHUNK 1024

//------------------------------------------------------------------------------
//******************************** CLIENT SIDE *********************************
//------------------------------------------------------------------------------



//------------------------------------------------------------------------------
//******************************** SERVER SIDE *********************************
//------------------------------------------------------------------------------

struct server_dw {
	int sock;
	struct fsnp_peer addr;
	char pretty_addr[32];
	sha256_t file_hash;
};

/*
 * Read DW_CHUNK bytes of the file. On output in size will be found how many bytes
 * were read.
 *
 * Returns true if the read was successful, false otherwise
 * NOTE: false will be returned also if there's nothing more to be read
 */
static bool sr_read_chunk(int fd, char *buf, size_t *size)
{
	ssize_t r = 0;

	r = fsnp_read(fd, buf, DW_CHUNK);
	if (r < 0) {
		slog_error(FILE_LEVEL, "Error %d while reading file to send", errno);
		return false;
	} else if (r == 0) {
		return false;
	} else {
		*size = (size_t)r;
		return true;
	}
}

/*
 * Send DW_CHUNK bytes of the file to the peer. On output in size will be found
 * how many bytes were sent to the peer
 *
 * Returns true if everything went well, false otherwise
 */
static bool sr_send_chunk(struct server_dw *sd, char *buf, size_t *sz)
{
	ssize_t w = 0;
	fsnp_err_t err;

	w = fsnp_timed_write(sd->sock, buf, *sz, 0, &err);
	if (err != E_NOERR) {
		slog_error(FILE_LEVEL, "Unable to send a chunk to %s", sd->pretty_addr);
		return false;
	}

	*sz = (size_t)w;
	return true;
}

/*
 * Send the file to the requester
 */
static void send_file(struct server_dw *sd, int fd, size_t size)
{
	char buf[DW_CHUNK];
	size_t sent = 0;
	size_t r = 0;
	bool ok = false;

	while (sent < size) {
		ok = sr_read_chunk(fd, buf, &r);
		if (!ok) {
			break;
		}

		ok = sr_send_chunk(sd, buf, &r);
		if (!ok) {
			break;
		}

		sent += r;
	}

	slog_debug(FILE_LEVEL, "send_file has done. Over %lu bytes to send, %lu"
						" were actually sent to %s.", size, sent, sd->pretty_addr);
}

/*
 * Send an ERROR msg
 */
static void send_error(struct server_dw *sd)
{
	struct fsnp_error error;
	fsnp_err_t err;

	fsnp_init_error(&error);
	slog_info(FILE_LEVEL, "Sending an ERROR msg to peer %s", sd->pretty_addr);
	err = fsnp_send_error(sd->sock, &error);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Send a DOWNLOAD msg
 */
static void send_download(struct server_dw *sd, size_t size)
{
	struct fsnp_download download;
	fsnp_err_t err;

	fsnp_init_download(&download, size, NULL);
	slog_info(FILE_LEVEL, "Sending a DOWNLOAD msg to peer %s", sd->pretty_addr);
	err = fsnp_send_download(sd->sock, &download);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Wait for a GET_FILE msg and parse it
 */
static void wait_for_get_file(struct server_dw *sd)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_get_file *get_file = NULL;
	fsnp_err_t err;
	char hash_str[SHA256_STR_BYTES];

	msg = fsnp_read_msg_tcp(sd->sock, 0, NULL, &err);
	if (!msg) {
		slog_error(FILE_LEVEL, "Unable to receive a GET_FILE msg");
		fsnp_log_err_msg(err, false);
		free(msg);
		return;
	}

	if (msg->msg_type != GET_FILE) {
		slog_warn(FILE_LEVEL, "Unexpected msg received. Expected GET_FILE (%u),"
						" got %u", GET_FILE, msg->msg_type);
		free(msg);
	}

	get_file = (struct fsnp_get_file *)msg;
	memcpy(sd->file_hash, get_file->hash, sizeof(sha256_t));
	stringify_hash(hash_str, sd->file_hash);
	slog_info(FILE_LEVEL, "Peer %s wants to download file %s",sd->pretty_addr,
			hash_str);
	free(msg);
}

/*
 * Entry point for server-dw-thread
 */
static void server_dw_thread(void *data)
{
	struct server_dw *sd = (struct server_dw *)data;
	size_t size = 0;
	bool valid = false;
	char filename[FSNP_NAME_MAX];
	int fd = 0;

	wait_for_get_file(sd);
	if (!key_exists(sd->file_hash)) {
		send_error(sd);
		close(sd->sock);
		return;
	}

	memset(filename, 0, sizeof(char) * FSNP_NAME_MAX);
	size = get_file_size(sd->file_hash);
	if (size == 0) {
		slog_error(FILE_LEVEL, "The size of the file cannot be 0");
		close(sd->sock);
		return;
	}

	valid = get_file_name(sd->file_hash, filename);
	if (!valid) {
		slog_error(FILE_LEVEL, "Unable to retrieve the name of the file");
		close(sd->sock);
		return;
	}

	send_download(sd, size);
	fd = get_file_desc(sd->file_hash, true, filename);
	if (fd < 0) {
		slog_error(FILE_LEVEL, "Unable to retrieve the file descriptor");
		close(sd->sock);
		return;
	}

	send_file(sd, fd, size);
	close(fd);
	close(sd->sock);
}

/*
 * Accept a connection to start a download session (server-side)
 */
static void accept_download(void)
{
	int dw_sock = 0;
	int s = 0;
	int ret = 0;
	struct sockaddr_in addr;
	struct server_dw *sd = NULL;
	socklen_t socklen = sizeof(addr);

	dw_sock = get_dw_sock();
	memset(&addr, 0, socklen);
	s = accept(dw_sock, (struct sockaddr *)&addr, &socklen);
	if (s < 0) {
		slog_error(FILE_LEVEL, "Unable to accept a new connection on the dw"
						 " sock. Error %d", errno);
		return;
	}

	sd = malloc(sizeof(struct server_dw));
	if (!sd) {
		close(s);
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		return;
	}

	sd->sock = s;
	sd->addr.ip = ntohl(addr.sin_addr.s_addr);
	sd->addr.port = ntohs(addr.sin_port);
	memset(sd->pretty_addr, 0, sizeof(char) * 32);
	memset(sd->file_hash, 0, sizeof(sha256_t));
	snprintf(sd->pretty_addr, sizeof(char) * 32, "%s:%hu",
			inet_ntoa(addr.sin_addr), sd->addr.port);
	slog_info(FILE_LEVEL, "Starting a server-side download session for %s",
			sd->pretty_addr);
	ret = start_new_thread(server_dw_thread, sd, "server-dw-thread");
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to start server-dw-thread for peer %s",
				sd->pretty_addr);
		close(s);
		free(sd);
	}
}

void dw_sock_event(short revents) {
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		accept_download();
	} else if (revents & POLLHUP) {
		slog_warn(FILE_LEVEL, "The poll for the dw sock has returned POLLHUP");
	} else {
		slog_error(FILE_LEVEL, "The poll for the dw sock has returned %hd", revents);
	}
}

#undef DW_CHUNK