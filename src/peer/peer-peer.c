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
#include "peer/stdin.h"

#include "fsnp/fsnp.h"

#include "slog/slog.h"

#define DW_CHUNK 1024

//------------------------------------------------------------------------------
//******************************** CLIENT SIDE *********************************
//------------------------------------------------------------------------------

struct client_dw {
	struct fsnp_peer peer;
	int sock;
	int fd;
	size_t file_size;
	char filename[FSNP_NAME_MAX];
	char pretty_addr[32];
	sha256_t file_hash;
	char hash_str[SHA256_STR_BYTES];
};

/*
 * Write a chunk into the file
 */
static bool store_chunk(const struct client_dw *cd, char buf[DW_CHUNK], size_t r)
{
	ssize_t w = 0;

	w = fsnp_write(cd->fd, buf, r);
	if (w < 0) {
		slog_warn(STDOUT_LEVEL, "Error %d has occurred while writing on disk"
						  " the file wich is being downloaded from %s.",
						  errno, cd->pretty_addr);
		PRINT_PEER;
		return false;
	} else if (w == 0) {
		slog_warn(STDOUT_LEVEL, "File %s unexpectedly closed", cd->filename);
		PRINT_PEER;
		return false;
	} else {
		return true;
	}
}

/*
 * Read a chunk from the socket
 */
static bool receive_chunk(const struct client_dw *cd, char buf[DW_CHUNK], size_t *r)
{
	ssize_t rt = 0;
	fsnp_err_t err;

	rt = fsnp_timed_read(cd->sock, buf, DW_CHUNK, FSNP_TIMEOUT, &err);
	if (rt < 0) {
		slog_warn(STDOUT_LEVEL, "An error has occurred while downloading"
		                        " the file from %s", cd->pretty_addr);
		fsnp_log_err_msg(err, true);
		PRINT_PEER;
		*r = 1; // so the if statement in download_file get triggered
		return false;
	} else if (rt == 0) {
		*r = 0;
		return false;
	} else {
		*r = (size_t)rt;
		return true;
	}
}

#define NSEC_TO_SEC(ns) ((double)(ns) / 1000000000.)

/*
 * Show on the stdout the status of the download
 */
static void show_dw_status(size_t rcvd, size_t tot, size_t diff, double time,
		const char *filename)
{
	char *prfx[] = {
			"B",
			"KiB",
			"MiB",
			"GiB"
	};
	double rc = (double)rcvd;
	double to = (double)tot;
	double di = (double)diff;
	unsigned i = 0;
	unsigned j = 0;
	unsigned k = 0;

	while (to > 1024. && i < sizeof(prfx)) {
		to /= 1024.;
		i++;
	}

	while (rc > 1024. && j < sizeof(prfx)) {
		rc /= 1024.;
		j++;
	}

	if (time > 0) {
		di /= time;
	}

	while (di > 1024. && k < sizeof(prfx)) {
		di /= 1024.;
		k++;
	}

	printf("\r%s download status: %.1lf %s of %.1lf %s (%.1lf %s)/s",
			filename, rc, prfx[j], to, prfx[i], di, prfx[k]);
	fflush(stdout);
}

/*
 * Receive a file from a peer
 */
static int download_file(struct client_dw *cd)
{
	char buf[DW_CHUNK];
	bool ok = true;
	size_t rcvd = 0;
	size_t prev_rcvd = 0;
	size_t r = 0;
	struct timespec curr;
	struct timespec last;
	double c = 0;
	double l = 0;

	slog_info(FILE_LEVEL, "The download is starting");
	block_stdin();
	clock_gettime(CLOCK_MONOTONIC, &last);
	memcpy(&curr, &last, sizeof(struct timespec));
	l = (double)last.tv_sec + NSEC_TO_SEC(last.tv_nsec);
	printf("\n");
	show_dw_status(0, cd->file_size, 0, 0, cd->filename);
	while (rcvd < cd->file_size && ok) {
		ok = receive_chunk(cd, buf, &r);
		if (!ok && r != 0) {
			break;
		}

		rcvd += r;

		clock_gettime(CLOCK_MONOTONIC, &curr);
		c = (double)curr.tv_sec + NSEC_TO_SEC(curr.tv_nsec);
		if (c - l > 0.5) {
			show_dw_status(rcvd, cd->file_size, rcvd - prev_rcvd, c-l, cd->filename);
			prev_rcvd = rcvd;
			memcpy(&last, &curr, sizeof(struct timespec));
			l = c;
		}

		ok = store_chunk(cd, buf, r);
		if (!ok) {
			break;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &curr);
	c = (double)curr.tv_sec + NSEC_TO_SEC(curr.tv_nsec);
	show_dw_status(rcvd, cd->file_size, rcvd - prev_rcvd, c-l, cd->filename);
	if (rcvd == cd->file_size) {
		printf("\nDownload completed\n");
	} else {
		printf("\nThe download ended due to an error\n");
	}
	
	PRINT_PEER;
	slog_debug(FILE_LEVEL, "download_file has done. Over %lu bytes to receive,"
						" %lu were actually received from %s.", cd->file_size,
						rcvd, cd->pretty_addr);

	release_stdin();
	if (ok) {
		return 0;
	} else {
		return -1;
	}
}

#undef NSEC_TO_SEC

/*
 * Wait for the peer response and return its type
 */
static fsnp_type_t wait_for_peer_response(struct client_dw *cd)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_download *download = NULL;
	fsnp_err_t err;
	fsnp_type_t type;

	slog_info(FILE_LEVEL, "Waiting for a get_file answer from %s", cd->pretty_addr);
	msg = fsnp_read_msg_tcp(cd->sock, 0, NULL, &err);
	if (!msg) {
		fsnp_log_err_msg(err, true);
		return ERROR;
	}

	if (msg->msg_type == DOWNLOAD) {
		download = (struct fsnp_download *)msg;
		cd->file_size = download->file_size;
		type = DOWNLOAD;
	} else if (msg->msg_type == ERROR) {
		slog_warn(STDOUT_LEVEL, "The peer doesn't have the file you're searching for");
		PRINT_PEER;
		type = ERROR;
	} else {
		slog_warn(STDOUT_LEVEL, "The peer sent a corrupted response. Aborting");
		PRINT_PEER;
		type = ERROR;
	}

	free(msg);
	return type;
}

static int send_get_file(const struct client_dw *cd)
{
	struct fsnp_get_file get_file;
	fsnp_err_t err;

	fsnp_init_get_file(&get_file, cd->file_hash);
	slog_info(FILE_LEVEL, "Sending a GET_FILE msg to %s", cd->pretty_addr);
	err = fsnp_send_get_file(cd->sock, &get_file);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, true);
		slog_warn(STDOUT_LEVEL, "Unable to start the download session");
		PRINT_PEER;
		return -1;
	}

	return 0;
}

/*
 * Create a socket and connect it to the peer specified in 'cd'
 */
static int connect_to_peer(struct client_dw *cd)
{
	struct in_addr a;

	a.s_addr = cd->peer.ip;
	cd->sock = fsnp_create_connect_tcp_sock(a, cd->peer.port);
	if (cd->sock < 0) {
		slog_error(FILE_LEVEL, "Unable to create/connect to %s", cd->pretty_addr);
		slog_warn(STDOUT_LEVEL, "Unable to start the download");
		PRINT_PEER;
		return -1;
	}

	return 0;
}

/*
 * Entry point for client-dw-thread
 */
static void client_dw_thread(void *data)
{
	struct client_dw *cd = (struct client_dw *)data;
	int ret = 0;
	fsnp_type_t type;

	sha256(cd->filename, strlen(cd->filename) + 1, cd->file_hash);
	stringify_hash(cd->hash_str, cd->file_hash);
	slog_debug(FILE_LEVEL, "client-dw-thread hash of file %s -> %s",
			cd->filename, cd->hash_str);
	ret = connect_to_peer(cd);
	if (ret < 0) {
		return;
	}

	ret = send_get_file(cd);
	if (ret < 0) {
		close(cd->sock);
		return;
	}

	type = wait_for_peer_response(cd);
	if (type == ERROR) {
		close(cd->sock);
		return;
	}

	slog_info(FILE_LEVEL, "Creating download file %s",cd->filename);
	cd->fd = create_download_file(cd->filename);
	if (cd->fd < 0) {
		slog_warn(FILE_LEVEL, "Unable to create file %s. Aborting the download",
				cd->filename);
		close(cd->sock);
		return;
	}

	ret = download_file(cd);

	if (ret < 0) {
		close_download_file(cd->fd, cd->filename, cd->file_hash, true);
	} else {
		close_download_file(cd->fd, cd->filename, cd->file_hash, false);
	}

	close(cd->sock);
}

void dw_from_peer(const struct fsnp_peer *peer, const char filename[FSNP_NAME_MAX])
{
	struct client_dw *cd = NULL;
	struct in_addr a;
	int ret = 0;

	cd = calloc(1, sizeof(struct client_dw));
	if (!cd) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		slog_warn(STDOUT_LEVEL, "Unable to start the download");
		PRINT_PEER;
		return;
	}

	memcpy(&cd->peer, peer, sizeof(struct fsnp_peer));
	strncpy(cd->filename, filename, sizeof(char) * FSNP_NAME_MAX);
	a.s_addr = htonl(peer->ip);
	snprintf(cd->pretty_addr, sizeof(char) * 32, "%s:%hu", inet_ntoa(a), peer->port);
	ret = start_new_thread(client_dw_thread, cd, "client-dw-thread");
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Unable to start client-dw-thread");
		slog_warn(STDOUT_LEVEL, "Unable to start the download");
		PRINT_PEER;
	}
}

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
static bool sr_send_chunk(const struct server_dw *sd, const char *buf, size_t *sz)
{
	ssize_t w = 0;
	fsnp_err_t err;

	w = fsnp_timed_write(sd->sock, buf, *sz, FSNP_TIMEOUT, &err);
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
static void send_file(const struct server_dw *sd, int fd, size_t size)
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
static void send_error(const struct server_dw *sd)
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
static void send_download(const struct server_dw *sd, size_t size)
{
	struct fsnp_download download;
	fsnp_err_t err;

	fsnp_init_download(&download, size);
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
	int fd = 0;

	wait_for_get_file(sd);
	if (!key_exists(sd->file_hash)) {
		send_error(sd);
		close(sd->sock);
		return;
	}

	size = get_file_size(sd->file_hash);
	if (size == 0) {
		slog_error(FILE_LEVEL, "The size of the file cannot be 0");
		send_error(sd);
		close(sd->sock);
		return;
	}

	send_download(sd, size);
	fd = get_file_desc(sd->file_hash, true, NULL);
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