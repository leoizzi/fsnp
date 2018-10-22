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
#include <memory.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <limits.h>
#include <errno.h>

#include "fsnp/fsnp.h"

int fsnp_create_bind_tcp_sock(in_port_t *port, bool localhost)
{
	int sock = 0;
	int ret = 0;
	struct sockaddr_in addr;

	sock = socket(PF_INET, SOCK_STREAM, 0);
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

	while (*port <= USHRT_MAX) {
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

int fsnp_create_connect_tcp_sock(struct in_addr ip, in_port_t port)
{
	int sock = 0;
	int ret = 0;
	struct sockaddr_in addr;
	socklen_t socklen = sizeof(addr);

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		return -1;
	}

	memset(&addr, 0, socklen);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ip.s_addr);
	addr.sin_port = htons(port);
	
	ret = connect(sock, (struct sockaddr *)&addr, socklen);
	if (ret < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

ssize_t fsnp_read(int sock, void *buf, size_t bytes)
{
	ssize_t r = 0;
	ssize_t t = 0;

	while (r < (ssize_t)bytes) {
		t = read(sock, buf + r, bytes - r);
		if (t > 0) {
			r += t;
		} else if (t < 0) {
			if (errno != EINTR) {
				return -1;
			}
		} else { // t == 0
			break;
		}
	}

	return r;
}

ssize_t fsnp_write(int sock, const void *buf, size_t bytes)
{
	ssize_t w = 0;
	ssize_t t = 0;

	while (w < (ssize_t)bytes) {
		t = write(sock, buf + w, bytes - w);
		if (t > 0) {
			w += t;
		} else if (t < 0) {
			if (errno != EINTR) {
				return -1;
			}
		} else { // t == 0
			break;
		}
	}

	return w;
}

ssize_t fsnp_timed_read(int sock, void *buf, size_t bytes, uint16_t timeout,
                        fsnp_err_t *err)
{
	struct pollfd pollfd;
	ssize_t r = 0;
	int ret = 0;
	short revents = 0;

	pollfd.fd = sock;
	pollfd.events = POLLIN;
	pollfd.revents = 0;

	ret = poll(&pollfd, 1, timeout);

	if (ret > 0) {
		revents = pollfd.revents;
		if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
			r = fsnp_read(sock, buf, bytes);
			if (r < 0) {
				*err = E_ERRNO;
			}
		} else if (revents & POLLHUP) {
			r = 0;
			*err = E_PEER_DISCONNECTED;
		} else {
			r = -1;
			*err = E_UNKNOWN;
		}
	} else {
		r = -1;
		if (ret == 0) {
			*err = E_TIMEOUT;
		} else {
			*err = E_ERRNO;
		}
	}

	return r;
}

ssize_t fsnp_timed_write(int sock, const void *buf, size_t bytes,
						 uint16_t timeout, fsnp_err_t *err)
{
	struct pollfd pollfd;
	ssize_t w = 0;
	int ret = 0;
	short revents = 0;

	pollfd.fd = sock;
	pollfd.events = POLLOUT;
	pollfd.revents = 0;

	ret = poll(&pollfd, 1, timeout);

	if (ret > 0) {
		revents = pollfd.revents;
		if (revents & POLLOUT || revents & POLLWRBAND) {
			w = fsnp_write(sock, buf, bytes);
			if (w < 0) {
				*err = E_ERRNO;
			}
		} else if (revents & POLLHUP) {
			w = 0;
			*err = E_PEER_DISCONNECTED;
		} else {
			w = -1;
			*err = E_UNKNOWN;
		}
	} else {
		w = -1;
		if (ret == 0) {
			*err = E_TIMEOUT;
		} else {
			*err = E_ERRNO;
		}
	}

	return w;
}

struct fsnp_msg *fsnp_read_msg_tcp(int sock, uint16_t timeout, ssize_t *r,
                                   fsnp_err_t *err)
{
	struct fsnp_msg header;
	struct fsnp_msg *msg = NULL;
	char *m = NULL;
	size_t header_size = sizeof(header);
	int ret = 0;
	ssize_t r1 = 0;
	ssize_t r2 = 0;

	if (timeout == 0) {
		timeout = FSNP_TIMEOUT;
	}

	// try to read the header file
	r1 = fsnp_timed_read(sock, &header, header_size, timeout, err);
	if (r1 < 0) {
		if (r) {
			*r = r1;
		}
		return NULL;
	}

	ret = strncmp((char *)header.magic, FSNP_MAGIC, FSNP_MAGIC_SIZE);
	if (ret != 0) {
		// not an fsnp message
		*err = E_NOT_FSNP_MSG;
		return NULL;
	}

	msg = malloc(header.msg_size + header_size);
	if (!msg) {
		*err = E_OUT_OF_MEM;
		return NULL;
	}

	// copy the header to the message
	memcpy(msg, &header, header_size);

	// DO NOT attempt a second read in these cases
	if (msg->msg_type == ACK || msg->msg_type == LEAVE || msg->msg_type == ALIVE
		|| msg->msg_type == ERROR) {
		if (r) {
			*r = r1;
		}

		return msg;
	}

	// read the rest of the message
	m = ((char *)msg) + header_size;
	r2 = fsnp_timed_read(sock, m, header.msg_size, FSNP_TIMEOUT, err);
	if (r2 < 0) {
		if (r) {
			*r = r1;
		}
		free(msg);
		return NULL;
	}
	if (r) {
		*r = r1 + r2;
	}

	*err = E_NOERR;
	return msg;
}

ssize_t fsnp_write_msg_tcp(int sock, uint16_t timeout,
                           const struct fsnp_msg *msg, fsnp_err_t *err)
{
	size_t tot_size = 0;
	ssize_t w = 0;

	if (timeout == 0) {
		timeout = FSNP_TIMEOUT;
	}

	tot_size = msg->msg_size + sizeof(struct fsnp_msg);
	w = fsnp_timed_write(sock, msg, tot_size, timeout, err);
	if (w == (ssize_t)tot_size) {
		*err = E_NOERR;
	}

	return w;
}

#define NULL_CHECK(param) { \
								if ((param) == NULL) { \
									return E_INVALID_PARAM; \
								} \
							}

fsnp_err_t fsnp_send_query(int sock, const struct fsnp_query *query)
{
	fsnp_err_t err;

	NULL_CHECK(query);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)query, &err);

	return err;
}

fsnp_err_t fsnp_send_query_res(int sock, const struct fsnp_query_res *query_res)
{
	fsnp_err_t err;

	NULL_CHECK(query_res);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)query_res, &err);

	return err;
}

fsnp_err_t fsnp_send_add_sp(int sock, const struct fsnp_add_sp *add_sp)
{
	fsnp_err_t err;

	NULL_CHECK(add_sp);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)add_sp, &err);

	return err;
}

fsnp_err_t fsnp_send_rm_sp(int sock, const struct fsnp_rm_sp *rm_sp)
{
	fsnp_err_t err;

	NULL_CHECK(rm_sp);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)rm_sp, &err);

	return err;
}

fsnp_err_t fsnp_send_join(int sock, const struct fsnp_join *join)
{
	fsnp_err_t err;

	NULL_CHECK(join);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)join, &err);

	return err;
}

fsnp_err_t fsnp_send_ack(int sock, const struct fsnp_ack *ack)
{
	fsnp_err_t err;

	NULL_CHECK(ack);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)ack, &err);

	return err;
}

fsnp_err_t fsnp_send_leave(int sock, const struct fsnp_leave *leave)
{
	fsnp_err_t err;

	NULL_CHECK(leave);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)leave, &err);

	return err;
}

fsnp_err_t fsnp_send_file_req(int sock, const struct fsnp_file_req *req)
{
	fsnp_err_t err;
	NULL_CHECK(req);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)req, &err);

	return err;
}

fsnp_err_t fsnp_send_file_res(int sock, const struct fsnp_file_res *res)
{
	fsnp_err_t err;
	NULL_CHECK(res);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)res, &err);

	return err;
}

fsnp_err_t fsnp_send_update(int sock, const struct fsnp_update *update)
{
	fsnp_err_t err;
	NULL_CHECK(update);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)update, &err);

	return err;
}

fsnp_err_t fsnp_send_alive(int sock, const struct fsnp_alive *alive)
{
	fsnp_err_t err;
	NULL_CHECK(alive);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)alive, &err);

	return err;
}

fsnp_err_t fsnp_send_get_file(int sock, const struct fsnp_get_file *get_file)
{
	fsnp_err_t err;
	NULL_CHECK(get_file);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)get_file, &err);

	return err;
}

fsnp_err_t fsnp_send_error(int sock, const struct fsnp_error *error)
{
	fsnp_err_t err;
	NULL_CHECK(error);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)error, &err);

	return err;
}

fsnp_err_t fsnp_send_download(int sock, const struct fsnp_download *download)
{
	fsnp_err_t err;
	NULL_CHECK(download);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)download, &err);

	return err;
}

fsnp_err_t fsnp_send_promote(int sock, const struct fsnp_promote *promote)
{
	fsnp_err_t err;
	NULL_CHECK(promote);
	fsnp_write_msg_tcp(sock, 0, (const struct fsnp_msg *)promote, &err);

	return err;
}

#undef NULL_CHECK