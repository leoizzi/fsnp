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
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <memory.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <poll.h>

#include "fsnp/fsnp.h"

#define FSNP_MAGIC_SIZE 4

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

static fsnp_err_t errno_check(void)
{
	switch (errno) {
		case ECONNRESET:
		case EHOSTUNREACH:
		case ENETDOWN:
			return E_PEER_DISCONNECTED;

		case EMSGSIZE:
		case EINVAL: // read the man page of recvfrom for why this is here
			return E_MSG_TOO_BIG;

		case ENOBUFS:
		case ENOMEM:
			return E_OUT_OF_MEM;

		case EBADF:
		case EFAULT:
		case ENOTSOCK:
		case EAFNOSUPPORT:
			return E_INVALID_PARAM;

		case ETIMEDOUT:
			return E_TIMEOUT;

		default:
			return E_ERRNO;
	}
}

fsnp_err_t fsnp_sendto(int sock, const struct fsnp_msg *msg,
                       const struct fsnp_peer *peer)
{
	struct sockaddr_in addr;
	socklen_t socklen = sizeof(addr);
	ssize_t w = 0;
	size_t msg_size = 0;

	msg_size = msg->msg_size + sizeof(struct fsnp_msg);
	if (msg_size > MAX_UDP_PKT_SIZE) {
		return E_MSG_TOO_BIG;
	}

	memset(&addr, 0, socklen);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(peer->ip);
	addr.sin_port = htons(peer->port);

	w = sendto(sock, msg, msg_size, 0, (const struct sockaddr *)&addr, socklen);
	if (w > 0) {
		return E_NOERR;
	} else if (w == 0) {
		return E_PEER_DISCONNECTED;
	} else {
		return errno_check();
	}
}

struct fsnp_msg *fsnp_recvfrom(int sock, struct fsnp_peer *peer, fsnp_err_t *err)
{
	struct sockaddr_in addr;
	socklen_t socklen = sizeof(addr);
	struct fsnp_msg *msg = NULL;
	char buf[MAX_UDP_PKT_SIZE];
	struct fsnp_msg header;
	ssize_t r = 0;
	int ret = 0;

	memset(&addr, 0, socklen);
	memset(buf, 0, sizeof(buf));
	r = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &socklen);
	if (r < 0) {
		*err = errno_check();
		return NULL;
	} else if (r == 0) {
		*err = E_PEER_DISCONNECTED;
		return NULL;
	}

	if (r < (ssize_t)sizeof(header)) { // the packet doesn't belong to the protocol
		*err = E_NOT_FSNP_MSG;
		return NULL;
	}

	memcpy(&header, buf, sizeof(header));
	ret = strncmp((char *)header.magic, FSNP_MAGIC, FSNP_MAGIC_SIZE);
	if (ret != 0) {
		// not an fsnp message
		*err = E_NOT_FSNP_MSG;
		return NULL;
	}

	msg = malloc(sizeof(header) + header.msg_size);
	if (!msg) {
		*err = E_OUT_OF_MEM;
		return NULL;
	}

	*err = E_NOERR;
	peer->ip = ntohl(addr.sin_addr.s_addr);
	peer->port = ntohs(addr.sin_port);
	memcpy(msg, buf, sizeof(header) + header.msg_size);
	return msg;
}
/*
struct fsnp_msg *fsnp_recvfrom(int sock, struct fsnp_peer *peer,
							   fsnp_err_t *err)
{
	struct sockaddr_in addr;
	socklen_t socklen = sizeof(addr);
	struct fsnp_msg *msg = NULL;
	struct fsnp_msg header;
	size_t h_size = sizeof(header);
	ssize_t r = 0;
	int ret = 0;
	char *m = NULL;

	memset(&addr, 0, socklen);
	memset(&header, 0, h_size);
	// try to read the header
	r = recvfrom(sock, &header, h_size, 0, (struct sockaddr *)&addr, &socklen);
	if (r < 0) {
		*err = errno_check();
		return NULL;
	} else if (r == 0) {
		*err = E_PEER_DISCONNECTED;
		return NULL;
	}

	ret = strncmp((char *)header.magic, FSNP_MAGIC, FSNP_MAGIC_SIZE);
	if (ret != 0) {
		// not an fsnp message
		*err = E_NOT_FSNP_MSG;
		return NULL;
	}

	msg = malloc(h_size + header.msg_size);
	if (!msg) {
		*err = E_OUT_OF_MEM;
		return NULL;
	}

	*err = E_NOERR;
	peer->ip = ntohl(addr.sin_addr.s_addr);
	peer->port = ntohs(addr.sin_port);
	memcpy(msg, &header, h_size);
	// DO NOT attempt a second read in this case
	if (msg->msg_size == 0) {
		return msg;
	}

	// prepare for a new recvfrom
	socklen = sizeof(addr);
	memset(&addr, 0, socklen);
	m = ((char *)msg) + h_size;
	// try to read the rest of the message
	r = recvfrom(sock, m, msg->msg_size, 0, (struct sockaddr *)&addr, &socklen);
	if (r < 0) {
		*err = errno_check();
		free(msg);
		return NULL;
	} else if (r == 0) {
		free(msg);
		*err = E_PEER_DISCONNECTED;
		return NULL;
	}

	return msg;
}
 */

fsnp_err_t fsnp_timed_sendto(int sock, timeout_t timeout,
                             const struct fsnp_msg *msg,
                             const struct fsnp_peer *peer)
{
	struct pollfd pollfd;
	int t = 0;
	int ret = 0;
	short revents = 0;
	fsnp_err_t err;

	if (timeout == 0) {
		t = FSNP_TIMEOUT;
	} else {
		t = timeout;
	}

	pollfd.fd = sock;
	pollfd.events = POLLOUT;
	pollfd.revents = 0;
	ret = poll(&pollfd, 1, t);
	if (ret > 0) {
		revents = pollfd.revents;
		if (revents & POLLOUT || revents & POLLWRBAND) {
			err = fsnp_sendto(sock, msg, peer);
		} else if (revents & POLLHUP) {
			err = E_PEER_DISCONNECTED;
		} else {
			err = E_UNKNOWN;
		}
	} else if (ret == 0) {
		err = E_TIMEOUT;
	} else {
		err = E_ERRNO;
	}

	return err;
}

struct fsnp_msg *fsnp_timed_recvfrom(int sock, timeout_t timeout,
                                     struct fsnp_peer *peer, fsnp_err_t *err)
{
	struct pollfd pollfd;
	int t = 0;
	int ret = 0;
	short revents = 0;

	pollfd.fd = sock;
	pollfd.events = POLLIN | POLLPRI;
	pollfd.revents = 0;
	if (timeout == 0) {
		t = FSNP_TIMEOUT;
	} else {
		t = timeout;
	}

	ret = poll(&pollfd, 1, t);
	if (ret > 0) {
		revents = pollfd.revents;
		if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
			return fsnp_recvfrom(pollfd.fd, peer, err);
		} else if (revents & POLLHUP) {
			*err = E_PEER_DISCONNECTED;
			return NULL;
		} else {
			*err = E_UNKNOWN;
			return NULL;
		}
	} else if (ret == 0) {
		*err = E_TIMEOUT;
		return NULL;
	} else {
		*err = E_ERRNO;
		return NULL;
	}
}

fsnp_err_t fsnp_send_udp_ack(int sock, timeout_t timeout,
                             const struct fsnp_ack *ack,
                             const struct fsnp_peer *peer)
{
	return fsnp_timed_sendto(sock, timeout, (const struct fsnp_msg *)ack, peer);
}

fsnp_err_t fsnp_send_udp_leave(int sock, timeout_t timeout,
                               const struct fsnp_leave *leave,
                               const struct fsnp_peer *peer)
{
	return fsnp_timed_sendto(sock, timeout, (const struct fsnp_msg *)leave, peer);
}

fsnp_err_t fsnp_send_promoted(int sock, timeout_t timeout,
                              const struct fsnp_promoted *promoted,
                              const struct fsnp_peer *peer)
{
	return fsnp_timed_sendto(sock, timeout, (const struct fsnp_msg *)promoted, peer);
}

fsnp_err_t fsnp_send_next(int sock, timeout_t timeout,
                          const struct fsnp_next *next,
                          const struct fsnp_peer *peer)
{
	return fsnp_timed_sendto(sock, timeout, (const struct fsnp_msg *)next, peer);
}

fsnp_err_t fsnp_send_whosnext(int sock, timeout_t timeout,
                              const struct fsnp_whosnext *whosnext,
                              const struct fsnp_peer *peer)
{
	return fsnp_timed_sendto(sock, timeout, (const struct fsnp_msg *)whosnext, peer);
}

fsnp_err_t fsnp_send_whohas(int sock, timeout_t timeout,
                            const struct fsnp_whohas *whohas,
                            const struct fsnp_peer *peer)
{
	return fsnp_timed_sendto(sock, timeout, (const struct fsnp_msg *)whohas, peer);
}

#undef FSNP_MAGIC_SIZE