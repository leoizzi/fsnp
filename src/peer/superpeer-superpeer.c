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
#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <errno.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <struct/hashtable.h>

#include "peer/superpeer-superpeer.h"
#include "peer/superpeer.h"
#include "peer/thread_manager.h"
#include "peer/peer.h"

#include "fsnp/fsnp.h"

#include "slog/slog.h"

// TODO: what to do if the neighbors field are set to this peer?

struct neighbors_flag {
	uint8_t next_set : 1;
	uint8_t snd_next_set : 1;
	uint8_t prev_set : 1;
};

struct neighbors {
	struct fsnp_peer next;
	struct fsnp_peer snd_next;
	struct fsnp_peer prev;
	struct neighbors_flag flags;
	char next_pretty[32];
	char snd_next_pretty[32];
	char prev_pretty[32];
};

#define SET_NEXT(flags) (flags).next_set = 1
#define GET_NEXT(flags) (flags).next_set
#define UNSET_NEXT(flags) (flags).next_set = 0

#define SET_SND_NEXT(flags) (flags).snd_next_set = 1
#define GET_SND_NEXT(flags) (flags).snd_next_set
#define UNSET_SND_NEXT(flags) (flags).snd_next_set = 0

#define SET_PREV(flags) (flags).prev_set = 1
#define GET_PREV(flags) (flags).prev_set
#define UNSET_PREV(flags) (flags).prev_set = 0

/*
 * Set the next sp as 'addr'
 */
static inline void set_next(struct neighbors *nb, const struct fsnp_peer *addr)
{
	struct in_addr a;

    memcpy(&nb->next, (addr), sizeof(struct fsnp_peer));
    memset(&nb->next_pretty, 0, sizeof(char) * 32);
    SET_NEXT(nb->flags);
    a.s_addr = htonl((addr)->ip);
    snprintf(nb->next_pretty, sizeof(char) * 32, "%s:%hu", inet_ntoa(a),
    		(addr)->port);
    slog_info(FILE_LEVEL, "Setting next sp to %s", nb->next_pretty);
}

/*
 * Return true if the next sp is known, false otherwise
 */
static always_inline bool isset_next(const struct neighbors *nb)
{
	return GET_NEXT(nb->flags) ? true : false;
}

/*
 * Compare a fsnp_peer with the next. If they match return true, false otherwise
 */
static inline bool cmp_next(const struct neighbors *nb, const struct fsnp_peer *p)
{
	if (nb->next.ip == p->ip) {
		if (nb->next.port == p->port) {
			return true;
		}
	}

	return false;
}

/*
 * Compare the address stored as next against the address of this superpeer.
 * If they match return true, false otherwise
 */
static inline bool cmp_next_against_self(const struct neighbors *nb)
{
	struct fsnp_peer self;

	self.ip = get_peer_ip();
	self.port = get_udp_sp_port();

	return cmp_next(nb, &self);
}

/*
 * Remove the next sp
 */
static inline void unset_next(struct neighbors *nb)
{
	memset(&nb->next, 0, sizeof(struct fsnp_peer));
    memset(nb->next_pretty, 0, sizeof(char) * 32);
    UNSET_NEXT(nb->flags);
    slog_info(FILE_LEVEL, "next sp unset");
}

/*
 * Set the snd_next sp as 'addr'
 */
static inline void set_snd_next(struct neighbors *nb,
		const struct fsnp_peer *addr)
{
	struct in_addr a;

	memcpy(&nb->snd_next, (addr), sizeof(struct fsnp_peer));
	memset(&nb->snd_next_pretty, 0, sizeof(char) * 32);
	SET_SND_NEXT(nb->flags);
	a.s_addr = htonl((addr)->ip);
    snprintf(nb->snd_next_pretty, sizeof(char) * 32, "%s:%hu", inet_ntoa(a),
    		(addr)->port);
    slog_info(FILE_LEVEL, "Setting snd_next sp to %s", nb->snd_next_pretty);
}

/*
 * Return true if the snd_next sp is known, false otherwise
 */
static always_inline int isset_snd_next(const struct neighbors *nb)
{
	return GET_SND_NEXT(nb->flags) ? true : false;
}

/*
 * Compare a fsnp_peer with the snd_next. If they match return true, false
 * otherwise
 */
static inline bool cmp_snd_next(const struct neighbors *nb,
		const struct fsnp_peer *p)
{
	if (nb->snd_next.ip == p->ip) {
		if (nb->snd_next.port == p->port) {
			return true;
		}
	}

	return false;
}

/*
 * Compare the address stored as snd_next against the address of this superpeer.
 * If they match return true, false otherwise
 */
static inline bool cmp_snd_next_against_self(const struct neighbors *nb)
{
	struct fsnp_peer self;

	self.ip = get_peer_ip();
	self.port = get_udp_sp_port();

	return cmp_snd_next(nb, &self);
}

/*
 * Remove the snd_next sp
 */
static inline void unset_snd_next(struct neighbors *nb)
{
	memset(&nb->snd_next, 0, sizeof(struct fsnp_peer));
    memset(nb->snd_next_pretty, 0, sizeof(char) * 32);
    UNSET_SND_NEXT(nb->flags);
    slog_info(FILE_LEVEL, "snd_next sp unset");
}

/*
 * Set the next as snd_next, unsetting the snd_next
 */
static inline void set_next_as_snd_next(struct neighbors *nb)
{
	unset_next(nb);
	set_next(nb, &nb->snd_next);
	unset_snd_next(nb);
}

/*
 * Set the prev sp as 'addr'
 */
static inline void set_prev(struct neighbors *nb, const struct fsnp_peer *addr)
{
	struct in_addr a;

    memcpy(&nb->prev, addr, sizeof(struct fsnp_peer));
	memset(&nb->prev_pretty, 0, sizeof(char) * 32);
   SET_PREV(nb->flags);
    a.s_addr = htonl(addr->ip);
    snprintf(nb->prev_pretty, sizeof(char) * 32, "%s:%hu", inet_ntoa(a),
    		addr->port);
    slog_info(FILE_LEVEL, "Setting prev sp to %s", nb->prev_pretty);
}

/*
 * Return true if the prev sp is known, false otherwise
 */
static always_inline int isset_prev(const struct neighbors *nb)
{
	return GET_PREV(nb->flags) ? true : false;
}

/*
 * Compare a fsnp_peer with the prev. If they match return true, false otherwise
 */
static inline bool cmp_prev(const struct neighbors *nb, const struct fsnp_peer *p)
{
	if (nb->prev.ip == p->ip) {
		if (nb->prev.port == p->port) {
			return true;
		}
	}

	return false;
}

/*
 * Compare the address stored as prev against the address of this superpeer.
 * If they match return true, false otherwise
 */
static inline bool cmp_prev_against_self(const struct neighbors *nb)
{
	struct fsnp_peer self;

	self.ip = get_peer_ip();
	self.port = get_udp_sp_port();

	return cmp_prev(nb, &self);
}

/*
 * Remove the prev sp
 */
static inline void unset_prev(struct neighbors *nb)
{
	memset(&nb->prev, 0, sizeof(struct fsnp_peer));
    memset(nb->prev_pretty, 0, sizeof(char) * 32);
    UNSET_PREV(nb->flags);
    slog_info(FILE_LEVEL, "prev sp unset");
}

/*
 * Clear every entry in the neighbors struct
 */
static void unset_all(struct neighbors *nb)
{
	if (isset_next(nb)) {
		unset_next(nb);
	}

	if (isset_snd_next(nb)) {
		unset_snd_next(nb);
	}

	if (isset_prev(nb)) {
		unset_prev(nb);
	}
}

#undef SET_NEXT
#undef GET_NEXT
#undef UNSET_NEXT
#undef SET_SND_NEXT
#undef GET_SND_NEXT
#undef UNSET_SND_NEXT
#undef SET_PREV
#undef GET_PREV
#undef UNSET_PREV

struct request {
	struct fsnp_peer peer;
	struct timespec creation_time;
};

struct sp_udp_state {
	int sock;
	int pipe[2];
	struct neighbors *nb;
	struct timespec last;
	hashtable_t *reqs; // key: sha256_t     value: request
	bool should_exit;
};

#define READ_END 0
#define WRITE_END 1

#define NSEC_TO_SEC(ns) ((double)(ns) / 1000000000.)
#define INVALIDATE_THRESHOLD 2. // minutes

#define VALIDATED 0
#define INVALIDATED_NO_SND 1
#define INVALIDATED_YES_SND 2

/*
 * Copy the content of b in a
 */
static inline void swap_timespec(struct timespec *a, const struct timespec *b)
{
	a->tv_sec = b->tv_sec;
	a->tv_nsec = b->tv_nsec;
}

/*
 * Update 't' to the current time
 */
static inline void update_timespec(struct timespec *t)
{
	clock_gettime(CLOCK_MONOTONIC, t);
}

/*
 * Invalidate the next field if needed. In case it's needed the swap with the
 * snd_next (if present) will be done.
 * On output in last will be found the values present in curr.
 *
 * - Return VALIDATED if the superpeer has listened the next in two minutes
 * - Return INVALIDATED_NO_SND if the next was invalidated but no snd_next is
 *      known
 * - Return INVALIDATED_YES_SND if the next was invalidated and a swap with the
 *      snd_next was accomplished
 */
static int invalidate_next_if_needed(struct neighbors *nb,
                                     struct timespec *last,
                                     const struct timespec *curr)
{
	double l = 0;
	double c = 0;

	l = (double)last->tv_sec + NSEC_TO_SEC(last->tv_nsec);
	c = (double)curr->tv_sec + NSEC_TO_SEC(curr->tv_nsec);
	swap_timespec(last, curr);
	if (c - l < INVALIDATE_THRESHOLD) {
		return VALIDATED;
	}

	if (isset_snd_next(nb)) {
		slog_info(FILE_LEVEL, "Next '%s' invalidated.", nb->next_pretty);
		set_next_as_snd_next(nb);
		return INVALIDATED_YES_SND;
	} else {
		slog_info(FILE_LEVEL, "Next '%s' invalidated. No snd_next to substitute"
						" it.", nb->next_pretty);
		unset_next(nb);
		return INVALIDATED_NO_SND;
	}
}

#undef NSEC_TO_SEC
#undef INVALIDATE_THRESHOLD

/*
 * Send a promoted msg to the next sp
 */
static void send_promoted(const struct sp_udp_state *sus)
{
	struct fsnp_promoted promoted;
	fsnp_err_t err;

	if (cmp_prev_against_self(sus->nb)) {
		return;
	}

	fsnp_init_promoted(&promoted);
	slog_info(FILE_LEVEL, "Sending an updated msg to %s", sus->nb->prev_pretty);
	err = fsnp_send_promoted(sus->sock, 0, &promoted, &sus->nb->prev);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Send a NEXT msg to the next sp. Pass NULL in 'old' if the next doesn't have
 * to change its next.
 */
static void send_next(const struct sp_udp_state *sus,
		const struct fsnp_peer *old)
{
	struct fsnp_next next;
	fsnp_err_t err;
	struct in_addr addr;

	if (cmp_next_against_self(sus->nb)) {
		return;
	}

	fsnp_init_next(&next, old);
	if (old) {
		addr.s_addr = htonl(old->ip);
		slog_info(FILE_LEVEL, "Sending a NEXT msg to %s with old_peer %s:%hu",
				sus->nb->next_pretty, inet_ntoa(addr), old->port);
	} else {
		slog_info(FILE_LEVEL, "Sending a NEXT msg to %s without old_peer",
				sus->nb->next_pretty)
	}

	err = fsnp_send_next(sus->sock, 0, &next, &sus->nb->next);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

struct sender {
	struct fsnp_peer addr;
	char pretty_addr[32];
};

/*
 * Compare sender against this superpeer address. If they match return true,
 * false otherwise
 */
static bool cmp_sender_against_self(const struct sender *sender)
{
	struct fsnp_peer self;

	self.ip = get_peer_ip();
	self.port = get_udp_sp_port();
	if (self.ip == sender->addr.ip && self.port == sender->addr.port) {
		return true;
	} else {
		return false;
	}
}

/*
 * Send an ACK msg to s
 */
static void send_ack(const struct sp_udp_state *sus, const struct sender *s)
{
	struct fsnp_ack ack;
	fsnp_err_t err;

	if (cmp_sender_against_self(s)) {
		return;
	}

	slog_info(FILE_LEVEL, "Sending an ACK msg to %s", s->pretty_addr);
	err = fsnp_send_udp_ack(sus->sock, 0, &ack, &s->addr);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Send a WHOSNEXT msg to s
 */
static void send_whosnext(const struct sp_udp_state *sus,
		const struct fsnp_whosnext *whosnext, const struct sender *s)
{
	fsnp_err_t err;

	if (cmp_sender_against_self(s)) {
		return;
	}

	slog_info(FILE_LEVEL, "Sending a WHOSNEXT msg to %s", s->pretty_addr);
	err = fsnp_send_whosnext(sus->sock, 0, whosnext, &s->addr);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Make sure that the prev will send a NEXT msg. If the timer will fire, send a
 * NEXT msg to his prev, which is stored in the snd_next position
 */
static void ensure_prev_conn(const struct sp_udp_state *sus)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_next *next = NULL;
	struct fsnp_peer p;
	fsnp_err_t err;
	unsigned counter = 0;

	if (cmp_prev_against_self(sus->nb)) {
		return;
	}

	while (true) {
		msg = fsnp_timed_recvfrom(sus->sock, 0, &p, &err);
		if (!msg && counter >= 4) {
			slog_warn(FILE_LEVEL, "Unable to receive a next msg from the prev");
			unset_prev(sus->nb);
			fsnp_log_err_msg(err, false);
			if (isset_snd_next(sus->nb)) {
				counter = 0;
				set_prev(sus->nb, &sus->nb->snd_next);
				unset_snd_next(sus->nb);
				continue;
			} else {
				slog_warn(FILE_LEVEL, "Unable to ensure the prev's connection");
				slog_warn(STDOUT_LEVEL, "Please join the network again");
				unset_all(sus->nb);
				prepare_exit_sp_mode();
				exit_sp_mode();
				return;
			}
		} else {
			fsnp_log_err_msg(err, false);
			counter++;
			slog_info(FILE_LEVEL, "Trying to contact for the %d time the prev",
			          counter);
			send_promoted(sus);
		}

		if (!cmp_prev(sus->nb, &p)) {
			free(msg);
			continue;
		} else {
			break;
		}
		// do this until the msg on the socket is from our promoter
	}

	if (isset_snd_next(sus->nb)) { // clear neighbors from the HACK
		unset_snd_next(sus->nb);
	}

	if (msg->msg_type != NEXT) {
		slog_warn(FILE_LEVEL, "Wrong msg type received from %s: expected %u, "
						"got %u", sus->nb->prev_pretty, NEXT, msg->msg_type);
		free(msg);
		slog_warn(STDOUT_LEVEL, "Please join the network again");
		unset_all(sus->nb);
		prepare_exit_sp_mode();
		exit_sp_mode();
		return;
	}

	slog_info(FILE_LEVEL, "NEXT msg received from prev %s", sus->nb->prev_pretty);
	next = (struct fsnp_next *)msg;
	if (next->old_next.ip != 0 && next->old_next.port != 0) {
		set_next(sus->nb, &next->old_next);
	}

	free(next);
}

/*
 * Make sure that the next will send
 */
static void ensure_next_conn(struct sp_udp_state *sus)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_peer p;
	fsnp_err_t err;
	unsigned counter = 0;

	if (cmp_next_against_self(sus->nb)) {
		return;
	}

	while (true) {
		msg = fsnp_timed_recvfrom(sus->sock, 0, &p, &err);
		if (!msg && counter >= 4) {
			slog_warn(FILE_LEVEL, "Unable to ensure next's connection");
			fsnp_log_err_msg(err, false);
			slog_warn(STDOUT_LEVEL, "Please join the network again");
			prepare_exit_sp_mode();
			exit_sp_mode();
			sus->should_exit = true;
			return;
		} else {
			fsnp_log_err_msg(err, false);
			counter++;
			slog_info(FILE_LEVEL, "Trying to contact for the %d time the next",
					counter);
			send_next(sus, NULL);
		}

		if (!cmp_next(sus->nb, &p)) {
			free(msg);
			continue;
		} else {
			break;
		}
	}

	if (msg->msg_type != ACK) {
		slog_warn(FILE_LEVEL, "Wrong msg type received from %s: expected %u, "
		                      "got %u", sus->nb->next_pretty, NEXT, msg->msg_type);
	}

	free(msg);
}

#define POLLFD_NUM 2
#define PIPE 0
#define SOCK 1

/*
 * Setup the pollfd structures
 */
static void setup_poll(struct pollfd *pollfd, const struct sp_udp_state *sus)
{
	memset(pollfd, 0, sizeof(struct pollfd) * POLLFD_NUM);

	pollfd[PIPE].fd = sus->pipe[READ_END];
	pollfd[PIPE].events = POLLIN | POLLPRI;
	pollfd[SOCK].fd = sus->sock;
	pollfd[SOCK].events = POLLIN | POLLPRI;
}

/*
 * Read a message received on the pipe
 */
static void read_pipe_msg(struct sp_udp_state *sus)
{
	// TODO: implement
	UNUSED(sus);
}

/*
 * Handle an event occurred on the pipe
 */
static void pipe_event(struct sp_udp_state *sus, short revents)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		read_pipe_msg(sus);
	} else {
		slog_error(FILE_LEVEL, "pipe revents: %d", revents);
		prepare_exit_sp_mode();
		exit_sp_mode();
		sus->should_exit = true;
	}
}

/*
 * Write into sender.pretty_addr the string representation of sender's addr
 */
static void stringify_sender(const struct neighbors *nb, struct sender *sender)
{
	struct in_addr a;

	if (cmp_next(nb, &sender->addr)) {
		strncpy(sender->pretty_addr, nb->next_pretty, sizeof(char) * 32);
	} else if (cmp_prev(nb, &sender->addr)) {
		strncpy(sender->pretty_addr, nb->prev_pretty, sizeof(char) * 32);
	} else if (cmp_snd_next(nb, &sender->addr)) {
		strncpy(sender->pretty_addr, nb->snd_next_pretty, sizeof(char) * 32);
	} else {
		memset(sender->pretty_addr, 0, sizeof(char) * 32);
		a.s_addr = htonl(sender->addr.ip);
		snprintf(sender->pretty_addr, sizeof(char) * 32, "%s:%hu", inet_ntoa(a),
		         sender->addr.port);
	}
}

/*
 * Handler called when a NEXT msg is received
 */
static void next_msg_rcvd(struct sp_udp_state *sus, const struct fsnp_next *next,
		const struct sender *sender)
{
	slog_info(FILE_LEVEL, "NEXT msg received from %s", sender->pretty_addr);
	if (next->old_next.ip != 0 && next->old_next.port) {
		set_next(sus->nb, &next->old_next);
		send_next(sus, NULL);
	}

	send_ack(sus, sender);
}

/*
 * Handler called when a PROMOTED msg is received
 */
static void promoted_msg_rcvd(struct sp_udp_state *sus,
		const struct fsnp_promoted *promoted, const struct sender *sender)
{
	UNUSED(promoted);

	slog_info(FILE_LEVEL, "PROMOTED msg received from %s", sender->pretty_addr);
	set_prev(sus->nb, &sender->addr);
	send_ack(sus, sender);
}

/*
 * Handler called when a WHOSNEXT msg is received
 */
static void whosnext_msg_rcvd(struct sp_udp_state *sus,
		struct fsnp_whosnext *whosnext, const struct sender *sender)
{
	slog_info(FILE_LEVEL, "WHOSNEXT msg received from %s", sender->pretty_addr);
	if (whosnext->next.ip == 0 && whosnext->next.port == 0) {
		memcpy(&whosnext->next, &sus->nb->next, sizeof(struct fsnp_peer));
		send_whosnext(sus, whosnext, sender);
	} else {
		if (cmp_snd_next(sus->nb, &whosnext->next)) {
			return;
		}

		if (isset_snd_next(sus->nb)) {
			unset_snd_next(sus->nb);
		}

		set_snd_next(sus->nb, &whosnext->next);
	}
}

/*
 * Handler called when a WHOHAS msg is received
 */
static void whohas_msg_rcvd(struct sp_udp_state *sus,
		const struct fsnp_whohas *whohas, const struct sender *sender)
{
	// TODO: continue from here
}

/*
 * Handler called when a LEAVE msg is received
 */
static void leave_msg_rcvd(struct sp_udp_state *sus,
		const struct fsnp_leave *leave, const struct sender *sender)
{

}

/*
 * Read a message sent on the socket
 */
static void read_sock_msg(struct sp_udp_state *sus)
{
	struct fsnp_msg *msg = NULL;
	fsnp_err_t err;
	struct sender sender;

	msg = fsnp_timed_recvfrom(sus->sock, 0, &sender.addr, &err);
	if (!msg) {
		fsnp_log_err_msg(err, false);
		return;
	}

	if (cmp_next(sus->nb, &sender.addr)) {
		update_timespec(&sus->last);
	}

	stringify_sender(sus->nb, &sender);
	switch (msg->msg_type) {
		case NEXT:
			next_msg_rcvd(sus, (const struct fsnp_next *)msg, &sender);
			break;

		case PROMOTED:
			promoted_msg_rcvd(sus, (const struct fsnp_promoted *)msg, &sender);
			break;

		case WHOSNEXT:
			whosnext_msg_rcvd(sus, (struct fsnp_whosnext *)msg, &sender);
			break;

		case WHOHAS:
			whohas_msg_rcvd(sus, (const struct fsnp_whohas *)msg, &sender);
			break;

		case ACK:
			slog_info(FILE_LEVEL, "ACK msg received from %s", sender.pretty_addr);
			break;

		case LEAVE:
			leave_msg_rcvd(sus, (const struct fsnp_leave *)msg, &sender);
			break;

		default:
			slog_warn(FILE_LEVEL, "Unexpected msg_type received on sp_udp_sock "
						 "= %u", msg->msg_type);
			break;
	}

	free(msg);
}

/*
 * Handle an event occurred on the socket
 */
static void sock_event(struct sp_udp_state *sus, short revents)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		read_sock_msg(sus);
	} else if (revents & POLLHUP) { // ???
		return;
	} else {
		slog_error(FILE_LEVEL, "sock revents: %d", revents);
		prepare_exit_sp_mode();
		exit_sp_mode();
		sus->should_exit = true;
	}
}

/*
 * Called to check the next's aliveness. If the next is considered dead it will
 * contact the snd_next to set it as next
 */
static void check_next_aliveness(struct sp_udp_state *sus)
{
	struct timespec curr;
	int ret = 0;

	clock_gettime(CLOCK_MONOTONIC, &curr);
	ret = invalidate_next_if_needed(sus->nb, &sus->last, &curr);
	switch (ret) {
		case VALIDATED:
			break;

		case INVALIDATED_NO_SND: // FIXME: maybe this case is useless? Or here we can send a WHOSNEXT msg?
			break;

		case INVALIDATED_YES_SND:
			send_next(sus, NULL);
			ensure_next_conn(sus);
			break;

		default:
			slog_panic(FILE_LEVEL, "Unknown return from invalidate_next_if_needed");
			break;
	}
}

/*
 * Invalidate any request that has expired
 */
static void invalidate_requests(struct sp_udp_state *sus)
{
	if (ht_count(sus->reqs) == 0) {
		return;
	}

	// TODO: implement
}

#define POLL_TIMEOUT 30000 // ms

/*
 * Entry point for the superpeer's udp subsystem.
 */
static void sp_udp_thread(void *data)
{
	struct sp_udp_state *sus = (struct sp_udp_state *)data;
	struct pollfd pollfd[POLLFD_NUM];
	int ret = 0;

	send_promoted(sus);
	ensure_prev_conn(sus);
	send_next(sus, NULL);
	ensure_next_conn(sus);
	clock_gettime(CLOCK_MONOTONIC, &sus->last);

	setup_poll(pollfd, sus);
	while (!sus->should_exit) {
		ret = poll(pollfd, POLLFD_NUM, POLL_TIMEOUT);
		invalidate_requests(sus);
		if (ret > 0) {
			if (pollfd[PIPE].revents) {
				pipe_event(sus, pollfd[PIPE].revents);
				pollfd[PIPE].revents = 0;
			}

			if (pollfd[SOCK].revents) {
				sock_event(sus, pollfd[SOCK].revents);
				pollfd[SOCK].revents = 0;
			}

			check_next_aliveness(sus);
		} else if (ret == 0) {
			check_next_aliveness(sus);
		} else {
			slog_error(FILE_LEVEL, "poll error %d");
			prepare_exit_sp_mode();
			exit_sp_mode();
			sus->should_exit = true;
		}
	}

	ht_destroy(sus->reqs);
	free(sus->nb);
	close(sus->sock);
	close(sus->pipe[READ_END]);
	close(sus->pipe[WRITE_END]);
	// Don't free sus, it will be freed by the thread_manager
}

#undef POLLFD_NUM
#undef PIPE
#undef SOCK
#undef POLL_TIMEOUT
#undef INVALIDATED_NO_SND
#undef INVALIDATED_YES_SND
#undef VALIDATED

/*
 * Free callback for the reqs hashtable
 */
static void reqs_free_callback(void *data)
{
	struct request *r = (struct request *)data;
	free(r);
}

#define NO_SP 0
#define ONE_SP 1
#define TWO_SPS 2

#define REQS_SIZE_MAX 1UL << 16UL

int enter_sp_network(int udp, const struct fsnp_peer *sps, unsigned n)
{
	int ret = 0;
	struct sp_udp_state *sus = NULL;
	struct fsnp_peer self;

	sus = calloc(1, sizeof(struct sp_udp_state));
	if (!sus) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		return -1;
	}

	sus->nb = calloc(1, sizeof(struct neighbors));
	if (!sus->nb) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		free(sus);
		return -1;
	}

	sus->reqs = ht_create(HT_SIZE_MIN, REQS_SIZE_MAX, reqs_free_callback);
	if (!sus->reqs) {
		slog_error(FILE_LEVEL, "Unable to create reqs hashtable");
		free(sus->nb);
		free(sus);
		return -1;
	}

	ret = pipe(sus->pipe);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Pipe error %d", errno);
		ht_destroy(sus->reqs);
		free(sus->nb);
		free(sus);
		return -1;
	}

	sus->sock = udp;
	sus->should_exit = false;
	self.ip = get_peer_ip();
	self.port = get_udp_sp_port();
	switch (n) {
		case NO_SP:
			set_prev(sus->nb, &self);
			set_next(sus->nb, &self);
			set_snd_next(sus->nb, &self);
			break;

		case ONE_SP:
			set_prev(sus->nb, sps);
			set_next(sus->nb, &self);
			set_snd_next(sus->nb, &self);
			break;

		case TWO_SPS:
			set_prev(sus->nb, &sps[0]);
			set_next(sus->nb, &self);
			/* HACK:
			 * at the beginning store the address of the second prev in
			 * the snd_next, because this field will not be used at the
			 * beginning and we need the address of the second_prev only at
			 * startup
			 */
			set_snd_next(sus->nb, &sps[1]);
			break;

		default:
			slog_error(FILE_LEVEL, "Wrong parameter: n can't be %u", n);
			ht_destroy(sus->reqs);
			free(sus->nb);
			free(sus);
			return -1;
	}

	ret = start_new_thread(sp_udp_thread, sus, "sp-udp-thread");
	if (ret < 0) {
		sus->sock = 0;
		ht_destroy(sus->reqs);
		free(sus->nb);
		free(sus);
		return -1;
	}

	return 0;
}

#undef NO_SP
#undef ONE_SP
#undef TWO_SPS

void exit_sp_network(void)
{
	// TODO: implement. write into the pipe to close
}

#undef READ_END
#undef WRITE_END
