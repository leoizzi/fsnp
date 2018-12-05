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

#include "peer/superpeer-superpeer.h"
#include "peer/superpeer.h"
#include "peer/thread_manager.h"
#include "peer/peer.h"
#include "peer/keys_cache.h"
#include "peer/peer-server.h"

#include "fsnp/fsnp.h"

#include "struct/hashtable.h"

#include "slog/slog.h"

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
	struct fsnp_peer self;

	memset(&nb->next, 0, sizeof(struct fsnp_peer));
    memset(nb->next_pretty, 0, sizeof(char) * 32);
    self.ip = get_peer_ip();
    self.port = get_udp_sp_port();
    memcpy(&nb->next, &self, sizeof(struct fsnp_peer));
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
	struct fsnp_peer self;

	memset(&nb->snd_next, 0, sizeof(struct fsnp_peer));
    memset(nb->snd_next_pretty, 0, sizeof(char) * 32);
	self.ip = get_peer_ip();
	self.port = get_udp_sp_port();
	memcpy(&nb->next, &self, sizeof(struct fsnp_peer));
    UNSET_SND_NEXT(nb->flags);
    slog_info(FILE_LEVEL, "snd_next sp unset");
}

/*
 * Set the snd_next as next, then unset the snd_next
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
	struct fsnp_peer self;
	
	memset(&nb->prev, 0, sizeof(struct fsnp_peer));
    memset(nb->prev_pretty, 0, sizeof(char) * 32);
	self.ip = get_peer_ip();
	self.port = get_udp_sp_port();
	memcpy(&nb->next, &self, sizeof(struct fsnp_peer));
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
	struct timespec creation_time;
	bool sent_by_me;
	struct fsnp_peer requester; // this field has a mean only if sent_by_me is true
};

/*
 * Free callback for the reqs hashtable
 */
static void reqs_free_callback(void *data)
{
	struct request *r = (struct request *)data;
	free(r);
}

struct sp_udp_state {
	int sock;
	int r_pipe[2];
	int w_pipe[2];
	struct neighbors *nb;
	struct timespec last;
	hashtable_t *reqs; // key: sha256_t     value: request
	bool should_exit;
};

#define READ_END 0
#define WRITE_END 1

#define NSEC_TO_SEC(ns) ((double)(ns) / 1000000000.)
#define INVALIDATE_THRESHOLD 2. * 60 // 2 minutes

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
 * Calculate the delta of two timespecs (b - a)
 */
static inline double calculate_timespec_delta(const struct timespec *a,
											  const struct timespec *b)
{
	double aa = 0;
	double bb = 0;

	aa = (double)a->tv_sec + NSEC_TO_SEC(a->tv_nsec);
	bb = (double)b->tv_sec + NSEC_TO_SEC(b->tv_nsec);
	return bb - aa;
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
                                     const struct timespec *curr,
                                     struct fsnp_peer *old_next)
{
#ifndef FSNP_INF_TIMEOUT
	
	double delta = 0;

	delta = calculate_timespec_delta(last, curr);
	swap_timespec(last, curr);
	if (delta < INVALIDATE_THRESHOLD) {
		return VALIDATED;
	}

    memcpy(old_next, &nb->next, sizeof(struct fsnp_peer));
	if (isset_snd_next(nb) && !cmp_snd_next_against_self(nb)) {
		slog_info(FILE_LEVEL, "Next '%s' invalidated.", nb->next_pretty);
        set_next_as_snd_next(nb);
		return INVALIDATED_YES_SND;
	} else {
		slog_info(FILE_LEVEL, "Next '%s' invalidated. No snd_next to substitute"
						" it.", nb->next_pretty);
		unset_next(nb);
		return INVALIDATED_NO_SND;
	}
#else
	UNUSED(nb);
	UNUSED(last);
	UNUSED(curr);
	UNUSED(old_next);
	return VALIDATED;
#endif
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

	if (!isset_prev(sus->nb)) {
		return;
	}

	if (cmp_prev_against_self(sus->nb)) {
		return;
	}

	fsnp_init_promoted(&promoted);
	slog_info(FILE_LEVEL, "Sending a promoted msg to sp %s", sus->nb->prev_pretty);
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

	if (!isset_next(sus->nb)) {
		return;
	}

	if (cmp_next_against_self(sus->nb)) {
		return;
	}

	fsnp_init_next(&next, old);
	if (old) {
		addr.s_addr = htonl(old->ip);
		slog_info(FILE_LEVEL, "Sending a NEXT msg to sp %s with old_peer %s:%hu",
				sus->nb->next_pretty, inet_ntoa(addr), old->port);
	} else {
		slog_info(FILE_LEVEL, "Sending a NEXT msg to sp %s without old_peer",
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

	slog_info(FILE_LEVEL, "Sending an ACK msg to sp %s", s->pretty_addr);
	fsnp_init_ack(&ack);
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

	slog_info(FILE_LEVEL, "Sending a WHOSNEXT msg to sp %s", s->pretty_addr);
	err = fsnp_send_whosnext(sus->sock, 0, whosnext, &s->addr);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Send a WHOHAS msg.
 * If next is true this message will be sent to the next, otherwise will be sent
 * to the peer who has started the request.
 */
static void send_whohas(const struct sp_udp_state *sus,
		const struct fsnp_whohas *whohas, bool next)
{
	struct fsnp_peer self;
	struct in_addr a;
	char pretty_addr[32];
	fsnp_err_t err;
	const struct fsnp_peer *p = NULL;

	if (next) {
		if (!isset_next(sus->nb)) {
			return;
		}

		if (cmp_next_against_self(sus->nb)) {
			return;
		}

		p = &sus->nb->next;
		strncpy(pretty_addr, sus->nb->next_pretty, sizeof(char) * 32);
	} else {
		self.ip = get_peer_ip();
		self.port = get_udp_sp_port();
		if (whohas->sp.ip == self.ip && whohas->sp.port == self.port) {
			return;
		}

		p = &whohas->sp;
		a.s_addr = htonl(self.ip);
		snprintf(pretty_addr, sizeof(char) * 32, "%s:%hu", inet_ntoa(a),
		         self.port);
	}

	slog_info(FILE_LEVEL, "Sending a WHOHAS msg to sp %s", pretty_addr);
	err = fsnp_send_whohas(sus->sock, 0, whohas, p);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Make sure that the prev will send a NEXT msg. If the timer will fire, send a
 * NEXT msg to his prev, which is stored in the snd_next position
 */
static void ensure_prev_conn(struct sp_udp_state *sus)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_next *next = NULL;
	struct fsnp_peer p;
	struct sender s;
	fsnp_err_t err;
	unsigned counter = 0;

	if (!isset_prev(sus->nb)) {
		return;
	}

	if (cmp_prev_against_self(sus->nb)) {
		return;
	}

	while (true) {
		slog_info(FILE_LEVEL, "Waiting a NEXT msg from the prev");
		msg = fsnp_timed_recvfrom(sus->sock, 0, &p, &err);
		if (!msg && counter >= 4) {
			slog_warn(FILE_LEVEL, "Unable to receive a NEXT msg from the prev sp");
			unset_prev(sus->nb);
			fsnp_log_err_msg(err, false);
			if (isset_snd_next(sus->nb)) {
				counter = 0;
				set_prev(sus->nb, &sus->nb->snd_next);
				unset_snd_next(sus->nb);
				continue;
			} else {
				slog_warn(FILE_LEVEL, "Unable to ensure the prev's sp connection");
				slog_warn(STDOUT_LEVEL, "Please join the network again");
				unset_all(sus->nb);
				prepare_exit_sp_mode();
				exit_sp_mode();
				return;
			}
		} else if (!msg && counter < 4){
			fsnp_log_err_msg(err, false);
			counter++;
			slog_info(FILE_LEVEL, "Trying to contact for the %d time the sp",
			          counter);
			send_promoted(sus);
		}

		if (!cmp_prev(sus->nb, &p)) {
			struct in_addr a;
			a.s_addr = htonl(p.ip);
			slog_warn(FILE_LEVEL, "UDP msg received from another sp (%s:%hu) while waiting for a NEXT", inet_ntoa(a), p.port);
			free(msg);
			continue;
		} else {
			break;
		}
		// do this until the msg on the socket is from our promoter
	}

	if (!cmp_snd_next_against_self(sus->nb) && isset_snd_next(sus->nb)) {
		// clear neighbors from the HACK
		unset_snd_next(sus->nb);
	}

	if (msg->msg_type != NEXT) {
		slog_warn(FILE_LEVEL, "Wrong msg type received from sp %s: expected NEXT "
						"(%u), got %u", sus->nb->prev_pretty, NEXT, msg->msg_type);
		free(msg);
		slog_warn(STDOUT_LEVEL, "Please join the network again");
		unset_all(sus->nb);
		prepare_exit_sp_mode();
		exit_sp_mode();
		return;
	}

	slog_info(FILE_LEVEL, "NEXT msg received from prev %s", sus->nb->prev_pretty);
	s.addr = sus->nb->prev;
	memcpy(s.pretty_addr, sus->nb->prev_pretty, sizeof(char) * 32);
	send_ack(sus, &s);
	next = (struct fsnp_next *)msg;
	if (next->old_next.ip != 0 && next->old_next.port != 0) {
		set_next(sus->nb, &next->old_next);
		update_timespec(&sus->last);
	}

	free(next);
}

/*
 * Make sure that the next will send an ACK after a NEXT msg
 */
static void ensure_next_conn(struct sp_udp_state *sus,
							 const struct fsnp_peer *old_next)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_peer p;
	fsnp_err_t err;
	unsigned counter = 0;

	if (!isset_next(sus->nb)) {
		return;
	}

	if (cmp_next_against_self(sus->nb)) {
		return;
	}

	while (true) {
		slog_info(FILE_LEVEL, "Waiting an ACK for validating the next...");
		msg = fsnp_timed_recvfrom(sus->sock, 0, &p, &err);
		if (!msg && counter >= 4) {
			slog_warn(FILE_LEVEL, "Unable to ensure next's connection");
			fsnp_log_err_msg(err, false);
			slog_warn(STDOUT_LEVEL, "Please join the network again");
			prepare_exit_sp_mode();
			exit_sp_mode();
			sus->should_exit = true;
			return;
		} else if (!msg && counter < 4){
			fsnp_log_err_msg(err, false);
			counter++;
			slog_info(FILE_LEVEL, "Trying to contact for the %u time the next",
					counter);
			send_next(sus, old_next);
		}

		if (!cmp_next(sus->nb, &p)) {
			slog_warn(FILE_LEVEL, "UDP msg received from another sp while waiting for an ACK");
			free(msg);
			continue;
		} else {
			break;
		}
	}

	if (msg->msg_type != ACK) {
		slog_warn(FILE_LEVEL, "Wrong msg type received from sp %s: expected ACK "
						"(%u), got %u", sus->nb->next_pretty, ACK, msg->msg_type);
	} else {
		slog_info(FILE_LEVEL, "The next has sent an ACK msg. Next validated");
	}

	free(msg);
}

static void ensure_whohas(struct sp_udp_state *sus,
						  const struct fsnp_whohas *whohas, bool send_to_next)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_peer p;
	fsnp_err_t err;
	unsigned counter = 0;

	if (!isset_next(sus->nb)) {
		return;
	}

	if (cmp_next_against_self(sus->nb)) {
		return;
	}

	while (true) {
		slog_info(FILE_LEVEL, "Waiting for an ACK for validating WHOHAS msg...");
		msg = fsnp_timed_recvfrom(sus->sock, 0, &p, &err);
		if (!msg && counter >= 4) {
			slog_warn(FILE_LEVEL, "Unable to send whohas");
			fsnp_log_err_msg(err, false);
			return;
		} else if (!msg && counter < 4) {
			fsnp_log_err_msg(err, false);
			counter++;
			slog_info(FILE_LEVEL, "Trying to contact for the %u time whohas's"
						 " receiver",
			          counter);
			send_whohas(sus, whohas, send_to_next);
		}

		if (send_to_next && !cmp_next(sus->nb, &p)) {
			free(msg);
			continue;
		} else {
			break;
		}
	}

	if (msg->msg_type != ACK) {
		slog_warn(FILE_LEVEL, "Wrong msg type received from whohas's receiver:"
						" expected ACK(%u), got %u", NEXT, msg->msg_type);
	} else {
		slog_info(FILE_LEVEL, "ACK msg received from whohas's receiver.");
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

	pollfd[PIPE].fd = sus->r_pipe[READ_END];
	pollfd[PIPE].events = POLLIN | POLLPRI;
	pollfd[SOCK].fd = sus->sock;
	pollfd[SOCK].events = POLLIN | POLLPRI;
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
	slog_info(FILE_LEVEL, "NEXT msg received from sp %s", sender->pretty_addr);
	if (next->old_next.ip != 0 && next->old_next.port) {
		set_next(sus->nb, &next->old_next);
		update_timespec(&sus->last);
		send_next(sus, NULL);
		ensure_next_conn(sus, NULL);
	}

	set_prev(sus->nb, &sender->addr);
	send_ack(sus, sender);
}

/*
 * Handler called when a PROMOTED msg is received
 */
static void promoted_msg_rcvd(struct sp_udp_state *sus,
		const struct fsnp_promoted *promoted, const struct sender *sender)
{
	struct fsnp_peer old_next;
	UNUSED(promoted);

	slog_info(FILE_LEVEL, "PROMOTED msg received from sp %s", sender->pretty_addr);
	memcpy(&old_next, &sus->nb->next, sizeof(struct fsnp_peer));
	set_next(sus->nb, &sender->addr);
	update_timespec(&sus->last);
	send_next(sus, &old_next);
	ensure_next_conn(sus, &old_next);
}

/*
 * Handler called when a WHOSNEXT msg is received
 */
static void whosnext_msg_rcvd(struct sp_udp_state *sus,
		struct fsnp_whosnext *whosnext, const struct sender *sender)
{
	slog_info(FILE_LEVEL, "WHOSNEXT msg received from sp %s", sender->pretty_addr);
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
		struct fsnp_whohas *whohas, const struct sender *sender)
{
	char key_str[SHA256_BYTES];
	unsigned i = 0;
	struct request *req = NULL;
	struct fsnp_peer peers[MAX_KNOWN_PEER];
	struct fsnp_peer *p = NULL;
	uint8_t n = 0;
	uint8_t j = 0;
	bool send_to_next = true;

	STRINGIFY_HASH(key_str, whohas->req_id, i);
	slog_info(FILE_LEVEL, "WHOHAS msg received from sp %s. req_id = %s",
	          sender->pretty_addr, key_str);
	req = ht_get(sus->reqs, whohas->req_id, sizeof(sha256_t), NULL);
	if (req) {
		if (req->sent_by_me) {
			communicate_whohas_result_to_peer(whohas, &req->requester);
			ht_delete(sus->reqs, whohas->req_id, sizeof(sha256_t), NULL, NULL);
		} else {
			slog_info(FILE_LEVEL, "Request %s is already in cache", key_str);
		}
		
		send_ack(sus, sender);
		return;
	}

	slog_info(FILE_LEVEL, "Adding request %s to the cache", key_str);
	req = malloc(sizeof(struct request));
	if (!req) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
	} else {
		update_timespec(&req->creation_time);
		req->sent_by_me = false;
		ht_set(sus->reqs, whohas->req_id, sizeof(sha256_t), req,
				sizeof(struct request));
	}

	get_peers_for_key(whohas->file_hash, peers, &n);
	if (n == 0) { // just send the message to the next
		send_whohas(sus, whohas, send_to_next);
		ensure_whohas(sus, whohas, send_to_next);
		return;
	}

	p = whohas->owners + whohas->num_peers;
	if (whohas->num_peers + n > FSNP_MAX_OWNERS) {
		n = ((uint8_t)FSNP_MAX_OWNERS) - whohas->num_peers;
		whohas->num_peers = (uint8_t)FSNP_MAX_OWNERS;
		send_to_next = false;
	} else {
		whohas->num_peers += n;
	}

	for (j = 0; j < n; j++) {
		memcpy(&p[j], &peers[j], sizeof(struct fsnp_peer));
	}

	send_whohas(sus, whohas, send_to_next);
	ensure_whohas(sus, whohas, send_to_next);
}

/*
 * Handler called when a LEAVE msg is received
 */
static void leave_msg_rcvd(struct sp_udp_state *sus,
		const struct fsnp_leave *leave, const struct sender *sender)
{
    UNUSED(leave);
    struct fsnp_whosnext whosnext;
    struct sender s;

	if (cmp_next(sus->nb, &sender->addr)) {
		slog_info(FILE_LEVEL, "next %s is leaving", sus->nb->next_pretty);
        set_next_as_snd_next(sus->nb);
        update_timespec(&sus->last);
        send_next(sus, NULL);
        ensure_next_conn(sus, NULL);
        fsnp_init_whosnext(&whosnext, NULL);
        s.addr = sus->nb->next;
        memcpy(s.pretty_addr, sus->nb->next_pretty, sizeof(char) * 32);
        send_whosnext(sus, &whosnext, &s);
	} else if (cmp_prev(sus->nb, &sender->addr)) {
		slog_info(FILE_LEVEL, "prev %s is leaving", sus->nb->prev_pretty);
	    unset_prev(sus->nb);
	} else {
		slog_info(FILE_LEVEL, "Sp %s is leaving. No special actions are required",
				sender->pretty_addr);
	}

	send_ack(sus, sender);
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
			whohas_msg_rcvd(sus, (struct fsnp_whohas *)msg, &sender);
			break;

		case ACK:
			slog_info(FILE_LEVEL, "ACK msg received from sp %s", sender.pretty_addr);
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
		slog_error(FILE_LEVEL, "sp UDP sock revents: %d", revents);
		prepare_exit_sp_mode();
		exit_sp_mode();
		sus->should_exit = true;
	}
}

struct pipe_whohas_msg {
	sha256_t file_hash;
	struct fsnp_peer requester;
};

/*
 * Generate a req_id from the requester's address and the file_hash.
 * Store the result in req_id
 */
static void generate_req_id(const struct fsnp_peer *requester,
                            const sha256_t file_hash, sha256_t req_id)
{
	char key_str[SHA256_BYTES];
	unsigned i = 0;
	char req_id_str[SHA256_BYTES + sizeof(struct fsnp_peer) + 16 + 1];
	size_t req_id_size = SHA256_BYTES + sizeof(struct fsnp_peer) + 16 + 1;
	struct in_addr a;

	STRINGIFY_HASH(key_str, file_hash, i);
	a.s_addr = htonl(requester->ip);
	sprintf("%s:%hu:%s", inet_ntoa(a), requester->port, key_str);
	sha256(req_id_str, req_id_size, req_id);
	STRINGIFY_HASH(key_str, req_id, i);
	slog_info(FILE_LEVEL, "req_id %s generated from %s", key_str, req_id_str);
}
/*
 * Read from the pipe what's searching a peer and progagate it through the sp
 * network
 */
static void pipe_whohas_rcvd(struct sp_udp_state *sus)
{
	ssize_t r = 0;
	struct pipe_whohas_msg whohas_msg;
	struct fsnp_whohas whohas;
	sha256_t req_id;
	struct request *req = NULL;
	struct fsnp_peer peers[MAX_KNOWN_PEER];
	uint8_t n = 0;
	int ret = 0;

	r = fsnp_read(sus->r_pipe[READ_END], &whohas_msg, sizeof(struct pipe_whohas_msg));
	if (r < 0) {
		slog_error(FILE_LEVEL, "Unable to read pipe_whohas_msg from the pipe");
		return;
	}

	req = malloc(sizeof(struct request));
	if (!req) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		return;
	}

	generate_req_id(&whohas_msg.requester, whohas_msg.file_hash, req_id);
	memcpy(&req->requester, &whohas_msg.requester, sizeof(struct fsnp_peer));
	update_timespec(&req->creation_time);
	req->sent_by_me = true;
	ret = ht_set_if_not_exists(sus->reqs, req_id, sizeof(sha256_t), req,
			sizeof(struct request));
	if (ret == 1) {
		slog_warn(FILE_LEVEL, "This request is already set");
		free(req);
		return;
	} else if (ret == -1) {
		free(req);
		slog_error(FILE_LEVEL, "Unable to set the request");
		return;
	}

	get_peers_for_key(whohas_msg.file_hash, peers, &n);
	if (n == 0) {
		fsnp_init_whohas(&whohas, &whohas_msg.requester, req_id,
		                 whohas_msg.file_hash, 0, NULL);
	} else {
		fsnp_init_whohas(&whohas, &whohas_msg.requester, req_id,
		                 whohas_msg.file_hash, n, peers);
	}

	if (n >= FSNP_MAX_OWNERS) {
		communicate_whohas_result_to_peer(&whohas, &whohas_msg.requester);
		ht_delete(sus->reqs, req_id, sizeof(sha256_t), NULL, NULL);
	} else {
		send_whohas(sus, &whohas, true);
		ensure_whohas(sus, &whohas, true);
	}
}

static void write_prev_to_pipe(struct sp_udp_state *sus)
{
	struct fsnp_peer prev;
	ssize_t w = 0;
	fsnp_err_t err;

	if (cmp_prev_against_self(sus->nb)) {
		memset(&prev, 0, sizeof(struct fsnp_peer));
	} else {
		memcpy(&prev, &sus->nb->prev, sizeof(struct fsnp_peer));
	}

	slog_debug(FILE_LEVEL, "Writing into the pipe prev's address")
	w = fsnp_timed_write(sus->w_pipe[WRITE_END], &prev, sizeof(struct fsnp_peer),
			FSNP_TIMEOUT, &err);
	if (w < 0) {
		slog_error(FILE_LEVEL, "Unable to write prev's address in the pipe");
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Read a message received on the pipe
 */
static void read_pipe_msg(struct sp_udp_state *sus)
{
	ssize_t r = 0;
	int msg = 0;

	r = fsnp_read(sus->r_pipe[READ_END], &msg, sizeof(int));
	if (r < 0) {
		slog_fatal(FILE_LEVEL, "Unable to read a message from the sp UDP pipe");
		sus->should_exit = true;
		prepare_exit_sp_mode();
		exit_sp_mode();
	}

	switch (msg) {
		case PIPE_WHOHAS:
			slog_info(FILE_LEVEL, "PIPE_WHOHAS read from sp UDP pipe");
			pipe_whohas_rcvd(sus);
			break;

		case PIPE_GET_PREV:
			slog_info(FILE_LEVEL, "PIPE_GET_PREV read from sp UDP pipe");
			write_prev_to_pipe(sus);
			break;

		case PIPE_QUIT:
			slog_info(FILE_LEVEL, "PIPE_QUIT read from sp UDP pipe");
			sus->should_exit = true;
			break;

		default:
			slog_error(FILE_LEVEL, "Unexpected sp UDP pipe message: %d", msg);
			break;
	}
}

/*
 * Handle an event occurred on the pipe
 */
static void pipe_event(struct sp_udp_state *sus, short revents)
{
	if (revents & POLLIN || revents & POLLPRI || revents & POLLRDBAND) {
		read_pipe_msg(sus);
	} else {
		slog_error(FILE_LEVEL, "sp UDP pipe revents: %d", revents);
		prepare_exit_sp_mode();
		exit_sp_mode();
		sus->should_exit = true;
	}
}

/*
 * Called to check the next's aliveness. If the next is considered dead it will
 * contact the snd_next to set it as next
 */
static void check_if_next_alive(struct sp_udp_state *sus)
{
	struct timespec curr;
	int ret = 0;
	struct fsnp_peer old_next;

	if (cmp_next_against_self(sus->nb)) {
		slog_debug(FILE_LEVEL, "next field is set to self. check_if_next_alive "
						 "will not remove it.");
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &curr);
	ret = invalidate_next_if_needed(sus->nb, &sus->last, &curr, &old_next);
	switch (ret) {
		case VALIDATED:
			break;

		case INVALIDATED_NO_SND:
			rm_dead_sp_from_server(&old_next);
			break;

		case INVALIDATED_YES_SND:
			rm_dead_sp_from_server(&old_next);
			send_next(sus, NULL);
			ensure_next_conn(sus, NULL);
			break;

		default:
			slog_panic(FILE_LEVEL, "Unknown return from invalidate_next_if_needed");
			break;
	}
}

struct invalidate_req_data {
	struct sp_udp_state *sus;
	struct timespec curr;
};

#define INVALIDATE_REQ_THRESHOLD 300.0f // 5 minutes

/*
 * Iterate over all the keys, removing that ones that are expired
 */
static int invalidate_requests_iterator(void *item, size_t idx, void *user)
{
	hashtable_key_t *key = (hashtable_key_t *)item;
	struct invalidate_req_data *data = (struct invalidate_req_data *)user;
	struct request *req = NULL;
	double delta = 0;
	char key_str[SHA256_BYTES];
	unsigned i = 0;
	uint8_t *p = NULL;

	UNUSED(idx);

	req = ht_get(data->sus->reqs, key->data, key->len, NULL);
	if (!req) {
		slog_warn(FILE_LEVEL, "Request iterator key not present in the hashtable");
		return GO_AHEAD;
	}

	delta = calculate_timespec_delta(&req->creation_time, &data->curr);
	if (delta > INVALIDATE_REQ_THRESHOLD) {
		p = key->data;
		STRINGIFY_HASH(key_str, p, i);
		slog_info(FILE_LEVEL, "Invalidating request %s", key_str);
		ht_delete(data->sus->reqs, key->data, key->len, NULL, NULL);
	}

	return GO_AHEAD;
}

#undef INVALIDATE_REQ_THRESHOLD

/*
 * Invalidate any request that has expired
 */
static void invalidate_requests(struct sp_udp_state *sus)
{
	linked_list_t *l = NULL;
	struct invalidate_req_data data;

	if (ht_count(sus->reqs) == 0) {
		return;
	}

	l = ht_get_all_keys(sus->reqs);
	if (!l) {
		slog_error(FILE_LEVEL, "Unable to get all the reqs keys");
		return;
	}

	update_timespec(&data.curr);
	data.sus = sus;
	list_foreach_value(l, invalidate_requests_iterator, &data);
	list_destroy(l);
}

#define POLL_TIMEOUT 30000 // ms

struct sp_thread_pipe {
	int r_pipe[2];
	int w_pipe[2];
	pthread_mutex_t mtx;
};

static struct sp_thread_pipe stp;

/*
 * Entry point for the superpeer's udp subsystem.
 */
static void sp_udp_thread(void *data)
{
	struct sp_udp_state *sus = (struct sp_udp_state *)data;
	struct pollfd pollfd[POLLFD_NUM];
	int ret = 0;

	sleep(10); // so we're sure to have left the sp
	slog_debug(FILE_LEVEL, "sp-udp-thread is awake");
	send_promoted(sus);
	slog_info(FILE_LEVEL, "Ensuring prev connection...");
	ensure_prev_conn(sus);
	if (sus->should_exit) {
		goto no_leave;
	}

	send_next(sus, NULL);
	slog_info(FILE_LEVEL, "Ensuring next connection...");
	ensure_next_conn(sus, NULL);
	if (sus->should_exit) {
		goto prev_leave;
	}

	clock_gettime(CLOCK_MONOTONIC, &sus->last);

	setup_poll(pollfd, sus);
	slog_info(FILE_LEVEL, "Superpeers' overlay network successfully joined");
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

			check_if_next_alive(sus);
		} else if (ret == 0) {
			check_if_next_alive(sus);
		} else {
			slog_error(FILE_LEVEL, "poll error %d");
			prepare_exit_sp_mode();
			exit_sp_mode();
			sus->should_exit = true;
		}
	}

	//TODO: send leave to next
prev_leave:
	// TODO: send leave to prev
no_leave:
	slog_info(FILE_LEVEL, "sp-udp-thread is leaving...");
	slog_info(FILE_LEVEL, "Destroyng the request cache");
	ht_destroy(sus->reqs);
	slog_info(FILE_LEVEL, "Unsetting al the neighbors");
	unset_all(sus->nb);
	free(sus->nb);
	slog_info(FILE_LEVEL, "Closing the UDP socket");
	close(sus->sock);
	slog_info(FILE_LEVEL, "Closing the pipe");
	pthread_mutex_lock(&stp.mtx);
	close(sus->r_pipe[READ_END]);
	close(sus->r_pipe[WRITE_END]);
	close(sus->w_pipe[READ_END]);
	close(sus->w_pipe[WRITE_END]);
	memset(stp.r_pipe, 0, sizeof(int) * 2);
	pthread_mutex_unlock(&stp.mtx);
	slog_info(FILE_LEVEL, "Destroying the stp mutex");
	pthread_mutex_destroy(&stp.mtx);
	// Don't free sus, it will be freed by the thread_manager
}

#undef POLLFD_NUM
#undef PIPE
#undef SOCK
#undef POLL_TIMEOUT
#undef INVALIDATED_NO_SND
#undef INVALIDATED_YES_SND
#undef VALIDATED

#define REQS_SIZE_MAX 1UL << 16UL

int enter_sp_network(int udp, const struct fsnp_peer *sps, unsigned n)
{
	int ret = 0;
	struct sp_udp_state *sus = NULL;
	struct fsnp_peer self;

	slog_info(FILE_LEVEL, "Creating struct sp_udp_state");
	sus = calloc(1, sizeof(struct sp_udp_state));
	if (!sus) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		return -1;
	}

	slog_info(FILE_LEVEL, "Creating struct neighbors");
	sus->nb = calloc(1, sizeof(struct neighbors));
	if (!sus->nb) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		free(sus);
		return -1;
	}

	slog_info(FILE_LEVEL, "Initializing reqs hashtable");
	sus->reqs = ht_create(HT_SIZE_MIN, REQS_SIZE_MAX, reqs_free_callback);
	if (!sus->reqs) {
		slog_error(FILE_LEVEL, "Unable to create reqs hashtable");
		free(sus->nb);
		free(sus);
		return -1;
	}

	slog_info(FILE_LEVEL, "Creating superpeer's pipe");
	ret = pipe(sus->r_pipe);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Pipe error %d", errno);
		ht_destroy(sus->reqs);
		free(sus->nb);
		free(sus);
		return -1;
	}

	ret = pipe(sus->w_pipe);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Pipe error %d", errno);
		ht_destroy(sus->reqs);
		free(sus->nb);
		free(sus);
		close(sus->r_pipe[READ_END]);
		close(sus->r_pipe[WRITE_END]);
		return -1;
	}

	slog_info(FILE_LEVEL, "Initializing struct sp_thread_pipe's mutex");
	ret = pthread_mutex_init(&stp.mtx, NULL);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "pthread_mutex_init error %d", ret);
		ht_destroy(sus->reqs);
		close(sus->r_pipe[READ_END]);
		close(sus->r_pipe[WRITE_END]);
		close(sus->w_pipe[READ_END]);
		close(sus->w_pipe[WRITE_END]);
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
			slog_info(FILE_LEVEL, "Case NO_SP");
			set_prev(sus->nb, &self);
			set_next(sus->nb, &self);
			set_snd_next(sus->nb, &self);
			break;

		case ONE_SP:
			slog_info(FILE_LEVEL, "Case ONE_SP");
			set_prev(sus->nb, sps);
			set_next(sus->nb, &self);
			set_snd_next(sus->nb, &self);
			break;

		case TWO_SPS:
			slog_info(FILE_LEVEL, "Case TWO_SPS");
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
			close(sus->r_pipe[READ_END]);
			close(sus->r_pipe[WRITE_END]);
			close(sus->w_pipe[READ_END]);
			close(sus->w_pipe[WRITE_END]);
			pthread_mutex_destroy(&stp.mtx);
			free(sus->nb);
			free(sus);
			return -1;
	}

	memcpy(stp.r_pipe, sus->r_pipe, sizeof(int) * 2);
	memcpy(stp.w_pipe, sus->w_pipe, sizeof(int) * 2);
	ret = start_new_thread(sp_udp_thread, sus, "sp-udp-thread");
	if (ret < 0) {
		sus->sock = 0;
		ht_destroy(sus->reqs);
		close(sus->r_pipe[READ_END]);
		close(sus->r_pipe[WRITE_END]);
		close(sus->w_pipe[READ_END]);
		close(sus->w_pipe[WRITE_END]);
		pthread_mutex_destroy(&stp.mtx);
		free(sus->nb);
		free(sus);
		memset(stp.r_pipe, 0, sizeof(int) * 2);
		memset(stp.w_pipe, 0, sizeof(int) * 2);
		return -1;
	}

	return 0;
}

/*
 * Return the write side (from the perspective of the sp-udp-thread) of the pipe
 */
static int get_pipe_write_end(void)
{
	int we = 0;

	pthread_mutex_lock(&stp.mtx);
	we = stp.r_pipe[WRITE_END];
	pthread_mutex_unlock(&stp.mtx);
	return we;
}

/*
 * Return the read side (from the perspective of the sp-udp-thread) of the pipe
 */
static int get_pipe_read_end(void)
{
	int re = 0;

	pthread_mutex_lock(&stp.mtx);
	re = stp.w_pipe[READ_END];
	pthread_mutex_unlock(&stp.mtx);
	return re;
}

int ask_whohas(const sha256_t file_hash, const struct fsnp_peer *requester)
{
	ssize_t w = 0;
	int we = 0;
	int msg = PIPE_WHOHAS;
	struct pipe_whohas_msg whohas_msg;
	fsnp_err_t err;


	we = get_pipe_write_end();
	if (we == 0) {
		slog_warn(FILE_LEVEL, "ask whohas attempted when the pipe doesn't exists");
		return -1;
	}

	slog_debug(FILE_LEVEL, "Writing PIPE_WHOHAS msg to the sp-udp thread");
	w = fsnp_timed_write(we, &msg, sizeof(int), FSNP_TIMEOUT, &err);
	if (w < 0) {
		slog_error(FILE_LEVEL, "Unable to write the message in the pipe");
		fsnp_log_err_msg(err, false);
		return -1;
	}

	memcpy(&whohas_msg.file_hash, file_hash, sizeof(sha256_t));
	memcpy(&whohas_msg.requester, requester, sizeof(struct fsnp_peer));
	slog_debug(FILE_LEVEL, "Writing the pipe_whohas_msg in the pipe");
	w = fsnp_timed_write(we, &whohas_msg, sizeof(struct pipe_whohas_msg),
			FSNP_TIMEOUT, &err);
	if (w < 0) {
		slog_error(FILE_LEVEL, "Unable to write pipe_whohas_msg in the pipe");
		fsnp_log_err_msg(err, false);
		return -1;
	}

	return 0;
}

#undef REQS_SIZE_MAX

bool get_prev_addr(struct fsnp_peer *prev)
{
	int re = 0;
	int we = 0;
	int msg = PIPE_GET_PREV;
	fsnp_err_t err;
	ssize_t rw = 0;

	we = get_pipe_write_end();
	if (we == 0) {
		return false;
	}

	slog_debug(FILE_LEVEL, "Writing PIPE_GET_PREV to the sp-udp-thread");
	rw = fsnp_timed_write(we, &msg, sizeof(int), FSNP_TIMEOUT, &err);
	if (rw < 0) {
		slog_error(FILE_LEVEL, "Unable to write PIPE_GET_PREV in the pipe");
		fsnp_log_err_msg(err, false);
		return false;
	}

	re = get_pipe_read_end();
	if (re == 0) {
		return false;
	}

	slog_debug(FILE_LEVEL, "Reading prev address from the sp UDP pipe");
	rw = fsnp_timed_read(re, prev, sizeof(struct fsnp_peer), FSNP_TIMEOUT, &err);
	if (rw < 0) {
		slog_error(FILE_LEVEL, "Unable to read prev address from the pipe");
		fsnp_log_err_msg(err, false);
		return false;
	}

	if (prev->ip == 0 && prev->port == 0) {
		slog_debug(FILE_LEVEL, "get_prev: prev is set to self")
		return false;
	} else {
		slog_debug(FILE_LEVEL, "get_prev: prev is NOT set to self")
		return true;
	}
}

void exit_sp_network(void)
{
	int we =0;
	int msg = PIPE_QUIT;
	ssize_t w = 0;
	fsnp_err_t err;

	we = get_pipe_write_end();
	if (we == 0) {
		return;
	}

	w = fsnp_timed_write(we, &msg, sizeof(int), FSNP_TIMEOUT, &err);
	if (w < 0) {
		slog_error(FILE_LEVEL, "Unable to write PIPE_QUIT in the sp UDP pipe");
		fsnp_log_err_msg(err, false);
	}
}

#undef READ_END
#undef WRITE_END
