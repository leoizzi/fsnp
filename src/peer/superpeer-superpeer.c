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
#include "peer/pipe_macro.h"
#include "peer/request.h"
#include "peer/timespec.h"
#include "peer/neighbors.h"
#include "peer/pending_msg.h"

#include "fsnp/fsnp.h"

#include "struct/hashtable.h"

#include "slog/slog.h"

#define INVALIDATE_NEXT_THRESHOLD 60.f // 1 minute
#define V_TIMEOUT INVALIDATE_NEXT_THRESHOLD / 4.

#define VALIDATED_NO_TIMEOUT 0
#define VALIDATED_TIMEOUT 1
#define INVALIDATED_NO_SND 2
#define INVALIDATED_YES_SND 3

/*
 * Invalidate the next field if needed. In case it's needed the swap with the
 * snd_next (if present) will be done.
 * On output in last will be found the values present in curr.
 *
 * - Return VALIDATED_TIMEOUT if the superpeer has listened the next in two minutes
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
	if (delta < INVALIDATE_NEXT_THRESHOLD) {
		if (delta > V_TIMEOUT) {
			return VALIDATED_TIMEOUT;
		} else {
			return VALIDATED_NO_TIMEOUT;
		}
	}

    memcpy(old_next, &nb->next, sizeof(struct fsnp_peer));
	if (isset_snd_next(nb) && !cmp_snd_next_against_self(nb)) {
		slog_info(FILE_LEVEL, "Next '%s' invalidated.", nb->next_pretty);
        set_next_as_snd_next(nb);
        update_timespec(last);
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
	return VALIDATED_NO_TIMEOUT;
#endif
}

#undef V_TIMEOUT

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

void send_next(const struct sp_udp_state *sus, const struct fsnp_peer *old)
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

void send_whosnext(const struct sp_udp_state *sus,
				   const struct fsnp_whosnext *whosnext, const struct sender *s)
{
	fsnp_err_t err;

	if (cmp_sender_against_self(s)) {
		return;
	}

#ifdef FSNP_DEBUG
	struct in_addr a;
	if (whosnext->next.ip == 0 && whosnext->next.port == 0) {
		slog_debug(FILE_LEVEL, "Sending an empty WHOSNEXT msg to sp %s",
				s->pretty_addr);
	} else {
		a.s_addr = htonl(whosnext->next.ip);
		slog_debug(FILE_LEVEL, "Sending a WHOSNEXT msg filled with next "
						 "'%s:%hu' to sp %s", inet_ntoa(a), whosnext->next.port,
						 s->pretty_addr);
	}
#else // !FSNP_DEBUG
	slog_info(FILE_LEVEL, "Sending a WHOSNEXT msg to sp %s", s->pretty_addr);
#endif

	err = fsnp_send_whosnext(sus->sock, 0, whosnext, &s->addr);
	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

void send_whohas(const struct sp_udp_state *sus,const struct fsnp_whohas *whohas,
		bool next)
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
 * Send a leave msg. If next is true the message will be sent to him, otherwise
 * will be sent to the prev
 */
static void send_leave(const struct sp_udp_state *sus, bool next)
{
	struct fsnp_leave leave;
	fsnp_err_t err;

	fsnp_init_leave(&leave);
	if (next) {
		slog_info(FILE_LEVEL, "Sending leave msg to the next %s",
				sus->nb->next_pretty);
		err = fsnp_send_udp_leave(sus->sock, 0, &leave, &sus->nb->next);
	} else {
		slog_info(FILE_LEVEL, "Sending leave msg to the prev %s",
				sus->nb->prev_pretty);
		err = fsnp_send_udp_leave(sus->sock, 0, &leave, &sus->nb->prev);
	}

	if (err != E_NOERR) {
		fsnp_log_err_msg(err, false);
	}
}

/*
 * Make sure that the prev will send a NEXT msg. If the timer will fire, send a
 * NEXT msg to his prev, which is stored in the snd_next position.
 *
 * This function will be used only when the sp subsystem is booting
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
				PRINT_PEER;
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
		PRINT_PEER;
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
 * Make sure that the next will send an ACK after a NEXT msg.
 *
 * This function will be used only when the sp subsystem is booting
 */
static void ensure_next_conn(struct sp_udp_state *sus,
							 const struct fsnp_peer *old_next)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_peer p;
	fsnp_err_t err;
	unsigned counter = 0;
	bool prev_asked_next = false;
	struct fsnp_whosnext whosnext;
	struct sender s;
	struct in_addr a;

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
			PRINT_PEER;
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
			sus->next_validated = false;
		}

		if (!cmp_next(sus->nb, &p)) {
			a.s_addr = htonl(p.ip);
			slog_warn(FILE_LEVEL, "UDP msg of type %u received from another sp "
						 "(%s:%hu) while waiting for an ACK", msg->msg_type,
						 inet_ntoa(a), p.port);
			if (cmp_prev(sus->nb, &p) && msg->msg_type == WHOSNEXT) {
				slog_debug(FILE_LEVEL, "WHOSNEXT rcvd from prev deferred");
				prev_asked_next = true;
			}

			free(msg);
			continue;
		} else {
			break;
		}
	}

	if (msg->msg_type != ACK) {
		slog_warn(FILE_LEVEL, "Wrong msg type received from sp %s: expected "
						"ACK (%u), got %u", sus->nb->next_pretty, ACK,
						msg->msg_type);
	} else {
		slog_info(FILE_LEVEL, "The next has sent an ACK msg. Next validated");
	}

	sus->next_validated = true;
	if (prev_asked_next) {
		s.addr = sus->nb->prev;
		strncpy(s.pretty_addr, sus->nb->prev_pretty, sizeof(char) * 32);
		fsnp_init_whosnext(&whosnext, &sus->nb->next);
		slog_debug(FILE_LEVEL, "Sending deferred WHOSNEXT");
		send_whosnext(sus, &whosnext, &s);
	}

	free(msg);
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
	if (cmp_prev(sus->nb, &sender->addr)) {
		// a NEXT from this sp has already been received. Do nothing
		slog_debug(FILE_LEVEL, "NEXT from sp %s already received",
				sender->pretty_addr);
		return;
	}

	if (next->old_next.ip != 0 && next->old_next.port) {
		set_next(sus->nb, &next->old_next);
		update_timespec(&sus->last);
		sus->next_validated = false;
		send_next(sus, NULL);
		add_pending_next(sus, &sus->nb->next, NULL);
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
	if (cmp_next(sus->nb, &sender->addr)) {
		// a PROMOTED from this sp has already been received. Do nothing
		slog_debug(FILE_LEVEL, "PROMOTED from sp %s already received",
				sender->pretty_addr);
		return;
	}

	memcpy(&old_next, &sus->nb->next, sizeof(struct fsnp_peer));
	set_snd_next(sus->nb, &sus->nb->next);
	set_next(sus->nb, &sender->addr);
	update_timespec(&sus->last);
	sus->next_validated = false;
	send_next(sus, &old_next);
	add_pending_next(sus, &sus->nb->next, &old_next);
}

/*
 * Handler called when a WHOSNEXT msg is received
 */
static void whosnext_msg_rcvd(struct sp_udp_state *sus,
		struct fsnp_whosnext *whosnext, const struct sender *sender)
{
	slog_info(FILE_LEVEL, "WHOSNEXT msg received from sp %s", sender->pretty_addr);
	if (whosnext->next.ip == 0 && whosnext->next.port == 0) {
		if (!cmp_prev(sus->nb, &sender->addr)) {
			// the request was not sent from the prev. Do not consider it
			slog_debug(FILE_LEVEL, "Empty WHOSNEXT not received from the prev "
						  "but from %s. Ignoring it", sender->pretty_addr);
			return;
		}

		memcpy(&whosnext->next, &sus->nb->next, sizeof(struct fsnp_peer));
		slog_debug(FILE_LEVEL, "Empty WHOSNEXT msg received from sp %s. Sending"
						 " it back with next address '%s'",sender->pretty_addr,
						 sus->nb->next_pretty);
		send_whosnext(sus, whosnext, sender);
	} else {
		if (!cmp_next(sus->nb, &sender->addr)) {
			// the response was not sent from the next. Do not consider it
			slog_debug(FILE_LEVEL, "Filled WHOSNEXT not sent from the next but"
						  " from %s. Ignoring it", sender->pretty_addr);
			return;
		}

		if (cmp_snd_next(sus->nb, &whosnext->next)) {
			slog_debug(FILE_LEVEL, "WHOSNEXT msg contains the same address"
						  " stored as sp snd_next '%s'", sus->nb->snd_next_pretty);
			return;
		}

		if (isset_snd_next(sus->nb)) {
			unset_snd_next(sus->nb);
		}

		slog_debug(FILE_LEVEL, "WHOSNEXT msg contains the address of the new"
						 " snd_next.");
		set_snd_next(sus->nb, &whosnext->next);
	}
}

/*
 * Handler called when a WHOHAS msg is received
 */
static void whohas_msg_rcvd(struct sp_udp_state *sus,
		struct fsnp_whohas *whohas, const struct sender *sender)
{
	char key_str[SHA256_STR_BYTES];
	struct request *req = NULL;
	struct fsnp_peer peers[MAX_KNOWN_PEER];
	struct fsnp_peer *p = NULL;
	uint8_t n = 0;
	uint8_t j = 0;
	bool send_to_next = true;

	stringify_hash(key_str, whohas->req_id);
	slog_info(FILE_LEVEL, "WHOHAS msg received from sp %s. req_id = %s",
	          sender->pretty_addr, key_str);
	req = get_request(whohas->req_id, sus->reqs);
	if (req) {
		if (req->sent_by_me) {
			communicate_whohas_result_to_peer(whohas, &req->requester);
			update_request(sus->reqs, whohas->req_id, whohas);
		} else {
			slog_info(FILE_LEVEL, "Request %s is already in cache", key_str);
		}

		send_ack(sus, sender);
		return;
	}

	slog_info(FILE_LEVEL, "Adding request %s to the cache", key_str);
	req = create_request(whohas->file_hash, false, NULL);
	if (!req) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
	} else {
		add_request_to_table(whohas->req_id, req, sus->reqs);
	}

	get_peers_for_key(whohas->file_hash, peers, &n);
	if (n == 0) { // just send the message to the next
		send_ack(sus, sender);
		send_whohas(sus, whohas, send_to_next);
		update_request(sus->reqs, whohas->req_id, whohas);
		add_pending_whohas(sus, &sus->nb->next, whohas, send_to_next);
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

	send_ack(sus, sender);
	send_whohas(sus, whohas, send_to_next);
	update_request(sus->reqs, whohas->req_id, whohas);
	if (send_to_next) {
		add_pending_whohas(sus, &sus->nb->next, whohas, send_to_next);
	} else {
		add_pending_whohas(sus, &whohas->sp, whohas, send_to_next);
	}
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

    if (cmp_snd_next(sus->nb, &sender->addr)) {
    	unset_snd_next(sus->nb);
    }

	if (cmp_next(sus->nb, &sender->addr)) {
		slog_info(FILE_LEVEL, "next %s is leaving", sus->nb->next_pretty);
        set_next_as_snd_next(sus->nb);
        sus->next_validated = false;
        update_timespec(&sus->last);
        send_next(sus, NULL);
        add_pending_next(sus, &sus->nb->next, NULL);
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
static void read_sock_msg(struct sp_udp_state *sus) {
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

	is_pending(sus, msg, &sender);
	switch (msg->msg_type) {
		case NEXT:
			next_msg_rcvd(sus, (const struct fsnp_next *) msg, &sender);
			break;

		case PROMOTED:
			promoted_msg_rcvd(sus, (const struct fsnp_promoted *) msg,
			                  &sender);
			break;

		case WHOSNEXT:
			whosnext_msg_rcvd(sus, (struct fsnp_whosnext *) msg, &sender);
			break;

		case WHOHAS:
			whohas_msg_rcvd(sus, (struct fsnp_whohas *) msg, &sender);
			break;

		case ACK:
			slog_info(FILE_LEVEL, "ACK msg received from sp %s",
			          sender.pretty_addr);
			break;

		case LEAVE:
			leave_msg_rcvd(sus, (const struct fsnp_leave *) msg, &sender);
			break;

		default:
			slog_warn(FILE_LEVEL,
			          "Unexpected msg_type received on sp_udp_sock "
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

	char addr_str[32];
	char key_str[SHA256_STR_BYTES];
	char req_id_str[32 + SHA256_STR_BYTES];
	struct in_addr a;

	memset(&addr_str, 0, sizeof(char) * 32);
	memset(&key_str, 0, sizeof(char) * SHA256_BYTES);
	memset(&req_id_str, 0, sizeof(char) * (32 + SHA256_BYTES));
	a.s_addr = htonl(requester->ip);
	stringify_hash(key_str, file_hash);
	snprintf(addr_str, sizeof(char) * 32, "%s:%hu", inet_ntoa(a), requester->port);
	snprintf(req_id_str, sizeof(char) * (32 + SHA256_BYTES), "%s:%s", addr_str,
			key_str);
	sha256(req_id_str, sizeof(char) * (32 + SHA256_BYTES), req_id);
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
	add_req_status_t ret = 0;

	r = fsnp_read(sus->r_pipe[READ_END], &whohas_msg, sizeof(struct pipe_whohas_msg));
	if (r < 0) {
		slog_error(FILE_LEVEL, "Unable to read pipe_whohas_msg from the pipe");
		return;
	}

	req = create_request(whohas_msg.file_hash, true, &whohas_msg.requester);
	if (!req) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		return;
	}

	generate_req_id(&whohas_msg.requester, whohas_msg.file_hash, req_id);
	ret = add_request_to_table(req_id, req, sus->reqs);
	if (ret == ALREADY_ADDED) {
		slog_warn(FILE_LEVEL, "This request is already set");
		free(req);
		req = get_request(req_id, sus->reqs);
		if (!req) {
			return;
		}

		communicate_whohas_result_to_peer(&req->whohas, &whohas_msg.requester);
		return;
	} else if (ret == NOT_ADDED) {
		free(req);
		slog_error(FILE_LEVEL, "Unable to set the request");
		communicate_error_to_peer(&req->requester);
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
		update_request(sus->reqs, req_id, &whohas);
	} else {
		if (cmp_next_against_self(sus->nb)) {
			// there's no other sp in the network. Just send the response
			communicate_whohas_result_to_peer(&whohas, &whohas_msg.requester);
			update_request(sus->reqs, req_id, &whohas);
		}

		send_whohas(sus, &whohas, true);
		add_pending_whohas(sus, &sus->nb->next, &whohas, true);
	}
}

/*
 * Write the prev address into the pipe
 */
static void write_prev_to_pipe(const struct sp_udp_state *sus)
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
 * Write a copy of the neighbors's addresses (+ a copy of self) as strings
 */
static void write_nb_addresses_to_pipe(const struct sp_udp_state *sus)
{
	struct sp_nb_addr sna;
	struct in_addr a;
	in_port_t port;
	size_t s = sizeof(char) * 32;
	ssize_t w = 0;
	fsnp_err_t err;

	memset(&sna, 0, sizeof(struct sp_nb_addr));
	a.s_addr = htonl(get_peer_ip());
	port = get_udp_sp_port();
	snprintf(sna.self, s, "%s:%hu", inet_ntoa(a), port);
	strncpy(sna.prev, sus->nb->prev_pretty, s);
	strncpy(sna.next, sus->nb->next_pretty, s);
	strncpy(sna.snd_next, sus->nb->snd_next_pretty, s);
	slog_debug(FILE_LEVEL, "Writing into the pipe neighbors' addresses")
	w = fsnp_timed_write(sus->w_pipe[WRITE_END], &sna, sizeof(struct sp_nb_addr),
	                     FSNP_TIMEOUT, &err);
	if (w < 0) {
		slog_error(FILE_LEVEL, "Unable to write neighbors' addresses in the pipe");
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

		case PIPE_ADDRESSES:
			slog_info(FILE_LEVEL, "PIPE_ADDRESSES read from sp UDP pipe");
			write_nb_addresses_to_pipe(sus);
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
	struct fsnp_whosnext whosnext;
	struct sender s;

	if (cmp_next_against_self(sus->nb) || !sus->next_validated) {
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &curr);
	ret = invalidate_next_if_needed(sus->nb, &sus->last, &curr, &old_next);
	fsnp_init_whosnext(&whosnext, NULL);
	switch (ret) {
		case VALIDATED_NO_TIMEOUT:
			break;

		case VALIDATED_TIMEOUT:
			s.addr = sus->nb->next;
			memcpy(s.pretty_addr, sus->nb->next_pretty, sizeof(char) * 32);
			send_whosnext(sus, &whosnext, &s);
			break;

		case INVALIDATED_NO_SND:
			rm_dead_sp_from_server(&old_next, SUPERPEER);
			sus->next_validated = false;
			if (cmp_prev(sus->nb, &old_next)) {
				// the next was also the prev. Unset it as well
				slog_debug(FILE_LEVEL, "The next was also the prev. Unsetting it");
				unset_prev(sus->nb);
			} else if (!cmp_prev_against_self(sus->nb)) {
				// this means that only two superpeers are remain in the network
				set_next(sus->nb, &sus->nb->prev);
				send_next(sus, NULL);
				add_pending_next(sus, &sus->nb->next, NULL);
				s.addr = sus->nb->next;
				memcpy(s.pretty_addr, sus->nb->next_pretty, sizeof(char) * 32);
				send_whosnext(sus, &whosnext, &s);
			}

			// TODO: re enter the network if needed
			break;

		case INVALIDATED_YES_SND:
			rm_dead_sp_from_server(&old_next, SUPERPEER);
			sus->next_validated = false;
			send_next(sus, NULL);
			add_pending_next(sus, &sus->nb->next, NULL);
			s.addr = sus->nb->next;
			memcpy(s.pretty_addr, sus->nb->next_pretty, sizeof(char) * 32);
			send_whosnext(sus, &whosnext, &s);
			break;

		default:
			slog_panic(FILE_LEVEL, "Unknown return from invalidate_next_if_needed");
			break;
	}
}

struct sp_thread_pipe {
	int r_pipe[2];
	int w_pipe[2];
	pthread_mutex_t mtx;
};

static struct sp_thread_pipe stp;

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

#ifndef FSNP_INF_TIMEOUT
#define SP_POLL_TIMEOUT 15000
#else
#define SP_POLL_TIMEOUT -1
#endif

/*
 * Entry point for the superpeer's udp subsystem.
 */
static void sp_udp_thread(void *data)
{
	struct sp_udp_state *sus = (struct sp_udp_state *)data;
	struct pollfd pollfd[POLLFD_NUM];
	int ret = 0;
	struct fsnp_whosnext whosnext;
	struct sender s;

	//sleep(10); // so we're sure to have left the sp
	//slog_debug(FILE_LEVEL, "sp-udp-thread is awake");
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

	update_timespec(&sus->last);
	s.addr = sus->nb->next;
	strncpy(s.pretty_addr, sus->nb->next_pretty, sizeof(char) * 32);
	fsnp_init_whosnext(&whosnext, NULL);
	send_whosnext(sus, &whosnext, &s);
	setup_poll(pollfd, sus);
	slog_info(FILE_LEVEL, "Superpeers' overlay network successfully joined");
	while (!sus->should_exit) {
		ret = poll(pollfd, POLLFD_NUM, SP_POLL_TIMEOUT);
		invalidate_requests(sus->reqs);
		if (ret > 0) {
			if (pollfd[PIPE].revents) {
				pipe_event(sus, pollfd[PIPE].revents);
				pollfd[PIPE].revents = 0;
			}

			if (pollfd[SOCK].revents) {
				sock_event(sus, pollfd[SOCK].revents);
				pollfd[SOCK].revents = 0;
			}
			check_pm_timeout(sus);
			check_if_next_alive(sus);
		} else if (ret == 0) {
			check_pm_timeout(sus);
			check_if_next_alive(sus);
		} else {
			slog_error(FILE_LEVEL, "poll error %d");
			prepare_exit_sp_mode();
			exit_sp_mode();
			sus->should_exit = true;
		}
	}

	send_leave(sus, true);
prev_leave:
	send_leave(sus, false);
no_leave:
	slog_info(FILE_LEVEL, "sp-udp-thread is leaving...");
	slog_info(FILE_LEVEL, "Destroyng the request cache");
	ht_destroy(sus->reqs);
	slog_info(FILE_LEVEL, "Destroying the pending_msgs list");
	list_destroy(sus->pending_msgs);
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
#undef INVALIDATED_NO_SND
#undef INVALIDATED_YES_SND
#undef VALIDATED_TIMEOUT

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

	slog_info(FILE_LEVEL, "Initializing pending_msgs linklist");
	sus->pending_msgs = list_create();
	if (!sus->pending_msgs) {
		slog_error(FILE_LEVEL, "Unable to create pending_msgs linklist");
		ht_destroy(sus->reqs);
		free(sus->nb);
		free(sus);
		return -1;
	}

	list_set_free_value_callback(sus->pending_msgs, free_pending_msg);
	slog_info(FILE_LEVEL, "Creating superpeer's pipe");
	ret = pipe(sus->r_pipe);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Pipe error %d", errno);
		list_destroy(sus->pending_msgs);
		ht_destroy(sus->reqs);
		free(sus->nb);
		free(sus);
		return -1;
	}

	ret = pipe(sus->w_pipe);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Pipe error %d", errno);
		list_destroy(sus->pending_msgs);
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
		list_destroy(sus->pending_msgs);
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
			list_destroy(sus->pending_msgs);
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
		list_destroy(sus->pending_msgs);
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

int get_neighbors_addresses(struct sp_nb_addr *sna)
{
	int msg = PIPE_ADDRESSES;
	int we = 0;
	int re = 0;
	ssize_t rw = 0;
	fsnp_err_t err;

	we = get_pipe_write_end();
	if (we == 0) {
		return -1;
	}

	slog_debug(FILE_LEVEL, "Writing PIPE_ADDRESSES to the sp-udp-thread");
	rw = fsnp_timed_write(we, &msg, sizeof(int), FSNP_TIMEOUT, &err);
	if (rw < 0) {
		slog_error(FILE_LEVEL, "Unable to write PIPE_ADDRESSES in the pipe");
		fsnp_log_err_msg(err, false);
		return -1;
	}

	re = get_pipe_read_end();
	if (re == 0) {
		return -1;
	}

	slog_debug(FILE_LEVEL, "Reading neighbors' address from the sp UDP pipe");
	rw = fsnp_timed_read(re, sna, sizeof(struct sp_nb_addr), FSNP_TIMEOUT, &err);
	if (rw < 0) {
		slog_error(FILE_LEVEL, "Unable to read neighbors' addresses from the pipe");
		fsnp_log_err_msg(err, false);
		return -1;
	}

	return 0;
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

#undef INVALIDATE_NEXT_THRESHOLD
#undef SP_POLL_TIMEOUT
