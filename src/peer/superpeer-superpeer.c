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
static inline void set_next(struct neighbors *nb, struct fsnp_peer *addr)
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
static always_inline bool isset_next(struct neighbors *nb)
{
	return GET_NEXT(nb->flags) ? true : false;
}

/*
 * Compare a fsnp_peer with the next. If they match return true, false otherwise
 */
static inline bool cmp_next(struct neighbors *nb, struct fsnp_peer *p)
{
	if (nb->next.ip == p->ip) {
		if (nb->next.port == p->port) {
			return true;
		}
	}

	return false;
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
static inline void set_snd_next(struct neighbors *nb, struct fsnp_peer *addr)
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
static always_inline int isset_snd_next(struct neighbors *nb)
{
	return GET_SND_NEXT(nb->flags) ? true : false;
}

/*
 * Compare a fsnp_peer with the snd_next. If they match return true, false
 * otherwise
 */
static inline bool cmp_snd_next(struct neighbors *nb, struct fsnp_peer *p)
{
	if (nb->snd_next.ip == p->ip) {
		if (nb->snd_next.port == p->port) {
			return true;
		}
	}

	return false;
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
static inline void set_prev(struct neighbors *nb, struct fsnp_peer *addr)
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
static always_inline int isset_prev(struct neighbors *nb)
{
	return GET_PREV(nb->flags) ? true : false;
}

/*
 * Compare a fsnp_peer with the prev. If they match return true, false otherwise
 */
static inline bool cmp_prev(struct neighbors *nb, struct fsnp_peer *p)
{
	if (nb->prev.ip == p->ip) {
		if (nb->prev.port == p->port) {
			return true;
		}
	}

	return false;
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

struct sp_udp_state {
	int sock;
	int pipe[2];
	struct neighbors *nb;
	struct timespec last;
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
static inline void swap_timespec(struct timespec *a, struct timespec *b)
{
	a->tv_sec = b->tv_sec;
	a->tv_nsec = b->tv_nsec;
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
                                     struct timespec *curr)
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
static void send_promoted(struct sp_udp_state *sus)
{
	struct fsnp_promoted promoted;
	fsnp_err_t err;

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
static void send_next(struct sp_udp_state *sus, const struct fsnp_peer *old)
{
	struct fsnp_next next;
	fsnp_err_t err;
	struct in_addr addr;

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

/*
 * Make sure that the prev will send a NEXT msg. If the timer will fire, send a
 * NEXT msg to his prev, which is stored in the snd_next position
 */
static void ensure_prev_conn(struct sp_udp_state *sus)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_next *next = NULL;
	struct fsnp_peer p;
	fsnp_err_t err;
	unsigned counter = 0;

	while (true) {
		msg = fsnp_timed_recvfrom(sus->sock, 0, true, &p, &err);
		if (!msg) {
			slog_warn(FILE_LEVEL, "Unable to receive a next msg from the prev");
			unset_prev(sus->nb);
			fsnp_log_err_msg(err, false);
			if (isset_snd_next(sus->nb)) {
				set_prev(sus->nb, &sus->nb->snd_next);
				unset_snd_next(sus->nb);
				continue;
			} else {
				slog_warn(FILE_LEVEL, "Unable to ensure the prev's connection");
				unset_all(sus->nb);
				prepare_exit_sp_mode();
				exit_sp_mode();
				return;
			}
		}

		if (!cmp_prev(sus->nb, &p)) {
			free(msg);
			counter++;
			if (counter >= 4) {
				slog_warn(FILE_LEVEL, "Too much time waiting for prev.");
				unset_all(sus->nb);
				prepare_exit_sp_mode();
				exit_sp_mode();
				return;
			} else {
				continue;
			}
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

static void ensure_next_conn(struct sp_udp_state *sus)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_peer p;
	fsnp_err_t err;
	unsigned counter = 0;

	while (true) {
		msg = fsnp_timed_recvfrom(sus->sock, 0, true, &p, &err);
		if (!msg) {
			slog_warn(FILE_LEVEL, "Unable to ensure next's connection");
			unset_all(sus->nb);
			prepare_exit_sp_mode();
			exit_sp_mode();
			return;
		}

		if (!cmp_next(sus->nb, &p)) {
			free(sus);
			counter++;
			if (counter >= 4) {
				slog_warn(FILE_LEVEL, "Too much time waiting for next");
				unset_all(sus->nb);
				prepare_exit_sp_mode();
				exit_sp_mode();
				return;
			}
			continue;
		} else {
			break;
		}
	}

	if (msg->msg_type != ACK) {
		slog_warn(FILE_LEVEL, "Wrong msg type received from %s: expected %u, "
		                      "got %u", sus->nb->next_pretty, NEXT, msg->msg_type);
	}
}

#define POLLFD_NUM 2
#define PIPE 0
#define SOCK 1

/*
 * Setup the pollfd structures
 */
static void setup_poll(struct pollfd *pollfd, struct sp_udp_state *sus)
{
	memset(pollfd, 0, sizeof(struct pollfd) * POLLFD_NUM);

	pollfd[PIPE].fd = sus->pipe[READ_END];
	pollfd[PIPE].events = POLLIN | POLLPRI;
	pollfd[SOCK].fd = sus->sock;
	pollfd[SOCK].events = POLLIN | POLLPRI;
}

static void pipe_event(struct sp_udp_state *sus)
{
	UNUSED(sus);
}

static void sock_event(struct sp_udp_state *sus)
{
	UNUSED(sus);
}

static void timeout_event(struct sp_udp_state *sus)
{
	struct timespec curr;
	int ret = 0;

	clock_gettime(CLOCK_MONOTONIC, &curr);
	ret = invalidate_next_if_needed(sus->nb, &sus->last, &curr);
	switch (ret) {
		case VALIDATED:
			break;

		case INVALIDATED_NO_SND:
			// TODO: Continue from here
			break;

		case INVALIDATED_YES_SND:
			send_next(sus, NULL);
			break;

		default:
			slog_panic(FILE_LEVEL, "Unknown return from invalidat_next_if_needed");
			break;
	}
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

	if (isset_prev(sus->nb)) {
		send_promoted(sus);
		ensure_prev_conn(sus);
	}

	if (isset_next(sus->nb)) {
		send_next(sus, NULL);
		ensure_next_conn(sus);
	}

	setup_poll(pollfd, sus);
	clock_gettime(CLOCK_MONOTONIC, &sus->last);
	while (!sus->should_exit) {
		ret = poll(pollfd, POLLFD_NUM, POLL_TIMEOUT);
		if (ret > 0) {
			if (pollfd[PIPE].revents) {
				pipe_event(sus);
				pollfd[PIPE].revents = 0;
			}

			if (pollfd[SOCK].revents) {
				sock_event(sus);
				pollfd[SOCK].revents = 0;
			}
		} else if (ret == 0) {
			timeout_event(sus);
		} else {
			slog_error(FILE_LEVEL, "poll error %d");
			prepare_exit_sp_mode();
			exit_sp_mode();
			sus->should_exit = true;
		}
	}

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

#define NO_SP 0
#define ONE_SP 1
#define TWO_SPS 2

int enter_sp_network(int udp, struct fsnp_peer *sps, unsigned n)
{
	int ret = 0;
	struct sp_udp_state *sus = calloc(1, sizeof(struct sp_udp_state));
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

	ret = pipe(sus->pipe);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Pipe error %d", errno);
		free(sus->nb);
		free(sus);
		return -1;
	}

	sus->sock = udp;
	sus->should_exit = false;
	switch (n) {
		case NO_SP:
			break;

		case ONE_SP:
			set_prev(sus->nb, sps);
			break;

		case TWO_SPS:
			set_prev(sus->nb, &sps[0]);
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
			free(sus->nb);
			free(sus);
			return -1;
	}

	ret = start_new_thread(sp_udp_thread, sus, "sp-udp-thread");
	if (ret < 0) {
		sus->sock = 0;
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
