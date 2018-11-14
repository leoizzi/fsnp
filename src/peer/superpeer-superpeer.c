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

#include "peer/superpeer-superpeer.h"
#include "peer/superpeer.h"
#include "peer/thread_manager.h"

#include "fsnp/fsnp.h"

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
	struct fsnp_peer p;

	p.ip = nb->snd_next.ip;
	p.port = nb->snd_next.port;
	set_next(nb, &p);
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
	bool should_exit;
};

#define READ_END 0
#define WRITE_END 1

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
 * Make sure that the prev will send a NEXT msg. If the timer will fire
 */
void ensure_next_conn(struct sp_udp_state *sus)
{
	struct fsnp_msg *msg = NULL;
	struct fsnp_next *next = NULL;
	struct fsnp_peer peer;
	fsnp_err_t err;

	do {
		msg = fsnp_timed_recvfrom(sus->sock, 0, true, &peer, &err);
		if (!msg) {
			slog_warn(FILE_LEVEL, "Unable to receive a next msg from the prev");
			unset_prev(sus->nb);
			fsnp_log_err_msg(err, false);
			return;
		}
		// do this until the msg on the socket is from our promoter
	} while (!cmp_prev(sus->nb, &peer));

	if (msg->msg_type != NEXT) {
		slog_warn(FILE_LEVEL, "Wrong msg type received from %s: expected %u, "
						"got %u", sus->nb->prev_pretty, NEXT, msg->msg_type);
		slog_warn(STDOUT_LEVEL, "Unable to join the sp network. Going back to "
						  "be a normal peer");
		sus->should_exit = true;
		prepare_exit_sp_mode();
		exit_sp_mode();
	}

	slog_info(FILE_LEVEL, "NEXT msg received from prev %s", sus->nb->prev_pretty);
	next = (struct fsnp_next *)msg;
	if (next->old_next.ip != 0 && next->old_next.port != 0) {
		set_next(sus->nb, &next->old_next);
	}
}

/*
 * Entry point for the superpeer's udp subsystem.
 */
static void sp_udp_thread(void *data)
{
	struct sp_udp_state *sus = (struct sp_udp_state *)data;

	if (isset_prev(sus->nb)) {
		send_promoted(sus);
		ensure_next_conn(sus);
	}

	if (isset_next(sus->nb)) {
		// TODO: send next without the old_next
	}

	while (!sus->should_exit) {
		break;
	}

	free(sus->nb);
	close(sus->sock);
	close(sus->pipe[READ_END]);
	close(sus->pipe[WRITE_END]);
}

#define NO_SP 0
#define ONE_SP 1
#define TWO_SPS 2

int enter_sp_network(int udp, struct fsnp_peer *sps, unsigned n)
{
	int ret = 0;
	struct sp_udp_state *sus = malloc(sizeof(struct sp_udp_state));
	if (!sus) {
		slog_error(FILE_LEVEL, "malloc error %d", errno);
		return -1;
	}

	sus->nb = malloc(sizeof(struct neighbors));
	if (!sus->nb) {
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

	memset(sus->nb, 0, sizeof(struct neighbors));
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
