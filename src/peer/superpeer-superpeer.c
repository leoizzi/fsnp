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
 * Set the prev sp as 'addr'
 */
static inline void set_prev(struct neighbors *nb, struct fsnp_peer *addr)
{
	struct in_addr a;

    memcpy(&nb->prev, addr, sizeof(struct fsnp_peer));
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
	struct neighbors nb;
	bool should_exit;
};

#define READ_END 0
#define WRITE_END 1

static void send_promoted(struct sp_udp_state *sus)
{

}

/*
 * Entry point for the superpeer's udp subsystem.
 */
static void sp_udp_thread(void *data)
{
	struct sp_udp_state *sus = (struct sp_udp_state *)data;

	if (isset_next(&sus->nb)) {
		send_promoted(sus);
	}

	while (!sus->should_exit) {
		;
	}

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

	ret = pipe(sus->pipe);
	if (ret < 0) {
		slog_error(FILE_LEVEL, "Pipe error %d", errno);
		free(sus);
		return -1;
	}

	memset(&sus->nb, 0, sizeof(sus->nb));
	sus->sock = udp;
	sus->should_exit = false;
	switch (n) {
		case NO_SP:
			break;

		case ONE_SP:
			set_next(&sus->nb, sps);
			break;

		case TWO_SPS:
			set_next(&sus->nb, &sps[0]);
			set_snd_next(&sus->nb, &sps[1]);
			break;

		default:
			slog_error(FILE_LEVEL, "Wrong parameter: n can't be %u", n);
			free(sus);
			return -1;
	}

	ret = start_new_thread(sp_udp_thread, sus, "sp-udp-thread");
	if (ret < 0) {
		sus->sock = 0;
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