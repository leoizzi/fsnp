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

#ifndef FSNP_NEIGHBORS_H
#define FSNP_NEIGHBORS_H

#include <stdio.h>
#include <memory.h>

#include "peer/peer.h"

#include "slog/slog.h"

#include "compiler.h"

FSNP_BEGIN_DECL

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
	UNSET_NEXT(nb->flags);
	slog_info(FILE_LEVEL, "next sp unset. Setting it to self");
	self.ip = get_peer_ip();
	self.port = get_udp_sp_port();
	set_next(nb, &self);
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
	UNSET_SND_NEXT(nb->flags);
	slog_info(FILE_LEVEL, "snd_next sp unset. Setting it to self");
	self.ip = get_peer_ip();
	self.port = get_udp_sp_port();
	set_snd_next(nb, &self);
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
	UNSET_PREV(nb->flags);
	slog_info(FILE_LEVEL, "prev sp unset. Setting it to self");
	self.ip = get_peer_ip();
	self.port = get_udp_sp_port();
	set_prev(nb, &self);
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

FSNP_END_DECL

#endif //FSNP_NEIGHBORS_H
