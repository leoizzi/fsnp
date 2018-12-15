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

#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <memory.h>

#include "peer/pending_msg.h"
#include "peer/superpeer-superpeer.h"
#include "peer/timespec.h"
#include "peer/neighbors.h"
#include "peer/peer-server.h"

#include "fsnp/fsnp.h"

#include "slog/slog.h"

void free_pending_msg(void *data)
{
	struct pending_msg *pm = (struct pending_msg *)data;

	free(pm);
}

/*
 * finish the initialization of a pending_msg and add it to the list
 */
static void add_pending(linked_list_t *list, struct pending_msg *pm)
{
	struct in_addr a;
	int ret = 0;

	memset(pm->pretty_addr, 0, sizeof(char) * 32);
	a.s_addr = htonl(pm->sp.ip);
	snprintf(pm->pretty_addr, sizeof(char) * 32, "%s:%hu", inet_ntoa(a), pm->sp.port);
	update_timespec(&pm->last_send);
	pm->retry = 0;
	slog_info(FILE_LEVEL, "Adding pending_msg of type %u for sp %s", pm->type,
	          pm->pretty_addr);

	ret = list_push_value(list, pm);
	if (ret < 0) {
		slog_warn(FILE_LEVEL, "Unable to push pending_msg");
		free(pm);
	}
}

void add_pending_next(struct sp_udp_state *sus, const struct fsnp_peer *sp,
                      const struct fsnp_peer *old_next)
{
	struct pending_msg *pm = NULL;

	if (cmp_next_against_self(sus->nb)) {
		return;
	}

	pm = malloc(sizeof(struct pending_msg));
	if (!pm) {
		slog_warn(FILE_LEVEL, "Unable to create pending_msg for NEXT msg")
		return;
	}

	memcpy(&pm->sp, sp, sizeof(struct fsnp_peer));
	pm->type = NEXT;
	pm->expected = ACK;
	pm->f.next = send_next;
	if (old_next) {
		memcpy(&pm->pfd.old_peer, old_next, sizeof(struct fsnp_peer));
	} else {
		memset(&pm->pfd.old_peer, 0, sizeof(struct fsnp_peer));
	}

	add_pending(sus->pending_msgs, pm);
}

void add_pending_whohas(struct sp_udp_state *sus, const struct fsnp_peer *sp,
						const struct fsnp_whohas *whohas, bool send_to_next)
{
	struct pending_msg *pm = NULL;

	if (send_to_next) {
		if (cmp_next_against_self(sus->nb)) {
			return;
		}
	}

	pm = malloc(sizeof(struct pending_msg));
	if (!pm) {
		slog_warn(FILE_LEVEL, "Unable to create pending_msg for WHOHAS msg")
		return;
	}

	memcpy(&pm->sp, sp, sizeof(struct fsnp_peer));
	pm->type = WHOHAS;
	pm->expected = ACK;
	pm->f.whohas = send_whohas;
	memcpy(&pm->pfd.pw.whohas, whohas, sizeof(struct fsnp_whohas));
	pm->pfd.pw.send_to_next = send_to_next;
	add_pending(sus->pending_msgs, pm);
}

struct is_pending_data {
	struct sp_udp_state *sus;
	struct fsnp_msg *msg;
	struct sender *sender;
};

/*
 * Iterate over all the pending messages. If the msg received was pending remove
 * it from the list
 */
int is_pending_iterator(void *item, size_t idx, void *user)
{
	struct pending_msg *pm = (struct pending_msg *)item;
	struct is_pending_data *pmd = (struct is_pending_data *)user;
	struct fsnp_msg *msg = pmd->msg;
	struct sender *sender = pmd->sender;
	struct sp_udp_state *sus = pmd->sus;
	struct sender s;
	struct fsnp_whosnext whosnext;

	UNUSED(idx);

	if (pm->expected != msg->msg_type) {
		return GO_AHEAD;
	}

	if (pm->sp.ip != sender->addr.ip || pm->sp.port != sender->addr.port) {
		return GO_AHEAD;
	}

	slog_debug(FILE_LEVEL, "The message received was pending. Removing it");
	if (pm->type == NEXT) {
		slog_info(FILE_LEVEL, "Next %s validated", sus->nb->next_pretty);
		sus->next_validated = true;
		s.addr = sus->nb->prev;
		strncpy(s.pretty_addr, sus->nb->prev_pretty, sizeof(char) * 32);
		fsnp_init_whosnext(&whosnext, &sus->nb->next);
		send_whosnext(sus, &whosnext, &s); // tell the prev who's the new next
		fsnp_init_whosnext(&whosnext, NULL);
		send_whosnext(sus, &whosnext, sender); // ask to the next who's after him
	}

	return REMOVE_AND_STOP;
}

/*
 * Look if the message received is pending. If so remove it from the list of
 * pending msgs.
 */
void is_pending(struct sp_udp_state *sus, struct fsnp_msg *msg,
				struct sender *sender)
{
	struct is_pending_data pmd;

	if (list_count(sus->pending_msgs) == 0) {
		return;
	}

	pmd.sus = sus;
	pmd.msg = msg;
	pmd.sender = sender;
	list_foreach_value(sus->pending_msgs, is_pending_iterator, &pmd);
}

struct check_pm_timeout_data
{
	struct sp_udp_state *sus;
	double curr_time;
};

/*
 * Try to send again a pending msg
 */
static void resend(struct sp_udp_state *sus, struct pending_msg *pm)
{
	slog_info(FILE_LEVEL, "Trying to send again pending_msg of type %u for peer"
	                      " %s", pm->expected, pm->pretty_addr);
	switch (pm->type) {
		case NEXT:
			if (pm->pfd.old_peer.ip == 0 && pm->pfd.old_peer.port == 0) {
				pm->f.next(sus, NULL);
			} else {
				pm->f.next(sus, &pm->pfd.old_peer);
			}
			break;

		case WHOHAS:
			pm->f.whohas(sus, &pm->pfd.pw.whohas, pm->pfd.pw.send_to_next);
			break;

		default:
			break;
	}

	pm->retry++;
	update_timespec(&pm->last_send);
}

/*
 * React to a pending_msg fail by its type
 */
static void handle_pm_fail(struct sp_udp_state *sus, struct pending_msg *pm)
{
	slog_warn(FILE_LEVEL, "pending_msg of type %u for peer %s has failed",
	          pm->expected, pm->pretty_addr);
	switch (pm->type) {
		case NEXT:
			if (!cmp_snd_next_against_self(sus->nb) && isset_snd_next(sus->nb)) {
				set_next_as_snd_next(sus->nb);
				if (pm->pfd.old_peer.ip == 0 && pm->pfd.old_peer.port == 0) {
					pm->f.next(sus, NULL);
					add_pending_next(sus, &sus->nb->next, NULL);
				} else {
					pm->f.next(sus, &pm->pfd.old_peer);
					add_pending_next(sus, &sus->nb->next,
					                 &pm->pfd.old_peer);
				}
			}

			rm_dead_sp_from_server(&pm->sp, SUPERPEER);
			break;

		case WHOHAS:
			if (pm->pfd.pw.send_to_next) {
				rm_dead_sp_from_server(&sus->nb->next, SUPERPEER);
				set_next_as_snd_next(sus->nb);
				send_next(sus, NULL);
				sus->next_validated = false;
				add_pending_next(sus, &sus->nb->next, NULL);
			}

			break;
		default:
			break;
	}
}


#define PM_TIMEOUT 15.f // s

/*
 * Iterate over all the values of pending_msgs to check if a pending message
 * has timed out
 */
static int check_pm_timeout_iterator(void *item, size_t idx, void *user)
{
	struct pending_msg *pm = (struct pending_msg *)item;
	struct check_pm_timeout_data *data = (struct check_pm_timeout_data *)user;
	struct sp_udp_state *sus = data->sus;
	double last_time = 0;

	UNUSED(idx);

	if (pm->type == WHOHAS) {
		if (pm->pfd.pw.send_to_next) {
			if (!cmp_next(sus->nb, &pm->sp)) {
				// If they don't match this pm is trash
				return REMOVE_AND_GO;
			}
		}
	} else if (pm->type == NEXT) {
		if (!cmp_next(sus->nb, &pm->sp)) {
			// If they don't match this pm is trash
			return REMOVE_AND_GO;
		}
	}

	last_time = (double)pm->last_send.tv_sec + NSEC_TO_SEC(pm->last_send.tv_nsec);
	if (data->curr_time - last_time > PM_TIMEOUT) {
		if (pm->retry < 4) {
			resend(sus, pm);
			return GO_AHEAD;
		} else {
			handle_pm_fail(sus, pm);
			return REMOVE_AND_GO;
		}
	} else {
		return GO_AHEAD;
	}
}

void check_pm_timeout(struct sp_udp_state *sus)
{
	struct check_pm_timeout_data data;
	struct timespec curr;

	update_timespec(&curr);
	data.curr_time = (double)curr.tv_sec + NSEC_TO_SEC(curr.tv_nsec);
	data.sus = sus;
	list_foreach_value(sus->pending_msgs, check_pm_timeout_iterator, &data);
}

#undef PM_TIMEOUT