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

#ifndef FSNP_SP_MANAGER_H
#define FSNP_SP_MANAGER_H

#include "boot_server/server_fsnp.h"

#include "struct/linklist.h"

#include "compiler.h"

FSNP_BEGIN_DECL
/*
 * Initialize the superpeer manager. Returns 0 on success, -1 otherwise
 */
int init_sp_manager(void);

/*
 * Close the superpeer manager, releasing all the resources used
 */
void close_sp_manager(void);

/*
 * Add a superpeer to the list.
 * Returns 0 on success, -1 otherwise
 */
int add_sp_to_list(struct fsnp_server_sp *sp);

/*
 * Remove a superpeer from the list.
 * In sp are contained the address and the port of the superpeer to remove.
 * type is used to know if the port to check for identifying the sp is the
 * superpeer's one or the peer's one
 */
struct fsnp_server_sp *rm_sp(struct fsnp_peer *sp, fsnp_peer_type_t type);

/*
 * Return a linked list which contains all the sp.
 * The sp are stored as struct fsnp_server_sp
 * When it's not needed anymore the list can be safely destroyed
 */
linked_list_t *read_all_sp(void);

/*
 * Return an array of fsnp_peer, where the port type is specified by type and
 * the length of the array is contained in num_sp.
 */
struct fsnp_peer *read_sp_by_type(uint8_t *num_sp, fsnp_peer_type_t type);

/*
 * Get the number of superpeers known by the server
 */
size_t count_sp(void);

/*
 * Lock the superpeer list
 */
void lock_sp_list(void);

/*
 * Unlock the superpeer list
 */
void unlock_sp_list(void);

FSNP_END_DECL

#endif //FSNP_SP_MANAGER_H
