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

#ifndef FSNP_FSNP_INIT_H
#define FSNP_FSNP_INIT_H


#include "compiler.h"
#include "fsnp_types.h"
/*
 * Initialization utility functions.
 * There are two kind of initialization functions:
 *      - The ones which need memory allocation;
 *      - The ones which don't.
 *
 * The former type takes only the arguments needed for the allocation and return
 * a pointer to the struct.
 *
 * The latter type takes a reference to the struct memory and the arguments in
 * order to perform the initialization. The return type is void.
 *
 * In order to distinguish the cases the functions that allocate memory have the
 * prefix fsnp_create_*, while the ones which just do initialization have the
 * prefix fsnp_init_*
 */

FSNP_BEGIN_DECL
 
EXPORT void fsnp_init_query(struct fsnp_query *query, fsnp_peer_type_t type);

EXPORT struct fsnp_query_res *fsnp_create_query_res(in_addr_t peer_addr,
                                                    uint8_t num_sp,
                                                    const struct fsnp_peer *sp_list);

EXPORT void fsnp_init_add_sp(struct fsnp_add_sp *add_sp, in_port_t p_port,
                             in_port_t sp_port);

EXPORT void fsnp_init_rm_sp(struct fsnp_rm_sp *rm_sp,
                            const struct fsnp_peer *addr,
                            fsnp_peer_type_t type);

EXPORT struct fsnp_join *fsnp_create_join(uint32_t num_files, uint16_t dw_port,
										  sha256_t *files_hash);

EXPORT void fsnp_init_ack(struct fsnp_ack *ack);

EXPORT void fsnp_init_leave(struct fsnp_leave *leave);

EXPORT void fsnp_init_file_req(struct fsnp_file_req *file_req, sha256_t hash);

EXPORT struct fsnp_file_res *fsnp_create_file_res(uint8_t num_peers,
												  const struct fsnp_peer *peers);

EXPORT struct fsnp_update *fsnp_create_update(uint32_t num_files,
                                              sha256_t *files_hash);

EXPORT void fsnp_init_alive(struct fsnp_alive *alive);

EXPORT void fsnp_init_get_file(struct fsnp_get_file *get_file, sha256_t hash);

EXPORT void fsnp_init_error(struct fsnp_error *error);

EXPORT void fsnp_init_download(struct fsnp_download *download,
							   uint64_t file_size);

EXPORT void fsnp_init_promote(struct fsnp_promote *promote, in_port_t sp_port,
                              const struct fsnp_peer *sp);

EXPORT void fsnp_init_promoted(struct fsnp_promoted *promoted);

/*
 * If there's no old_next it's allowed to pass NULL instead
 */
EXPORT void fsnp_init_next(struct fsnp_next *next,
                           const struct fsnp_peer *old_next);

/*
 * If there's no next it's allowed to pass NULL instead
 */
EXPORT void fsnp_init_whosnext(struct fsnp_whosnext *whosnext,
                               const struct fsnp_peer *next);

EXPORT void fsnp_init_whohas(struct fsnp_whohas *whohas, struct fsnp_peer *sp,
                             sha256_t req_id, sha256_t file_hash,
                             uint8_t num_peers, struct fsnp_peer *owners);

FSNP_END_DECL

#endif //FSNP_FSNP_INIT_H
