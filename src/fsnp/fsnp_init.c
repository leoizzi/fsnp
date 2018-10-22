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
#include <memory.h>

#include "fsnp/fsnp_init.h"

// TODO: add support for big endian

void fsnp_init_msg(struct fsnp_msg *header, fsnp_type_t type, uint64_t size)
{
	memcpy(header->magic, FSNP_MAGIC, FSNP_MAGIC_SIZE);
	header->msg_type = type;
	header->msg_size = size - sizeof(*header);
}

void fsnp_init_query(struct fsnp_query *query, fsnp_peer_type_t type)
{
	query->peer_type = type;
	fsnp_init_msg(&query->header, QUERY, sizeof(*query));
}

struct fsnp_query_res *fsnp_create_query_res(in_addr_t peer_addr, uint8_t num_sp,
                                             struct fsnp_peer *sp_list)
{
	struct fsnp_query_res *query_res = NULL;
	uint64_t list_size = 0;
	uint64_t size = 0;

	if (num_sp == 0) {
		list_size = sizeof(struct fsnp_peer);
	} else {
		list_size = num_sp * sizeof(struct fsnp_peer);
	}

	size = list_size + sizeof(*query_res) - sizeof(query_res->sp_list);
	query_res = malloc(size);
	if (!query_res) {
		return NULL;
	}

	if (num_sp == 0) {
		query_res->num_sp = 1;
		query_res->sp_list->ip = 0;
		query_res->sp_list->port = 0;
	} else {
		query_res->num_sp = num_sp;
		memcpy(query_res->sp_list, sp_list, list_size);
	}

	query_res->peer_addr = peer_addr;
	fsnp_init_msg(&query_res->header, QUERY_RES, size);
	return query_res;
}

void fsnp_init_add_sp(struct fsnp_add_sp *sp, in_port_t p_port, in_port_t sp_port)
{
	sp->p_port = p_port;
	sp->sp_port = sp_port;
	fsnp_init_msg(&sp->header, ADD_SP, sizeof(*sp));
}

void fsnp_init_rm_sp(struct fsnp_rm_sp *rm_sp, struct fsnp_peer *addr,
                     fsnp_peer_type_t type)
{
	rm_sp->peer_type = type;
	memcpy(&rm_sp->addr, addr, sizeof(rm_sp->addr));
	fsnp_init_msg(&rm_sp->header, RM_SP, sizeof(*rm_sp));
}

struct fsnp_join *fsnp_create_join(uint32_t num_files, sha256_t *files_hash)
{
	uint64_t data_size = 0;
	uint64_t size = 0;
	struct fsnp_join *join = NULL;
	uint32_t i = 0;

	data_size = num_files * sizeof(sha256_t); // size of the field files_hash
	size = data_size +  sizeof(*join) - sizeof(join->files_hash);
	join = malloc(size);
	if (!join) {
		return NULL;
	}

	join->num_files = num_files;
	if (data_size > 0) {
		for (i = 0; i < num_files; i++) {
			memcpy(join->files_hash + i * sizeof(sha256_t), files_hash[i],
					sizeof(sha256_t));
		}
	} else {
		memset(join->files_hash, 0, sizeof(join->files_hash));
	}

	fsnp_init_msg(&join->header, JOIN, size);
	return join;
}

void fsnp_init_ack(struct fsnp_ack *ack)
{
	fsnp_init_msg(&ack->header, ACK, sizeof(*ack));
}

void fsnp_init_leave(struct fsnp_leave *leave)
{
	fsnp_init_msg(&leave->header, LEAVE, sizeof(*leave));
}

void fsnp_init_file_req(struct fsnp_file_req *file_req, sha256_t hash)
{
	memcpy(file_req->hash, hash, sizeof(sha256_t));
	fsnp_init_msg(&file_req->header, FILE_REQ, sizeof(*file_req));
}

struct fsnp_file_res *fsnp_create_file_res(uint8_t num_peers,
                                           struct fsnp_peer *peers)
{
	struct fsnp_file_res *file_res = NULL;
	uint64_t peer_size = 0;
	uint64_t size = 0;

	peer_size = num_peers * sizeof(struct fsnp_peer);
	size = peer_size + sizeof(*file_res) - sizeof(file_res->peers);
	file_res = malloc(size);
	if (!file_res) {
		return NULL;
	}

	file_res->num_peers = num_peers;
	memcpy(file_res->peers, peers, peer_size);
	fsnp_init_msg(&file_res->header, FILE_RES, size);

	return file_res;
}

struct fsnp_update *fsnp_create_update(uint32_t num_files,
                                       sha256_t *files_hash)
{
	struct fsnp_update *update = NULL;
	uint64_t data_size = 0;
	uint64_t size = 0;
	uint32_t i = 0;

	data_size = num_files * sizeof(sha256_t); // size of the field files_hash
	size = data_size +  sizeof(*update) - sizeof(update->files_hash);
	update = malloc(size);
	if (!update) {
		return NULL;
	}

	update->num_files = num_files;
	if (data_size > 0) {
		for (i = 0; i < num_files; i++) {
			memcpy(update->files_hash + i * sizeof(sha256_t), files_hash[i],
					sizeof(sha256_t));
		}
	} else {
		memset(update->files_hash, 0, sizeof(update->files_hash));
	}

	fsnp_init_msg(&update->header, UPDATE, size);
	return update;
}

void fsnp_init_alive(struct fsnp_alive *alive)
{
	fsnp_init_msg(&alive->header, ALIVE, sizeof(*alive));
}

void fsnp_init_get_file(struct fsnp_get_file *get_file, sha256_t hash)
{
	memcpy(get_file->hash, hash, sizeof(sha256_t));
	fsnp_init_msg(&get_file->header, GET_FILE, sizeof(*get_file));
}

void fsnp_init_error(struct fsnp_error *error)
{
	fsnp_init_msg(&error->header, ERROR, sizeof(*error));
}

void fsnp_init_download(struct fsnp_download *download, uint64_t file_size)
{
	download->file_size = file_size;
	fsnp_init_msg(&download->header, DOWNLOAD, sizeof(*download));
}

void fsnp_init_whohas(struct fsnp_whohas *whohas, sha256_t req_id,
                      sha256_t file_hash, uint8_t missing_peers)
{
	memcpy(whohas->req_id, req_id, sizeof(sha256_t));
	memcpy(whohas->file_hash, file_hash, sizeof(sha256_t));
	whohas->missing_peers = missing_peers;
	fsnp_init_msg(&whohas->header, WHOHAS, sizeof(*whohas));
}

void fsnp_init_promote(struct fsnp_promote *promote, in_port_t sp_port,
					   struct fsnp_peer *sp)
{
	uint64_t size = 0;

	memcpy(&promote->sp, sp, sizeof(promote->sp));
	promote->sp_port = sp_port;
	fsnp_init_msg(&promote->header, PROMOTE, sizeof(*promote));
}
