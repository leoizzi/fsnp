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

#ifndef FSNP_FILE_MANAGER_H
#define FSNP_FILE_MANAGER_H

#include <stdbool.h>
#include <limits.h>

#include "fsnp/sha-256.h"
#include "fsnp/fsnp_types.h"

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * Initialize the file manager
 * Returns 0 on success, -1 otherwise
 */
int init_file_manager(void);

/*
 * Close the file manager
 */
void close_file_manager(void);

/*
 * Set the directory where are located the files to share. path must be non NULL
 * Returns 0 on success, -1 otherwise
 */
int set_shared_dir(const char *path);

/*
 * Set the directory where to download the files. If path is NULL then will be
 * used the directory where the executable lives (which is the default)
 * Returns 0 on success, -1 otherwise
 */
int set_download_dir(const char *path);

/*
 * Returns true if the shared dir is set, false otherwise
 */
bool shared_dir_is_set(void);

/*
 * Return a newly allocated array of sha256_t, which are all the keys of the
 * files. In num will be found in output the number of elements in the array.
 */
sha256_t *retrieve_all_keys(uint32_t *num);

/*
 * Return true if the key is present in the file manager, false otherwise
 */
bool key_exists(sha256_t key);

/*
 * Delete 'key' from a hashtable.
 * If dw is true the key will be deleted from the download hashtable, otherwise
 * will be deleted from the shared hashtable
 */
void delete_key(sha256_t key);

/*
 * Return the size of the file associated to key
 */
size_t get_file_size(sha256_t key);

/*
 * Get a file descriptor for the one associated to key. The caller is responsible
 * to close it when it has done.
 *
 * if read is true the file will be opened as read-only, otherwise it will be
 * created and opened as read-write.
 *
 * filename has a meaning only if read is false. In this case it will be the
 * name of the file.
 */
int get_file_desc(sha256_t key, bool read, char filename[FSNP_NAME_MAX]);

/*
 * Create a new file called 'filename' in the download_path. It must be closed
 * with close_download_file.
 *
 * The return value is a file descriptor
 */
int create_download_file(char filename[FSNP_NAME_MAX]);

/*
 * Close a file previosly opened with create_download_file.
 *
 * If del is true the file will be closed and removed, otherwise will be
 * available for sharing
 */
void close_download_file(int fd, char filename[256], sha256_t hash, bool del);

/*
 * Ask to the file manager if something has changed. Return true if changes are
 * present,false otherwise
 */
bool check_for_updates(void);

/*
 * Show the user the path where he's saving the files
 */
void show_download_path(void);

FSNP_END_DECL

#endif //FSNP_FILE_MANAGER_H
