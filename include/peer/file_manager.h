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

#include "fsnp/sha-256.h"

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
