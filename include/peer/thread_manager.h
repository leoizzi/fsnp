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

#ifndef FSNP_THREAD_MANAGER_H
#define FSNP_THREAD_MANAGER_H

#include <pthread.h>

#include "compiler.h"

FSNP_BEGIN_DECL

/*
 * The entry point of a new thread. Call just return from here, not pthread_create
 */
typedef void (*entry_point)(void *data);

/*
 * Initialize the thread_manager. If something goes wrong the return value is -1
 */
int init_thread_manager(void);

/*
 * Launch a new thread. The thread manager will take care of freeing all the
 * memory used after the thread has accomplished its work.
 * 'name' can be NULL
 * If the manager is unable to start the thread a value of -1 is returned
 */
int start_new_thread(entry_point e, void *data, const char *name);

/*
 * Join all the closed threads, if any
 */
void join_threads_if_any(void);

/*
 * Close the thread manager, freeing all its resources
 */
void close_thread_manager(void);

FSNP_END_DECL

#endif //FSNP_THREAD_MANAGER_H
