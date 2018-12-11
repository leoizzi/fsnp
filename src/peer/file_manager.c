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

#include <limits.h>
#include <stdbool.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>
#include <fcntl.h>

#include "peer/file_manager.h"
#include "peer/thread_manager.h"
#include "peer/peer-superpeer.h"
#include "peer/peer.h"

#include "struct/hashtable.h"

#include "fsnp/sha-256.h"

#include "slog/slog.h"

// TODO: look for files also in the dw directory

struct directory {
	char path[PATH_MAX]; // the root path
	hashtable_t *hashtable;
	bool is_set;
};

struct h_entry {
	// name max doesn't consider the '\0' char, this is why there's the +1
	char name[NAME_MAX + 1];
	size_t name_len;
	char path[PATH_MAX];
	/* set to true when "parse_dir" find it, set to false by "update_peer". This
	 * mechanism allow the detection of files no longer present inside the
	 * directory */
	bool found;
};

#define HASH_MAX_SIZE 1UL << 32

static struct directory shared;
static struct directory download;

static void free_callback(void *data)
{
	struct h_entry *entry = (struct h_entry *)data;
	free(entry);
}

/*
 * Add the file to the table. If 'sha' is NULL the key will be calculated by
 * this function
 */
static void add_file_to_table(hashtable_t *hashtable, const char *name,
							  size_t name_len, const char *path, sha256_t sha)
{
	sha256_t key;
	struct h_entry *e = NULL;
	int ret = 0;
	char key_str[SHA256_STR_BYTES];

	e = malloc(sizeof(struct h_entry));
	if (!e) {
		return;
	}

	if (sha) {
		memcpy(key, sha, sizeof(sha256_t));
	} else {
		sha256(name, name_len, key);
	}

	strncpy(e->name, name, name_len);
	strncpy(e->path, path, PATH_MAX);
	e->name_len = name_len;
	e->found = true;
	ret = ht_set(hashtable, key, sizeof(key), e, sizeof(*e));
	if (ret < 0) {
		free(e);
		slog_debug(FILE_LEVEL, "Unable to add file \"%s\"", name);
	}

	stringify_hash(key_str, key);
	slog_info(FILE_LEVEL, "Adding file \"%s\", path \"%s\", SHA-256 \"%s\"",
			name, path, key_str);
}

#define ERR -1
#define OK 0
#define NEW 1

/*
 * Control if a file is already known. If not, add it to the hashtable and
 * communicate it to the caller with the return value
 */
static int check_if_known(hashtable_t *hashtable, const char *name,
                          size_t name_len, const char *path)
{
	sha256_t key;
	int ret = 0;
	struct h_entry *entry;

	sha256(name, name_len, key);
	ret = ht_exists(hashtable, key, sizeof(key));
	if (ret == 1) { // the key already exists
		entry = ht_get(hashtable, key, sizeof(key), NULL);
		entry->found = true;
		return OK;
	} else if (ret == 0) { // the key doesn't exists
		add_file_to_table(hashtable, name, name_len, path, key);
		return NEW;
	} else { // error
		return ERR;
	}
}

/*
 * Go over all the files contained in the directory's path and:
 *      - if "first_time" is true -> add them to the hash table
 *      - if "first_time" is false -> check if the file already exists, if not
 *        add him to the table and signal it to the caller with the return value
 *
 * For distinguish the cases there are 3 macro: ERR, OK, NEW.
 */
static int parse_dir(hashtable_t *hashtable, const char *path, bool first_time)
{
	DIR *dir = NULL;
	struct dirent *dirent = NULL;
	struct stat s;
	int ret = 0;
	int res = OK;
	int prev_res = OK;
	char filename[PATH_MAX];
	size_t name_len = 0;
	int mode = 0;

	dir = opendir(path);
	if (!dir) {
		slog_warn(STDOUT_LEVEL, "%s is not a directory!", path);
		return ERR;
	}

	while ((dirent = readdir(dir)) != NULL) {
		// skip all the hidden files/directories, as well as . and ..
		if (!strncmp(dirent->d_name, ".", 1)) {
			continue;
		}

		strncpy(filename, path, sizeof(filename));
		if (filename[strlen(path) - 1] != '/') { // fix the path if needed
			strcat(filename, "/\0");
		}

		name_len = strlen(dirent->d_name) + 1; // consider the '\0' char
		strncat(filename, dirent->d_name, name_len);
		ret = stat(filename, &s);
		if (ret < 0) {
			if (errno == EACCES) { // not enough permission: go to the next one
				slog_warn(FILE_LEVEL, "Not enough permission to stat %s", filename);
				continue;
			} else {
				break;
			}
		}

		mode = s.st_mode & S_IFMT;

		if (mode == S_IFREG) {
			if (first_time) {
				add_file_to_table(hashtable, dirent->d_name, name_len, path,
				                  NULL);
			} else {
				prev_res = res;
				res = check_if_known(hashtable, dirent->d_name, name_len, path);
				/* HACK: this is ugly, but it's needed for avoiding that the
				 * recursion could wrongly return OK instead of NEW */
				if (res == OK) {
					res = prev_res;
				}
			}
		} else if (mode == S_IFDIR) {
			prev_res = res;
			res = parse_dir(hashtable, filename, first_time); // recursion step
			/* HACK: same HACK as for the file */
			if (res == OK) {
				res = prev_res;
			} else if (res == ERR) {
				break;
			}
		} else { // avoid symlink and other weird stuff...
			continue;
		}
	}

	closedir(dir);

	return res;
}

int set_download_dir(const char *path)
{
	memset(download.path, 0, sizeof(download.path));

	if (!path) {
		download.path[0] = '.';
		download.path[1] = '/';
		download.path[2] = '\0';
	} else {
		memcpy(download.path, path, strnlen(path, sizeof(download.path)));
	}

	slog_info(STDOUT_LEVEL, "New download directory: \"%s\"", download.path);
	PRINT_PEER;
	return 0;
}

bool shared_dir_is_set(void)
{
	return shared.is_set;
}

/*
 * List iterator for copying all the keys inside the array to be returned
 */
int key_copy_list_iterator(void *item, size_t idx, void *user)
{
	sha256_t *keys = (sha256_t *)user;
	hashtable_key_t *k = (hashtable_key_t *)item;

	memcpy(keys[idx], k->data, k->len);
	return GO_AHEAD;
}

sha256_t *retrieve_all_keys(uint32_t *num)
{
	sha256_t *keys = NULL;
	uint32_t n = 0;
	linked_list_t *k_list = NULL;

	if (!shared_dir_is_set()) { // there's nothing!
		return NULL;
	}

	n = (uint32_t)ht_count(shared.hashtable);

	if (n == 0) { // again, there's nothing to share
		return NULL;
	}

	slog_debug(FILE_LEVEL, "Retrieving all keys (%u)", n);
	k_list = ht_get_all_keys(shared.hashtable);
	if (!k_list) {
		slog_warn(FILE_LEVEL, "Unable to retrieve the keys");
		return NULL;
	}

	keys = malloc(sizeof(sha256_t) * n);
	if (!keys) {
		slog_error(FILE_LEVEL, "malloc. Error %d", errno);
		list_destroy(k_list);
		return NULL;
	}

	list_foreach_value(k_list, key_copy_list_iterator, keys);
	list_destroy(k_list);

	*num = n;

	return keys;
}

#define HT_ERROR -1
#define HT_DOESNT_EXIST 0
#define HT_EXISTS 1

bool key_exists(sha256_t key)
{
	int ret = 0;

	if (!shared_dir_is_set()) {
		return false;
	}

	ret = ht_exists(shared.hashtable, key, sizeof(sha256_t));
	switch (ret) {
		case HT_ERROR:
			slog_error(FILE_LEVEL, "ht_exists has returned -1");
		case HT_DOESNT_EXIST:
			return false;

		case HT_EXISTS:
			return true;

		default:
			slog_error(FILE_LEVEL, "%d is an unexpected return value from"
						  " ht_exists", ret);
			return false;
	}
}

#undef HT_ERROR
#undef HT_DOESNT_EXIST
#undef HT_EXISTS

size_t get_file_size(sha256_t key)
{
	int fd = 0;
	size_t size = 0;
	off_t off = 0;

	fd = get_file_desc(key, true, NULL);
	if (fd < 0) {
		return 0;
	}

	off = lseek(fd, 0, SEEK_END);
	if (off < 0) {
		slog_error(FILE_LEVEL, "lseek errno %d, strerror %s", errno, strerror(errno));
		close(fd);
		return 0;
	}

	close(fd);
	size = (size_t)off;
	return size;
}

int get_file_desc(sha256_t key, bool read, char filename[FSNP_NAME_MAX])
{
	int fd = 0;
	struct h_entry *entry = NULL;
	char path[PATH_MAX];

	if (read) {
		entry = ht_get(shared.hashtable, key, sizeof(sha256_t), NULL);
		if (!entry) {
			return -1;
		}

		snprintf(path, PATH_MAX, "%s/%s", entry->path, entry->name);
		fd = open(path, O_RDONLY);
	} else {
		snprintf(path, PATH_MAX, "%s/%s", download.path, filename);
		fd = open(path, O_CREAT | O_RDWR, 0644);
	}

	if (fd < 0) {
		slog_error(FILE_LEVEL, "Error while opening %s. errno %d, strerror: %s",
		           path, errno, strerror(errno));
		return -1;
	}

	return fd;
}

int create_download_file(char filename[FSNP_NAME_MAX])
{
	return get_file_desc(NULL, false, filename);
}

void close_download_file(int fd, char filename[256], sha256_t hash, bool del)
{
	int ret = 0;
	char path[PATH_MAX];

	close(fd);
	if (del) {
		snprintf(path, sizeof(char) * PATH_MAX, "%s/%s", download.path, filename);
		ret = remove(path);
		if (ret < 0) {
			slog_error(FILE_LEVEL, "Unable to delete file %s. Error %d,"
						  " strerror %s", path, errno, strerror(errno));
		}
	} else {
		add_file_to_table(download.hashtable, filename, strlen(filename) + 1,
		                  download.path, hash);
	}
}

struct search_delete_file_data {
	hashtable_t *table;
	int changes;
};

/*
 * Search along all the list if any file was deleted
 */
static int search_delete_file_iterator(void *item, size_t idx, void *user)
{
	hashtable_value_t *v = (hashtable_value_t *)item;
	struct h_entry *entry = (struct h_entry *)v->data;
	struct search_delete_file_data *d = (struct search_delete_file_data *)user;
	sha256_t key;
	char key_str[SHA256_STR_BYTES];

	UNUSED(idx);
	
	if (entry->found) {
		entry->found = false;
	} else {
		sha256(entry->name, entry->name_len, key);
		ht_delete(d->table, key, sizeof(key), NULL, NULL);
		stringify_hash(key_str, key);
		slog_info(FILE_LEVEL, "Deleting file corresponding to key %s", key_str);
		d->changes = NEW;
	}

	return GO_AHEAD;
}

/*
 * Update the file manager. If something changed returns true, otherwise false
 */
static bool update_file_manager(void)
{
	int changes = 0;
	linked_list_t *l = NULL;
	struct search_delete_file_data d;

	if (!shared_dir_is_set()) {
		return false;
	}

	slog_debug(FILE_LEVEL, "Looking for changes in the shared dir...");
	changes = parse_dir(shared.hashtable, shared.path, false);
	if (changes == ERR) {
		return false;
	}
	
	l = ht_get_all_values(shared.hashtable);
	if (!l) {
		return false;
	}

	d.changes = 0;
	d.table = shared.hashtable;
	list_foreach_value(l, search_delete_file_iterator, &d);
	list_destroy(l);
	if (changes == NEW || d.changes == NEW) {
		slog_debug(FILE_LEVEL, "Changes found");
		return true;
	} else {
		slog_debug(FILE_LEVEL, "Changes not found");
		return false;
	}
}

struct update_thr_data {
	pthread_mutex_t mtx;
	pthread_cond_t cond;
	bool run;
	bool changes;
};

static struct update_thr_data utd;

#define SEC_TO_SLEEP 15

/*
 * Entry point for the update thread. Every 30 seconds go through all the
 * entries in the shared_dir for checking if something has changed.
 */
static void update_thread(void *data)
{
	struct timespec to_sleep;
	struct timeval tod;
	int ret = 0;
	bool changes = false;

	UNUSED(data);

	to_sleep.tv_sec = SEC_TO_SLEEP;
	to_sleep.tv_nsec = 0;
	while (true) {
		gettimeofday(&tod, NULL);
		to_sleep.tv_sec = SEC_TO_SLEEP + tod.tv_sec;
		ret = pthread_mutex_lock(&utd.mtx);
		if (ret) {
			slog_error(FILE_LEVEL, "pthread_mutex_lock error %d", ret);
		}

		ret = pthread_cond_timedwait(&utd.cond, &utd.mtx, &to_sleep);
		if (ret != 0 && ret != ETIMEDOUT) {
			slog_fatal(FILE_LEVEL, "pthread_cond_timedwait returned EINVAL");
			break;
		}

		if (utd.run == false) {
			ret = pthread_mutex_unlock(&utd.mtx);
			if (ret) {
				slog_error(FILE_LEVEL, "pthread_mutex_unlock error %d", ret);
			}

			break;
		}

		changes = update_file_manager();
		/*
		 * If utd.changes is false is ok to set it to changes. If it's true
		 * no one checked the field before and it would be wrong set it to
		 * changes, since it could be false.
		 */
		if (!utd.changes) {
			utd.changes = changes;
		}

		ret = pthread_mutex_unlock(&utd.mtx);
		if (ret) {
			slog_error(FILE_LEVEL, "pthread_mutex_unlock error %d", ret);
		}
	}

	pthread_mutex_destroy(&utd.mtx);
	pthread_cond_destroy(&utd.cond);
}

/*
 * Routine for spawning the update thread
 */
static void launch_update_thread(bool first_launch)
{
	const char update_err[] = "Unable to start the update thread. This means"
	                          "that any file added after this point will not be"
	                          "shared";
	int ret = 0;

	if (first_launch && get_peer_sock() == 0) {
		utd.changes = false;
	} else {
		utd.changes = true;
	}

	utd.run = false;
	ret = pthread_mutex_init(&utd.mtx, NULL);
	if (ret) {
		slog_error(FILE_LEVEL, "Unable to initialize the mutex. Error %d", ret);
		slog_warn(STDOUT_LEVEL, "%s", update_err);
		PRINT_PEER;
		return;
	}

	ret = pthread_cond_init(&utd.cond, NULL);
	if (ret) {
		pthread_mutex_destroy(&utd.mtx);
		slog_error(FILE_LEVEL, "Unable to initialize the condition. Error %d",ret);
		slog_warn(STDOUT_LEVEL, "%s", update_err);
		PRINT_PEER;
		return;
	}

	ret = start_new_thread(update_thread, NULL, "update-thread");
	if (ret < 0) {
		slog_warn(STDOUT_LEVEL, "%s", update_err);
		PRINT_PEER;
		pthread_mutex_destroy(&utd.mtx);
		pthread_cond_destroy(&utd.cond);
		return;
	}

	utd.run = true; // if we get here everything went ok with the update thread
}

static void stop_update_thread(void)
{
	if (utd.run) {
		slog_info(FILE_LEVEL, "Telling to update_thread to stop");
		// don't care about errors here
		pthread_mutex_lock(&utd.mtx);
		utd.run = false;
		pthread_cond_signal(&utd.cond);
		pthread_mutex_unlock(&utd.mtx);
	}
}

bool check_for_updates(void)
{
	int ret = 0;
	bool changes = false;

	if (!utd.run) {
		return false;
	}

	ret = pthread_mutex_lock(&utd.mtx);
	if (ret) {
		slog_error(FILE_LEVEL, "pthread_mutex_lock error %d", ret);
		return false;
	}

	changes = utd.changes;
	utd.changes = false; // Avoid false positive in subsequents calls

	ret = pthread_mutex_unlock(&utd.mtx);
	if (ret) {
		slog_error(FILE_LEVEL, "pthread_mutex_unlock error %d", ret);
		return false;
	}

	return changes;
}

int set_shared_dir(const char *path)
{
	int ret = 0;
	static bool first_launch = true;

	if (!path) {
		return -1;
	}

	stop_update_thread();
	if (shared.is_set) {
		ht_clear(shared.hashtable);
	}

	strncpy(shared.path, path, PATH_MAX);
	slog_info(FILE_LEVEL, "Setting shared_dir to %s", path);
	ret = parse_dir(shared.hashtable, shared.path, true);
	if (ret < 0) {
		ht_clear(shared.hashtable);
		memset(shared.path, 0, sizeof(path));
		shared.is_set = false;
		slog_error(FILE_LEVEL, "Unable to parse shared_dir. shared_dir is unset"
		                       " now");
		return -1;
	}

	slog_info(STDOUT_LEVEL, "All the files were parsed. You're sharing %lu "
	                        "files.", ht_count(shared.hashtable));
	slog_info(STDOUT_LEVEL, "New shared directory: \"%s\"", shared.path);
	PRINT_PEER;
	launch_update_thread(first_launch);
	first_launch = false;
	shared.is_set = true;

	return 0;
}

void show_download_path(void)
{
	if (!download.is_set) {
		printf("The download path is not set.\n");
	} else {
		printf("You're downloading files in \"%s\".\n", download.path);
	}
}

int init_file_manager(void)
{
	shared.hashtable = ht_create(0, HASH_MAX_SIZE, free_callback);
	if (!shared.hashtable) {
		slog_error(FILE_LEVEL, "Unable to create shared.hashtable");
		pthread_mutex_destroy(&utd.mtx);
		return -1;
	}

	download.hashtable = ht_create(0, HASH_MAX_SIZE, free_callback);
	if (!download.hashtable) {
		slog_error(FILE_LEVEL, "Unable to create download.hashtable");
		pthread_mutex_destroy(&utd.mtx);
		ht_destroy(shared.hashtable);
		return -1;
	}

	memset(shared.path, 0, sizeof(shared.path));
	memset(download.path, 0, sizeof(download.path));

	shared.is_set = false;

	set_download_dir(".\0"); // set the standard download path
	download.is_set = true;

	slog_info(FILE_LEVEL, "init_file_manager initialized");
	return 0;
}

void close_file_manager(void)
{
	stop_update_thread();
	ht_destroy(shared.hashtable);
	ht_destroy(download.hashtable);
	slog_info(FILE_LEVEL, "file_manager closed");
}

#undef HASH_MAX_SIZE
#undef ERR
#undef OK
#undef NEW
#undef SEC_TO_SLEEP