/*
   $Id: directory.c 1014 2011-02-03 16:04:37Z volz0r $

   * Copyright (C) 2009 Inter7 Internet Technologies, Inc.
   *
   * This program is free software; you can redistribute it and/or modify
   * it under the terms of the GNU General Public License as published by
   * the Free Software Foundation; either version 2 of the License, or
   * (at your option) any later version.
   *
   * This program is distributed in the hope that it will be useful,
   * but WITHOUT ANY WARRANTY; without even the implied warranty of
   * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   * GNU General Public License for more details.
   *
   * You should have received a copy of the GNU General Public License
   * along with this program; if not, write to the Free Software
   * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include "conf.h"
#include "path.h"
#include "../storage.h"
#include "directory.h"

/*
   Minimum time in which two directory polls may be done in seconds
*/

#define DIRECTORY_MINIMUM_POLL_TIME 15

/*
   Count directory entry size
*/

#define DIRECTORY_COUNT_ENTRY_SIZE 0

/*
   Use Maildir++ format?
*/

#define DIRECTORY_USE_MAILDIRPP_FORMAT 1

static int directory_use_maildirpp_format = DIRECTORY_USE_MAILDIRPP_FORMAT;
static int directory_count_entry_size = DIRECTORY_COUNT_ENTRY_SIZE;
int directory_minimum_poll_time = DIRECTORY_MINIMUM_POLL_TIME;

static directory_t *directory_alloc(const char *);
static inline storage_t directory_filesize(const char *, int fnlen);

/*
   Initialize directory polling system
*/

int directory_init(config_t *config)
{
   int pt = 0;
   char *str = NULL;

#ifdef ASSERT_DEBUG
   assert(config != NULL);
#endif

   str = config_fetch_by_name(config, "Polling", "Use Maildir++ format");
   if (str) {
	  if (!(*str)) {
		 fprintf(stderr, "directory_init: Polling::Use Maildir++ format: invalid configuration\n");
		 return 0;
	  }

	  if (!(strcasecmp(str, "True")))
		 directory_use_maildirpp_format = 1;

	  else if (!(strcasecmp(str, "False")))
		 directory_use_maildirpp_format = 0;

	  else {
		 fprintf(stderr, "directory_init: Polling::Use Maildir++ format: invalid configuration: %s\n", str);
		 return 0;
	  }
   }

   str = config_fetch_by_name(config, "Polling", "Directory minimum poll time");
   if (str) {
	  if (!(*str)) {
		 fprintf(stderr, "directory_init: Polling::Directory minimum poll time: invalid configuration\n");
		 return 0;
	  }

	  pt = atoi(str);
	  if (pt == -1) {
		 fprintf(stderr, "directory_init: Polling::Directory minimum poll time: invalid configuration: %s\n", str);
		 return 0;
	  }

	  directory_minimum_poll_time = pt;
   }

   str = config_fetch_by_name(config, "Polling", "Count directory entry size");
   if (str) {
	  if (!(*str)) {
		 fprintf(stderr, "directory_init: Polling::Count directory entry size: invalid configuration\n");
		 return 0;
	  }

	  if (!(strcasecmp(str, "True")))
		 directory_count_entry_size = 1;

	  else if (!(strcasecmp(str, "False")))
		 directory_count_entry_size = 0;

	  else {
		 fprintf(stderr, "directory_init: Polling::Count directory entry size: invalid configuration\n");
		 return 0;
	  }
   }

   return 1;
}

/*
   Allocate and fill a directory entry
*/

directory_t *directory_load(const char *path)
{
   int ret = 0;
   directory_t *d = NULL;

#ifdef ASSERT_DEBUG
   assert(path != NULL);
   assert(*path == '/');
#endif

   /*
	  Check if the directory exists
   */

   ret = directory_exists(path, NULL);
   if (!ret)
	  return NULL;

   /*
	  Allocate
   */

   d = directory_alloc(path);
   if (d == NULL) {
	  fprintf(stderr, "directory_load: directory_alloc failed\n");
	  return NULL;
   }

   /*
	  Poll
   */

   ret = directory_poll(d);
   if (!ret)
	  fprintf(stderr, "directory_load: directory_poll failed\n");
#ifdef DIRECTORY_DEBUG
   else
	  printf("directory: %s: loaded\n", path);
#endif

   return d;
}

/*
   Deallocate a directory structure
*/

void directory_free(directory_t *d)
{
#ifdef ASSERT_DEBUG
   assert(d != NULL);
#endif

   if (d->directory)
	  free(d->directory);

   free(d);
}

/*
   Determine if a directory, and optionally a subdirectory
   of that directory, exist
*/

int directory_exists(const char *path, const char *subdir)
{
   int ret = 0;
   struct stat st;
   char b[PATH_MAX] = { 0 };

#ifdef ASSERT_DEBUG
   assert(path != NULL);
   assert(*path);

   if (subdir)
	  assert(*subdir);
#endif

   /*
	  Initial path
   */

   memset(&st, 0, sizeof(st));

   ret = stat(path, &st);
   if (ret == -1) {
#ifdef DIRECTORY_DEBUG
	  if (errno != ENOENT)
		 fprintf(stderr, "directory_exists: %s: error: %d\n", path, errno);
#endif

	  return 0;
   }

   if (!(S_ISDIR(st.st_mode))) {
	  fprintf(stderr, "directory_exists: %s: not a directory\n", path);
	  return 0;
   }

   if (subdir == NULL)
	  return 1;

   /*
	  Subdirectory
   */

   memset(b, 0, sizeof(b));
   snprintf(b, sizeof(b), "%s/%s", path, subdir);

   memset(&st, 0, sizeof(st));

   ret = stat(b, &st);
   if (ret == -1) {
	  if (errno != ENOENT)
		 fprintf(stderr, "directory_exists: %s: error: %d\n", b, errno);

	  return 0;
   }

   if (!(S_ISDIR(st.st_mode))) {
	  fprintf(stderr, "directory_exists: %s: not a directory\n", b);
	  return 0;
   }

   return 1;
}

/*
   Poll a directory for changes
*/

int directory_poll(directory_t *d)
{
   int ret = 0;
   DIR *dir = NULL;
   struct stat st;
   struct dirent *e = NULL;
   char b[PATH_MAX] = { 0 };
   storage_t storage = 0, size = 0, count = 0;

#ifdef ASSERT_DEBUG
   assert(d != NULL);
#endif

   /*
	  No matter what, never poll faster than this
   */

   if ((time(NULL) - d->last_update) <= directory_minimum_poll_time) {
#ifdef DIRECTORY_DEBUG
	  printf("directory: %s: too soon\n", d->directory);
#endif
	  return 1;
   }

#ifdef DIRECTORY_DEBUG
   printf("directory: %p: %s: polling (now = %lu, last = %lu)\n",
		 d, d->directory, time(NULL), d->last_update);
#endif

   /*
	  Update last time polled
   */

   d->last_update = time(NULL);

   ret = stat(d->directory, &st);
   if (ret == -1) {
#ifdef DIRECTORY_DEBUG
	  fprintf(stderr, "directory: stat: %s: error: %d\n", d->directory, errno);
#endif
	  return 0;
   }

   /*
	  Only run through directory contents if directory was modified since
	  last poll
   */

   if ((d->st.st_mtime) && (d->st.st_mtime >= st.st_mtime)) {
#ifdef DIRECTORY_DEBUG
	  printf("directory: %s: no changes\n", d->directory);
#endif
	  return 1;
   }

   /*
	  Run through directory calculating usage
   */

   storage = 0;
   count = 0;

   dir = opendir(d->directory);

#if 0
   if (dir == NULL) {
	  fprintf(stderr, "directory: %s: opendir failed\n", d->directory);

	  /*
		 Return 1 here in case opendir() failure is a temporary error
		 The stat() call above should be the only way to detect a removed
		 folder
	  */

	  return 1;
   }
#endif

   if (dir) {
	  for (e = readdir(dir); e; e = readdir(dir)) {
		 /*
			Hidden files, current directory, and parent directory are not calculated
		 */

		 if (*(e->d_name) == '.') {
			if (!directory_count_entry_size)
			   continue;

			else if (*((e->d_name) + 1) != '\0')
			   continue;
		 }

		 /*
			Form temporary path and determine it's size
		 */

		 memset(b, 0, sizeof(b));
		 ret = snprintf(b, sizeof(b), "%s/%s", d->directory, e->d_name);

		 size = directory_filesize(b, ret);
		 if (size == -1) {
			fprintf(stderr, "directory: %s: directory_filesize failed\n", b);
			continue;
		 }

		 storage += size;
		 count++;
	  }

	  closedir(dir);
   }

   /*
	  Update directory
   */

   memcpy(&d->st, &st, sizeof(struct stat));

   d->usage = storage;
   d->count = count;

#ifdef DIRECTORY_DEBUG
   printf("directory: %s: updated\n", d->directory);
#endif
   return 1;
}

/*
   Allocate a directory structure
*/

directory_t *directory_alloc(const char *path)
{
   char *str = NULL;
   directory_t *d = NULL;

#ifdef ASSERT_DEBUG
   assert(path != NULL);
   assert(*path);
#endif

   str = malloc(strlen(path) + 1);
   if (str == NULL) {
	  fprintf(stderr, "directory_alloc: malloc failed\n");
	  return NULL;
   }

   memset(str, 0, (strlen(path) + 1));
   memcpy(str, path, strlen(path));

   d = malloc(sizeof(directory_t));
   if (d == NULL) {
	  free(str);
	  fprintf(stderr, "directory_alloc: malloc failed\n");
	  return NULL;
   }

   memset(d, 0, sizeof(directory_t));

   d->directory = str;
   return d;
}

/*
   Return a file's size on the disk
   Supports Maildir++ format
*/

static inline storage_t directory_filesize(const char *file, int fnlen)
{
   int ret = 0;
   struct stat st;
   storage_t size = 0;
   const char *h = NULL, *t = NULL;

#ifdef ASSERT_DEBUG
   assert(file != NULL);
   assert(*file);
   assert(fnlen > 0);
#endif
   
   /*
	  Find S=VALUE within filename
   */

   if (directory_use_maildirpp_format) {
	  /*
		 Separate comma values
	  */

	  for (t = h = (file + fnlen); h > file; h--) {
		 if (*h == ',') {
			/*
			   Not interested in empty or non-assignment formats
			*/

			if (t <= h)
			   continue;

			if ((!(*(h + 1))) || (*(h + 1) == ',')) {
			   t = (h - 1);
			   continue;
			}

			/*
			   Only interested in S=VALUE format
			*/

			if ((!(*(h + 1) == 'S')) || (!(*(h + 2) == '='))) {
			   t = (h - 1);
			   continue;
			}

			/*
			   Convert to integer
			*/

			size = strtoll(h + 3, NULL, 10);
			if (size == LLONG_MAX) {
			   fprintf(stderr, "directory_filesize: syntax error in Maildir++ filename: %s\n", file);
			   break;
			}

			return size;
		 }
	  }
   }

   /*
	  Use stat() to determine file size
   */

   memset(&st, 0, sizeof(st));
   ret = stat(file, &st);
   if (ret == -1) {
	  if (errno != ENOENT) {
		 fprintf(stderr, "directory_filesize: %s: stat failed: %d\n", file, errno);
		 return -1;
	  }

	  /*
		 File disappeared or broken symlink
	  */

	  return 0;
   }

   return (storage_t)st.st_size;
}
