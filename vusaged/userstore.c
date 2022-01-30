/*
   $Id: userstore.c 1014 2011-02-03 16:04:37Z volz0r $

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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include "path.h"
#include "../storage.h"
#include "directory.h"
#include "list.h"
#include "conf.h"
#include "userstore.h"

/*
   Factor by which to age userstores which take a long time to update
*/

#define USERSTORE_AGE 1

static int userstore_age = USERSTORE_AGE;

static int userstore_find_directories(userstore_t *);
static int userstore_monitors_directory(userstore_t *, const char *);
static void userstore_free_directory(userstore_t *);

/*
   Configure userstore system
*/

int userstore_init(config_t *config)
{
   char *str = NULL;

#ifdef ASSERT_DEBUG
   assert(config != NULL);
#endif

   userstore_age = USERSTORE_AGE;

   str = config_fetch_by_name(config, "Polling", "Age Factor");
   if (str) {
	  userstore_age = atoi(str);

	  if (userstore_age == -1) {
		 fprintf(stderr, "userstore_init: invalid configuration: Polling::Age Factor: %s\n", str);
		 return 0;
	  }
   }

   return 1;
}

/*
   Load information on a single user's total usage
*/

userstore_t *userstore_load(const char *path)
{
   userstore_t *u = NULL;
   directory_t **dlist = NULL;
   int items = 0, i = 0, ret = 0;

#ifdef ASSERT_DEBUG
   assert(path != NULL);
   assert(*path);
#endif

   /*
	  Allocate structure
   */

   u = malloc(sizeof(userstore_t));
   if (u == NULL) {
	  fprintf(stderr, "userstore_load: malloc failed\n");
	  return NULL;
   }

   memset(u, 0, sizeof(userstore_t));

   /*
	  Save path
   */

   u->path = strdup(path);
   if (u->path == NULL) {
	  free(u);

	  for (i = 0; i < items; i++)
		 directory_free(dlist[i]);

	  list_free((void **)dlist, &items);
	  fprintf(stderr, "userstore_load: strdup failed\n");
	  return NULL;
   }

   /*
	  Poll to initialize userstore contents
   */

   ret = userstore_poll(u);
   if (!ret) {
	  userstore_free(u);
	  return NULL;
   }

   /*
	  Set last updated time
   */

   u->last_updated = time(NULL);
   return u;
}

/*
   Deallocate all parts of a userstore structure
*/

void userstore_free(userstore_t *u)
{
#ifdef ASSERT_DEBUG
   assert(u != NULL);
#endif

   if (u->path)
	  free(u->path);

   if (u->directory)
	  userstore_free_directory(u);

   pthread_mutex_destroy(&u->m_usage);
   free(u);
}

/*
   Update userstore structure
*/

int userstore_poll(userstore_t *u)
{
   int i = 0, ret = 0;
   storage_t usage = 0, count = 0;
   struct stat st;
   time_t tstart = 0, tend = 0;

#ifdef ASSERT_DEBUG
   assert(u != NULL);
#endif

   /*
	  un-Age the userstore entry
   */

   if (u->time_taken) {
#ifdef USERSTORE_DEBUG
	  printf("userstore_poll: %p:%s is still %lu seconds old\n", u, u->path, u->time_taken);
#endif
	  u->time_taken--;

	  return 1;
   }

   /*
	  Get start time
   */

   tstart = time(NULL);

   /*
	  Find modification time of root directory
   */

   memset(&st, 0, sizeof(st));
   ret = stat(u->path, &st);
   if (ret == -1) {
	  if (errno != ENOENT)
		 fprintf(stderr, "userstore_poll: stat(%s) failed: %d\n", u->path, errno);

	  /*
		 Lost their root directory
	  */

	  userstore_free_directory(u);
	  return 0;
   }
   
#ifdef USERSTORE_DEBUG
   printf("userstore_poll: %s: %lu < %lu\n",
		 u->path,
		 u->st.st_mtime,
		 st.st_mtime);
#endif

   /*
	  Look for added/removed directories if modification time
	  on root directory has changed
   */

   if (u->st.st_mtime < st.st_mtime) {
#ifdef USERSTORE_DEBUG
	  printf("userstore_poll: %s has changed; looking for folder changes...\n", u->path);
#endif

	  /*
		 Save current modification time
	  */

	  memcpy(&u->st, &st, sizeof(struct stat));

	  /*
		 Look for folders
	  */

	  ret = userstore_find_directories(u);
	  if (!ret) {
		 fprintf(stderr, "userstore_poll: userstore_find_directories failed\n");
		 return 0;
	  }
   }

   /*
	  Update known directories
   */

   usage = 0;
   count = 0;

   for (i = 0; i < u->num_directories;) {
#ifdef ASSERT_DEBUG
	  assert(u->directory[i] != NULL);
#endif
	  ret = directory_poll(u->directory[i]);
	  if (!ret) {
#ifdef USERSTORE_DEBUG
		 printf("userstore_poll: Lost folder: %s\n", u->directory[i]->directory);
#endif
		 u->directory = (directory_t **)list_remove((void **)(u->directory), &(u->num_directories), u->directory[i]);
		 continue;
	  }

	  usage += u->directory[i]->usage;
	  count += u->directory[i]->count;
	  i++;
   }

   /*
	  Update usage
   */

   pthread_mutex_lock(&u->m_usage);
   u->usage = usage;
   u->count = count;
   pthread_mutex_unlock(&u->m_usage);

   u->last_updated = time(NULL);

   /*
	  Age the userstore entry
   */

   tend = time(NULL);
   u->time_taken = ((tend - tstart) * userstore_age);

#ifdef ASSERT_DEBUG
   assert(u->time_taken >= 0);
#endif

#ifdef USERSTORE_DEBUG
   if (u->time_taken)
	  printf("userstore_poll: aged %p:%s by %lu seconds\n", u, u->path, u->time_taken);
#endif

   return 1;
}

/*
   Return usage
*/

storage_t userstore_usage(userstore_t *u)
{
   storage_t usage = 0;

#ifdef ASSERT_DEBUG
   assert(u != NULL);
#endif

   pthread_mutex_lock(&u->m_usage);
   usage = u->usage;
   pthread_mutex_unlock(&u->m_usage);

   return usage;
}

/*
   Return count
*/

storage_t userstore_count(userstore_t *u)
{
   storage_t count = 0;

#ifdef ASSERT_DEBUG
   assert(u != NULL);
#endif

   pthread_mutex_lock(&u->m_usage);
   count = u->count;
   pthread_mutex_unlock(&u->m_usage);

   return count;
}

/*
   Return both usage and count
*/

void userstore_use(userstore_t *u, storage_t *usage, storage_t *count)
{
#ifdef ASSERT_DEBUG
   assert(u != NULL);
#endif

   if ((usage == NULL) || (count == NULL))
	  return;

   pthread_mutex_lock(&u->m_usage);

   *usage = u->usage;
   *count = u->count;

   pthread_mutex_unlock(&u->m_usage);
}

/*
   Look in a directory and monitor any sub-directories that we're interested in
*/

static int userstore_find_directories(userstore_t *u)
{
   struct stat st;
   int ret = 0, uret = 0;
   DIR *dir = NULL;
   char b[PATH_MAX] = { 0 };
   directory_t *d = NULL;
   struct dirent *e = NULL;

#ifdef ASSERT_DEBUG
   assert(u != NULL);
   assert(u->path != NULL);
   assert(*(u->path) != '\0');
#endif

   dir = opendir(u->path);
   if (dir == NULL) {
	  fprintf(stderr, "userstore_load: opendir: %s: error %d\n", u->path, errno);
	  return 0;
   }

   for (e = readdir(dir); e; e = readdir(dir)) {
	  if (!(strcmp(e->d_name, "..")))
		 continue;

	  /*
		 Look for 'new' subdirectory
	  */

	  memset(b, 0, sizeof(b));
	  snprintf(b, sizeof(b), "%s/%s/new", u->path, e->d_name);

	  /*
		 Check if we already know about this directory
	  */

	  uret = userstore_monitors_directory(u, b);
	  if (uret)
		 continue;

	  /*
		 If not, stat()
	  */

	  memset(&st, 0, sizeof(st));
	  ret = stat(b, &st);
	  if (ret == -1) {
		 if ((errno != ENOENT) && (errno != ENOTDIR)) {
			fprintf(stderr, "userstore_find_directories: stat: %s: error %d\n", b, errno);
			closedir(dir);
			return 0;
		 }

		 /*
			File disappeared
		 */

		 continue;
	  }

#ifdef USERSTORE_DEBUG
	  printf("userstore_find_directories: Found new folder: %s\n", b);
#endif

	  /*
		 ..and load
	  */

	  d = directory_load(b);

	  /*
		 ..and add to the list
	  */

	  if (d)
		 u->directory = (directory_t **)list_add((void **)u->directory, &(u->num_directories), d);
#ifdef USERSTORE_DEBUG
	  else
		 fprintf(stderr, "userstore_find_directories: directory_load(%s) failed\n", b);
#endif

	  /*
		 Ditto for 'cur' subdirectory
	  */

	  memset(b, 0, sizeof(b));
	  snprintf(b, sizeof(b), "%s/%s/cur", u->path, e->d_name);

	  uret = userstore_monitors_directory(u, b);
	  if (uret)
		 continue;

	  memset(&st, 0, sizeof(st));
	  ret = stat(b, &st);
	  if (ret == -1) {
		 if ((errno != ENOENT) && (errno != ENOTDIR)) {
			fprintf(stderr, "userstore_find_directories: stat: %s: error %d\n", b, errno);
			closedir(dir);
			return 0;
		 }

		 continue;
	  }

#ifdef USERSTORE_DEBUG
	  printf("userstore_find_directories: Found new folder: %s\n", b);
#endif
	  
	  d = directory_load(b);
	  if (d)
		 u->directory = (directory_t **)list_add((void **)u->directory, &(u->num_directories), d);
#ifdef USERSTORE_DEBUG
	  else
		 fprintf(stderr, "userstore_find_directories: directory_load(%s) failed\n", b);
#endif
   }

   closedir(dir);
   return 1;
}

/*
   Returns true if a userstore monitors directory
*/

static int userstore_monitors_directory(userstore_t *u, const char *dir)
{
   int i = 0;

#ifdef ASSERT_DEBUG
   assert(u != NULL);
   assert(dir != NULL);
   assert(*dir);

   if (u->directory == NULL)
	  assert(u->num_directories == 0);
   else
	  assert(u->num_directories >= 1);
#endif

   /*
	  No directories loaded yet
   */

   if (u->directory == NULL) {
	  return 0;
   }

   for (i = 0; i < u->num_directories; i++) {
#ifdef ASSERT_DEBUG
	  assert(u->directory[i] != NULL);
	  assert(u->directory[i]->directory != NULL);
	  assert(*(u->directory[i]->directory) != '\0');
#endif

	  if (!(strcasecmp(u->directory[i]->directory, dir)))
		 return 1;
   }

   return 0;
}

/*
   Deallocate all directory structures in a userstore
*/

static void userstore_free_directory(userstore_t *u)
{
   int i = 0;

#ifdef ASSERT_DEBUG
   assert(u != NULL);
#endif

   if (u->directory == NULL)
	  return;

   for (i = 0; i < u->num_directories; i++)
	  directory_free(u->directory[i]);

   list_free((void **)u->directory, &u->num_directories);

   u->directory = NULL;
   u->num_directories = 0;

   pthread_mutex_lock(&u->m_usage);
   u->usage = 0;
   u->count = 0;
   pthread_mutex_unlock(&u->m_usage);
}
