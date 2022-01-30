/*
   $Id: userstore.h 1014 2011-02-03 16:04:37Z volz0r $

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

#ifndef __USERSTORE_H_
   #define __USERSTORE_H_

#include "storage.h"
#include "directory.h"
#include "conf.h"
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*
   Total sum of a user's disk usage under their primary Maildir path
*/

typedef struct __userstore_ {
   char *path;
   struct stat st;

   time_t last_updated,
		  time_taken;

   int num_directories;
   directory_t **directory;

   pthread_mutex_t m_usage;
   storage_t usage,
			 count;
} userstore_t;

int userstore_init(config_t *);
userstore_t *userstore_load(const char *);
void userstore_free(userstore_t *);
int userstore_poll(userstore_t *);
storage_t userstore_usage(userstore_t *);
storage_t userstore_count(userstore_t *);
void userstore_use(userstore_t *, storage_t *, storage_t *);

#endif
