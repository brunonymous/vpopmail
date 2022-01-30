/*
   $Id: directory.h 1014 2011-02-03 16:04:37Z volz0r $

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

#ifndef __DIRECTORY_H_
   #define __DIRECTORY_H_

#include <time.h>
#include <sys/stat.h>
#include "conf.h"
#include "storage.h"

/*
   A single directory structure
*/

typedef struct __directory_ {
   char *directory;
   time_t last_update;				// Last update time
   struct stat st;					// Last update stat call
   storage_t usage,					// Current cached usage
			 count;					// Current cached number of entries in directory
} directory_t;

int directory_init(config_t *);
directory_t *directory_load(const char *);
void directory_free(directory_t *);
int directory_exists(const char *, const char *);
int directory_poll(directory_t *);

#endif
