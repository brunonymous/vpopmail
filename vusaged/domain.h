/*
   $Id: domain.h 1014 2011-02-03 16:04:37Z volz0r $

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

#ifndef __DOMAIN_H_
   #define __DOMAIN_H_

#include <pthread.h>
#include "storage.h"

/*
   Maximum length of a domain name
*/

#define DOMAIN_MAX_DOMAIN 512

/*
   Domain structure
*/

typedef struct __domain_ {
   char *domain;

   storage_t usage,
			 count;
   pthread_mutex_t m_usage;
} domain_t;

domain_t *domain_load(const char *);
void domain_free(domain_t *);
domain_t *domain_get(const char *);
storage_t domain_usage(domain_t *);
storage_t domain_get_usage(const char *);
int domain_get_use(const char *, storage_t *, storage_t *);
int domain_update(domain_t *, storage_t, storage_t, storage_t, storage_t);

#endif
