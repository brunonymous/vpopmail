/*
   $Id: user.h 1014 2011-02-03 16:04:37Z volz0r $

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

#ifndef __USER_H_
   #define __USER_H_

#include "storage.h"
#include "domain.h"
#include "userstore.h"

/*
   Maximum length of a username
*/

#define USER_MAX_USERNAME 512

/*
   User structure
*/

typedef struct __user_ {
   char *user,
                *home;                          // Home directory of user

   domain_t *domain;
   userstore_t *userstore;
   struct __user_ *next, *prev;
} user_t;

user_t *user_get(const char *);
storage_t user_usage(user_t *);
storage_t user_get_usage(const char *);
int user_get_use(const char *, storage_t *, storage_t *);
int user_poll(user_t *);
user_t *user_get_userlist(void);
int user_verify(user_t *);

#endif
