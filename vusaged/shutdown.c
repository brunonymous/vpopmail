/*
   $Id: shutdown.c 1014 2011-02-03 16:04:37Z volz0r $

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
#include <pthread.h>
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include "queue.h"
#include "shutdown.h"

/*
   Write operations on this variable should be atomic on
   all architectures
*/

char shutdown_flag = 0;

static pthread_mutex_t m_shutdown = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t c_shutdown = PTHREAD_COND_INITIALIZER;

/*
   Initialize
*/

int shutdown_init(void)
{
   int ret = 0;

   shutdown_flag = 0;

   ret = pthread_mutex_init(&m_shutdown, NULL);
   if (ret != 0) {
	  fprintf(stderr, "shutdown_init: pthread_mutex_init failed\n");
	  return 0;
   }

   ret = pthread_cond_init(&c_shutdown, NULL);
   if (ret != 0) {
	  fprintf(stderr, "shutdown_init: pthread_cond_init failed\n");
	  return 0;
   }

   return 1;
}

/*
   Wait for a period of time in seconds on the shutdown condition
   This function is mainly used for threads that need to go to sleep
   for a long period of time that only ever need to wake on shutdown.

   Returns 1 if condition was triggered
*/

int shutdown_wait(int seconds)
{
   int ret = 0;
   struct timespec ts;

#ifdef ASSERT_DEBUG
   assert(seconds >= 0);
#endif

   if (shutdown_flag)
	  return 1;

   ts.tv_sec = (time(NULL) + seconds);
   ts.tv_nsec = 0;

   pthread_mutex_lock(&m_shutdown);
   ret = pthread_cond_timedwait(&c_shutdown, &m_shutdown, &ts);
   pthread_mutex_unlock(&m_shutdown);

   if (ret != 0)
	  return 0;

   return 1;
}

/*
   Trigger shutdown condition
*/

int shutdown_trigger(void)
{
   if (shutdown_flag)
	  return 1;

   printf("<shutdown>\n");

   pthread_mutex_lock(&m_shutdown);
   shutdown_flag = 1;

   /*
	  Flag the condition
   */

   pthread_cond_broadcast(&c_shutdown);
   pthread_mutex_unlock(&m_shutdown);

   queue_wake();
   return 1;
}

