/*
   $Id: queue.c 1014 2011-02-03 16:04:37Z volz0r $

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
#include <unistd.h>
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include <pthread.h>
#include <vpopmail.h>
#include <vauth.h>
#include "conf.h"
#include "domain.h"
#include "userstore.h"
#include "user.h"
#include "shutdown.h"
#include "queue.h"

extern char shutdown_flag;
extern int directory_minimum_poll_time;

/*
   Queue structure
*/

typedef struct __queue_ {
   user_t *user;
   struct __queue_ *next;
} wqueue_t;

/*
   New user queue structure
*/

typedef struct __newuser_ {
   char *email;
   struct __newuser_ *next;
} newuser_t;

static int queue_workers = 0;
static pthread_t **threads = NULL, controller;
static wqueue_t *queue = NULL;
static newuser_t *newusers = NULL;
static int queue_max_size = 0, queue_size = 0, queue_proc = 0;
static pthread_cond_t c_queue = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t m_queue = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t m_newusers = PTHREAD_MUTEX_INITIALIZER;

static void *queue_controller(void *);
static void *queue_worker(void *);
static inline wqueue_t *queue_pop(void);
static inline int queue_lock(void);
static inline int queue_unlock(void);
static inline int queue_spin(int);
static inline void queue_free(wqueue_t *);

/*
   Initialize update queue
*/

int queue_init(config_t *config)
{
   int i = 0, ret = 0;
   char *str = NULL;

#ifdef ASSERT_DEBUG
   assert(config != NULL);
#endif

   /*
	  Initialize
   */

   queue_size = 0;
   queue_workers = 0;
   queue_max_size = -1;
   queue_proc = 0;
   queue = NULL;

   ret = pthread_mutex_init(&m_queue, NULL);
   if (ret != 0) {
	  fprintf(stderr, "queue_init: pthread_mutex_init failed\n");
	  return 0;
   }

   ret = pthread_cond_init(&c_queue, NULL);
   if (ret != 0) {
	  fprintf(stderr, "queue_init: pthread_cond_init failed\n");
	  return 0;
   }

   ret = pthread_mutex_init(&m_newusers, NULL);
   if (ret != 0) {
	  fprintf(stderr, "queue_init: pthread_mutex_init failed\n");
	  return 0;
   }

   /*
	  Load configurations
   */

   str = config_fetch_by_name(config, "Queue", "Workers");
   if (str == NULL)
	  return 1;

   queue_workers = atoi(str);
   if ((queue_workers == -1) || (queue_workers < 0)) {
	  fprintf(stderr, "queue_init: Queue::Workers: invalid configuration: %s\n", str);
	  return 0;
   }

   str = config_fetch_by_name(config, "Queue", "Max queue size");
   if ((str) && (*str))
	  queue_max_size = atoi(str);

   if ((queue_max_size == -1) || (queue_max_size <= 0)) {
	  fprintf(stderr, "queue_init: Queue::Max Queue Size: invalid configuration: %s\n", str);
	  return 0;
   }

   /*
	  Allocate thread array and begin workers
   */

   threads = malloc(sizeof(pthread_t *) * queue_workers);
   if (threads == NULL) {
	  fprintf(stderr, "queue_init: malloc failed\n");
	  return 0;
   }

   for (i = 0; i < queue_workers; i++) {
	  threads[i] = malloc(sizeof(pthread_t));
	  if (threads[i] == NULL) {
		 fprintf(stderr, "queue_init: malloc failed\n");
		 return 0;
	  }

	  memset(threads[i], 0, sizeof(pthread_t));

	  /*
		 Start worker
	  */

	  ret = pthread_create(threads[i], NULL, queue_worker, threads[i]);
	  if (ret != 0) {
		 fprintf(stderr, "queue_init: pthread_create failed\n");
		 return 0;
	  }
   }

   /*
	  Start controller thread
   */

   ret = pthread_create(&controller, NULL, queue_controller, &controller);
   if (ret != 0) {
	  fprintf(stderr, "queue_init: pthread_create failed\n");
	  return 0;
   }

#ifdef QUEUE_DEBUG
   printf("queue: started %d workers (queue size = %d)\n", queue_workers, queue_max_size);
#endif
   return 1;
}

/*
   Wait for workers to shut down
*/

int queue_shutdown(void)
{
   int i = 0, ret = 0;

   ret = pthread_join(controller, NULL);
   if (ret != 0)
	  fprintf(stderr, "queue: warning: pthread_join failed\n");

   for (i = 0; i < queue_workers; i++) {
	  ret = pthread_join((pthread_t)(*threads[i]), NULL);
	  if (ret != 0)
		 fprintf(stderr, "queue: warning: pthread_join failed\n");

	  free(threads[i]);
   }

   free(threads);
   threads = NULL;

   pthread_mutex_destroy(&m_queue);
   pthread_cond_destroy(&c_queue);

#ifdef QUEUE_DEBUG
   printf("queue: %d workers shut down\n", queue_workers);
#endif
   return 1;
}

/*
   Add an item to the queue
   Assumes queue is locked
*/

int queue_push(user_t *user)
{
   int ret = 0;
   wqueue_t *q = NULL;

#ifdef ASSERT_DEBUG
   assert(user != NULL);
   assert(user->user != NULL);
   assert(user->domain != NULL);
   assert(user->domain->domain != NULL);
#endif

   /*
	  Allocate new queue structure
   */

   q = malloc(sizeof(wqueue_t));
   if (q == NULL) {
	  fprintf(stderr, "queue_add: malloc failed\n");
	  return 0;
   }

   /*
	  Fill values
   */

   memset(q, 0, sizeof(wqueue_t));
   q->user = user;

   /*
	  Add to linked list
   */

   q->next = queue;
   queue = q;

   queue_size++;

   /*
	  Wake workers
   */

   ret = pthread_cond_signal(&c_queue);
   if (ret != 0)
	  fprintf(stderr, "queue_add: pthread_cond_signal failed\n");

   return 1;
}

/*
   Remove top of queue
   Assumes queue is locked
*/

wqueue_t *queue_pop(void)
{
   wqueue_t *q = NULL;

#ifdef ASSERT_DEBUG
   assert(queue != NULL);
   assert(queue_size > 0);
#endif

   /*
	  Update linked list
   */

   q = queue;
   queue = queue->next;

   /*
	  Update queue size
   */

   queue_size--;
   return q;
}

/*
   Wake up all workers
*/

void queue_wake(void)
{
   queue_lock();
   pthread_cond_broadcast(&c_queue);
   queue_unlock();
}

/*
   Add address to possible new user queue
*/

int queue_check_newuser(const char *email)
{
   char *em = NULL;
   newuser_t *n = NULL;

   /*
	  Copy address
   */

   em = strdup(email);
   if (em == NULL) {
	  fprintf(stderr, "queue_check_newuser: strdup failed\n");
	  return 0;
   }

   /*
	  Allocate linked list structure
   */

   n = malloc(sizeof(newuser_t));
   if (n == NULL) {
	  fprintf(stderr, "queue_check_newuser: malloc failed\n");
	  return 0;
   }

   n->email = em;

   /*
	  Add to list
   */
   
   pthread_mutex_lock(&m_newusers);

   n->next = newusers;
   newusers = n;

   pthread_mutex_unlock(&m_newusers);
   return 1;
}

/*
   Controller function
*/

static void *queue_controller(void *self)
{
   int ret = 0;
   time_t last = 0, diff = 0;
   user_t *u = NULL, *userlist = NULL;
   struct vqpasswd *vpw = NULL;
   domain_entry *e = NULL;
   char b[USER_MAX_USERNAME] = { 0 };
   newuser_t *nu = NULL, *no = NULL;

   e = NULL;

   printf("controller: stage one\n");

   /*
	  Stage one: Run through the entire list of users and domains
	             rather hastily
   */

   while(1) {
	  if (shutdown_flag)
		 break;

	  /*
		 Fill the queue with work
	  */

	  while(1) {
		 if (shutdown_flag)
			break;

		 queue_lock();

		 if (queue_size >= queue_max_size) {
			queue_unlock();
			break;
		 }

		 /*
			Next user
		 */
	  
		 if (e) {
			vpw = vauth_getall(e->realdomain, 0, 1);
#ifdef QUEUE_DEBUG
			if (vpw)
			   printf("controller: next %s@%s\n", vpw->pw_name, e->realdomain);
			else
			   printf("controller: finished %s\n", e->realdomain);
#endif
		 }
			
		 /*
			Next domain
		 */

		 if ((e == NULL) || (vpw == NULL)) {
			e = get_domain_entries(e == NULL ? "" : NULL);
#ifdef QUEUE_DEBUG
			if (e)
			   printf("controller: polling %s\n", e->realdomain);
			else
			   printf("controller: done\n");
#endif

			/*
			   No more domains
			*/

			if (e == NULL) {
			   queue_unlock();
			   break;
			}

			/*
			   Get first user
			*/

			vpw = vauth_getall(e->realdomain, 1, 1);
#ifdef QUEUE_DEBUG
			if (vpw)
			   printf("controller: next %s@%s\n", vpw->pw_name, e->realdomain);
			else
			   printf("controller: %s has no users\n", e->realdomain);
#endif
		 }

		 if (vpw == NULL) {
			queue_unlock();
			continue;
		 }

		 /*
			Add to the queue
		 */

		 memset(b, 0, sizeof(b));
		 snprintf(b, sizeof(b), "%s@%s", vpw->pw_name, e->realdomain);

		 u = user_get(b);
		 if (u == NULL)
			fprintf(stderr, "controller: user_get(%s) failed\n", b);
		 else
			queue_push(u);

		 queue_unlock();
	  }

	  /*
		 Move on to stage two
	  */

	  if (e == NULL)
		 break;

	  ret = shutdown_wait(1);
	  if (ret)
		 break;
   }

   if (!shutdown_flag)
	  printf("controller: stage two\n");

   /*
	  Stage two: Keep userlist up to date
   */

   while(1) {
	  if (shutdown_flag)
		 break;

	  /*
		 Process potential new users
	  */

	  pthread_mutex_lock(&m_newusers);

	  nu = newusers;
	  while(nu) {
		 no = nu;
		 nu = nu->next;

		 /*
			Try to load the user
		 */

		 user_get(no->email);

		 /*
			Deallocate the newuser structure and move on
		 */

		 free(no->email);
		 free(no);
	  }

	  newusers = NULL;
	  pthread_mutex_unlock(&m_newusers);

	  /*
		 This has to be re-called every loop through the list
		 because new items are added to the front of the list
	  */

	  if (userlist == NULL) {
		 last = time(NULL);
		 u = userlist = user_get_userlist();
	  }

	  /*
		 Fill the queue with work
	  */

	  for (; u; u = u->next) {
		 if (shutdown_flag)
			break;

		 /*
			Detect lost users
		 */

		 if ((u->userstore == NULL) || (u->userstore->num_directories == 0)) {
			if ((u->userstore == NULL) || ((u->userstore) && (u->userstore->last_updated != 0))) {
#ifdef QUEUE_DEBUG
			   printf("controller: %s@%s might be a lost user\n", u->user, u->domain->domain);
#endif
			   if (!(user_verify(u))) {
				  u = userlist = user_get_userlist();
				  continue;
			   }
			}
		 }

		 queue_lock();

		 if (queue_size >= queue_max_size) {
			queue_unlock();
			break;
		 }

		 queue_push(u);
		 queue_unlock();
	  }

	  /*
		 Reset userlist pointer and estimate time to go to sleep
	  */

	  if (u == NULL) {
		 userlist = NULL;

		 diff = (directory_minimum_poll_time - ((time(NULL) - last)));
		 if (diff < 1)
			diff = 1;

		 ret = shutdown_wait(diff);
		 if (ret)
			break;
	  }

	  /*
		 Only sleep long enough for some space to clear in the queue
	  */

	  else {
		 ret = shutdown_wait(1);
		 if (ret)
			break;
	  }
   }

   printf("controller: done\n");
   pthread_exit(NULL);
   return NULL;
}

/*
   Worker function
*/

static void *queue_worker(void *self)
{
   int ret = 0;
   wqueue_t *q = NULL;

   q = NULL;

   while(1) {
	  if (q)
		 queue_free(q);

	  if (shutdown_flag)
		 break;

	  ret = queue_lock();
	  if (!ret) {
		 ret = shutdown_wait(1);
		 if (ret)
			break;

		 continue;
	  }

	  if (q) {
		 queue_proc--;
		 q = NULL;
	  }

	  /*
		 Wait for queue item
	  */

	  ret = queue_spin(15);

	  if (shutdown_flag) {
		 queue_unlock();
		 break;
	  }

	  if (!ret) {
		 queue_unlock();
		 continue;
	  }

	  /*
		 Get item
	  */

	  q = queue_pop();
	  if (q == NULL) {
		 fprintf(stderr, "queue_worker: queue_pop failed\n");
		 queue_unlock();
		 continue;
	  }

	  queue_proc++;
	  queue_unlock();

	  /*
		 Process item
	  */

	  ret = user_poll(q->user);
#ifdef QUEUE_DEBUG
	  printf("queue: %p: processed %s@%s\n", self, q->user->user, q->user->domain->domain);
#endif
   }

   pthread_exit(NULL);
   return NULL;
}

/*
   Lock the queue
*/

static inline int queue_lock(void)
{
   int ret = 0;

   ret = pthread_mutex_lock(&m_queue);
   if (ret == 0)
	  return 1;

   return 0;
}

/*
   Unlock the queue
*/

static inline int queue_unlock(void)
{
   int ret = 0;

   ret = pthread_mutex_unlock(&m_queue);
   if (ret == 0)
	  return 1;

   return 0;
}

/*
   Wait for item in the queue
   Assumes queue mutex is locked
*/

static inline int queue_spin(int stime)
{
   int ret = 0;
   struct timespec ts;

#ifdef ASSERT_DEBUG
   assert(queue_size <= queue_size);
   assert(queue_size >= 0);
#endif

   if (queue_size)
	  return 1;

   /*
	  Wait a period of time for entry in the queue
   */

   ts.tv_sec = (time(NULL) + stime);
   ts.tv_nsec = 0;

   ret = pthread_cond_timedwait(&c_queue, &m_queue, &ts);
   if (ret != 0)
	  return 0;

   /*
	  Nothing in the queue
   */

   if (queue_size == 0)
	  return 0;

   /*
	  1 or more items in the queue
   */

   return 1;
}

/*
   Deallocate queue structure
*/

static inline void queue_free(wqueue_t *q)
{
#ifdef ASSERT_DEBUG
   assert(q != NULL);
#endif

   free(q);
}
