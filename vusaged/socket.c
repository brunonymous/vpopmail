/*
   $Id: socket.c 1014 2011-02-03 16:04:37Z volz0r $

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
#include <fcntl.h>
#include <time.h>
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <ev.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "conf.h"
#include "packet.h"
#include "grow.h"
#include "ippp.h"
#include "socket.h"

/*
   Shutdown flag
*/

extern char shutdown_flag;

/*
   Read size
*/

#define SOCKET_MAX_READ_SIZE 1400

/*
   Maximum buffer size
*/

#define SOCKET_MAX_BUFFER_SIZE (SOCKET_MAX_READ_SIZE * 10)

/*
   Poll timeout in milliseconds
*/

#define SOCKET_POLL_TIMEOUT 1000

/*
   Time to loop on socket linked list
*/

#define SOCKET_DETECT_CLIENT_TIMEOUT 4

/*
   Timeout
*/

#define SOCKET_CLIENT_TIMEOUT 10

/*
   Socket flags
*/

#define SOCKET_F_NONE  0
#define SOCKET_F_READ  1	/* Socket is readable  */
#define SOCKET_F_WRITE 2	/* Socket is writeable */
#define SOCKET_F_KILL  4    /* Socket is closing   */

/*
   Socket linked list
*/

typedef struct __socket_ {
   int s,					// Socket
	   flags;				// Flags

   grow_t *in,				// Incoming buffer
		  *out;				// Outgoing buffer
   
   time_t last_query;		// Last query time
   struct ev_io r_eio, w_eio;	// libev handle
   struct __socket_ *prev, *next;
} socket_t;

#ifdef SOCKET_DEBUG
static int num_sockets = 0;
#endif
static char *socket_file = NULL;
static char **socket_allow = NULL;
static struct ev_io els;
static struct ev_timer etime;
static struct ev_loop *ev = NULL;
static int ls = 0;
static time_t last_client_check = 0;
static socket_t *sockets = NULL;
static int socket_poll_timeout = SOCKET_POLL_TIMEOUT;
static int socket_client_timeout = SOCKET_CLIENT_TIMEOUT;
static int socket_detect_client_timeout = SOCKET_DETECT_CLIENT_TIMEOUT;

static inline socket_t *socket_new(void);
static inline void socket_close(socket_t *);
static inline void socket_remove(socket_t *);
static inline void socket_accept(EV_P_ struct ev_io *, int);
static inline void socket_read(EV_P_ struct ev_io *, int);
static inline void socket_write(EV_P_ struct ev_io *, int);
static inline void socket_timer(EV_P_ struct ev_timer *, int);

/*
   Initialize socket functions
*/

int socket_init(config_t *config)
{
   uid_t uid = 0;
   gid_t gid = 0;
   mode_t modes = 0;
   struct sockaddr_un lun;
   struct sockaddr_in addr;
   struct passwd *pw = NULL;
   struct group *grp = NULL;
   int ret = 0, lf = 0, fl = 0;
   char *str = NULL, *t = NULL, *h = NULL;

   ls = -1;

   /*
	  Socket file
   */

   socket_file = config_fetch_by_name(config, "Socket", "Filename");

   /*
	  IP and port
   */

   str = config_fetch_by_name(config, "Socket", "Listen");
   if (((str == NULL) || (!(*str))) && ((socket_file == NULL) || (!(*socket_file)))) {
	  fprintf(stderr, "socket_init: missing configuration: Socket::Filename or Socket::Listen\n");
	  return 0;
   }

   if (str) {
	  if (socket_file) {
		 fprintf(stderr, "socket_init: invalid configuration: Can't use both Socket::Filename and Socket::Listen\n");
		 return 0;
	  }

	  /*
		 Parse IP:PORT pair
	  */

	  ret = ippp_parse(str, &addr);
	  if (!ret) {
		 fprintf(stderr, "socket_init: syntax error: Socket::Listen: %s\n", str);
		 return 0;
	  }

	  /*
		 Load allowed source IPs
	  */

	  socket_allow = NULL;

	  str = config_fetch_by_name(config, "Socket", "Allow");
	  if ((str == NULL) || (!(*str)))
		 printf("socket: warning: no incoming connections allowed\n");

	  else {
		 /*
			Count IPs
		 */

		 lf = 1;

		 for (h = str; *h; h++) {
			if ((*h == ' ') || (*h == '\t'))
			   lf++;
		 }

		 /*
			Allocate array
		 */

		 socket_allow = malloc(sizeof(char *) * (lf + 1));
		 if (socket_allow == NULL) {
			fprintf(stderr, "socket_init: malloc failed\n");
			return 0;
		 }

		 /*
			Fill array
		 */

		 lf = 0;

		 for (t = h = str;; h++) {
			if ((*h == ' ') || (*h == '\t') || (*h == '\0')) {
			   if (!(*h))
				  h = NULL;
			   else
				  *h = '\0';

			   if (*t) {
				  socket_allow[lf] = strdup(t);
				  lf++;
			   }

			   if (h == NULL)
				  break;

			   h++;
			   t = h;
			}
		 }

		 /*
			Terminate the array
		 */

		 socket_allow[lf] = NULL;
	  }
   }

   /*
	  Ownership and permissions
   */

   if (socket_file) {
	  str = config_fetch_by_name(config, "Socket", "UID");
	  if (str) {
		 if (!(*str)) {
			fprintf(stderr, "socket_init: missing configuration: Socket::UID\n");
			return 0;
		 }

		 if (!(strcasecmp(str, "auto")))
			str = "vpopmail";

		 uid = atoi(str);

		 /*
			UID may be username
		 */

		 if (uid <= 0) {
			pw = getpwnam(str);
			if (pw == NULL) {
			   fprintf(stderr, "socket_init: invalid configuration: Socket::UID: %s\n", str);
			   return 0;
			}

			uid = pw->pw_uid;
		 }
	  }

	  str = config_fetch_by_name(config, "Socket", "GID");
	  if (str) {
		 if (!(*str)) {
			fprintf(stderr, "socket_init: missing configuration: Socket::GID\n");
			return 0;
		 }

		 if (!(strcasecmp(str, "auto")))
			str = "vchkpw";

		 gid = atoi(str);

		 if (gid <= 0) {
			grp = getgrnam(str);
			if (grp == NULL) {
			   fprintf(stderr, "socket_init: invalid configuration: Socket::GID: %s\n", str);
			   return 0;
			}

			gid = grp->gr_gid;
		 }
	  }

	  str = config_fetch_by_name(config, "Socket", "Modes");
	  if (str) {
		 if (!(*str)) {
			fprintf(stderr, "socket_init: missing configuration: Socket::Modes\n");
			return 0;
		 }

		 modes = atoi(str);
		 if ((modes == 0) || (errno == EINVAL)) {
			fprintf(stderr, "socket_init: invalid configuration: Socket::Modes: %s\n", str);
			return 0;
		 }
	  }

	  unlink(socket_file);

	  /*
		 Setup the unix structure
	  */

	  memset(&lun, 0, sizeof(lun));

	  ret = strlen(socket_file);
	  if (ret > 107) {
		 fprintf(stderr, "socket_init: Socket::Filename too long (maximum 107 characters)\n");
		 return 0;
	  }

	  memcpy(lun.sun_path, socket_file, ret);

	  lun.sun_family = PF_UNIX;
   }

   socket_poll_timeout = SOCKET_POLL_TIMEOUT;
   str = config_fetch_by_name(config, "Socket", "Poll timeout");
   if (str) {
	  socket_poll_timeout = atoi(str);
	  if (socket_poll_timeout == -1) {
		 fprintf(stderr, "socket_init: invalid configuration: Socket::Poll timeout: %s\n", str);
		 return 0;
	  }
   }

   socket_client_timeout = SOCKET_CLIENT_TIMEOUT;
   str = config_fetch_by_name(config, "Socket", "Client timeout");
   if (str) {
	  socket_client_timeout = atoi(str);
	  if (socket_client_timeout == -1) {
		 fprintf(stderr, "socket_init: invalid configuration: Socket::Client timeout: %s\n", str);
		 return 0;
	  }
   }

   socket_detect_client_timeout = SOCKET_DETECT_CLIENT_TIMEOUT;
   str = config_fetch_by_name(config, "Socket", "Detect client timeout");
   if (str) {
	  socket_detect_client_timeout = atoi(str);
	  if (socket_detect_client_timeout == -1) {
		 fprintf(stderr, "socket_init: invalid configuration: Socket::Detect client timeout: %s\n", str);
		 return 0;
	  }
   }

   /*
	  Create socket
   */

   ls = socket(socket_file != NULL ? PF_UNIX : AF_INET, SOCK_STREAM, 0);
   if (ls == -1) {
	  fprintf(stderr, "socket_init: socket failed: %d\n", errno);
	  return 0;
   }

   fl = fcntl(ls, F_GETFL);
   if (fl == -1) {
	  close(ls);
	  ls = -1;
	  fprintf(stderr, "socket_init: fcntl failed: %d\n", errno);
	  return 0;
   }

   fl |= O_NONBLOCK;

   ret = fcntl(ls, F_SETFL, fl);
   if (ret == -1) {
	  close(ls);
	  ls = -1;
	  fprintf(stderr, "socket_init: fcntl failed: %d\n", errno);
	  return 0;
   }

   lf = 1;
   ret = setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &lf, sizeof(int));
   if (ret == -1)
	  fprintf(stderr, "socket_init: warning: SO_REUSEADDR failed\n");

   if (socket_file)
	  ret = bind(ls, (struct sockaddr *)&lun, sizeof(lun));
   else
	  ret = bind(ls, (struct sockaddr *)&addr, sizeof(addr));

   if (ret == -1) {
	  fprintf(stderr, "socket_init: bind failed: %d\n", errno);
	  close(ls);
	  ls = -1;
	  return 0;
   }
  
   /*
	  Set ownership
   */

   if (socket_file) {
	  ret = chown(socket_file, uid, gid);
	  if (ret == -1) {
		 fprintf(stderr, "socket_init: warning: chown(%s, %u, %u) failed\n", socket_file, uid, gid);
		 close(ls);
		 ls = -1;
		 return 0;
	  }

	  /*
		 Set socket file modes
	  */

	  ret = chmod(socket_file, 0644);
	  if (ret == -1) {
		 fprintf(stderr, "socket_init: warning: chmod failed\n");
		 close(ls);
		 ls = -1;
		 return 0;
	  }
   }

   /*
	  Listen
   */

   ret = listen(ls, 10);
   if (ret == -1) {
	  fprintf(stderr, "socket_init: listen failed: %d\n", errno);
	  close(ls);
	  ls = -1;
	  return 0;
   }

   /*
	  Set up libev
   */

   ev = ev_default_loop(0);
   if (ev == NULL) {
	  close(ls);
	  ls = -1;
	  fprintf(stderr, "socket_init: ev_default_loop failed: %d\n", errno);
	  return 0;
   }

   ev_io_init(&els, socket_accept, ls, EV_READ);
   ev_io_start(ev, &els);

   ev_timer_init(&etime, socket_timer, socket_poll_timeout, socket_poll_timeout);
   ev_timer_start(ev, &etime);

   /*
	  Report configuration
   */

   if (socket_file)
	  printf("socket: listening on %s\n", socket_file);
   else
	  printf("socket: listening on %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

   /*
	  Set initial last timeout check
   */

   last_client_check = time(NULL);
   return 1;
}

/*
   Listen for queries   
*/

int socket_listen(void)
{
   ev_loop(ev, 0);
   return 1;
}

/*
   Buffer outbound data
*/

int socket_buffer(void *handle, const void *data, int len)
{
   int ret = 0;
   socket_t *s = (socket_t *)handle;

#ifdef ASSERT_DEBUG
   assert(handle != NULL);
   assert(data != NULL);
   assert(len > 0);
#endif

   ret = grow_inject(s->out, (char *)data, len);
   if (!ret) {
	  fprintf(stderr, "socket_buffer: grow_inject failed\n");
	  return 0;
   }

   return 1;
}

/*
   Allocate new socket structure and add to linked list
*/

static socket_t *socket_new(void)
{
   socket_t *s = NULL;

   s = malloc(sizeof(socket_t));
   if (s == NULL) {
	  fprintf(stderr, "socket_new: malloc failed\n");
	  return NULL;
   }

   memset(s, 0, sizeof(socket_t));

   /*
	  Allocate growing buffers
   */

   s->in = grow_alloc();
   if (s->in == NULL) {
	  free(s);
	  fprintf(stderr, "socket_new: grow_alloc failed\n");
	  return NULL;
   }

   s->out = grow_alloc();
   if (s->out == NULL) {
	  free(s);
	  grow_kill(s->in);
	  fprintf(stderr, "socket_new: grow_alloc failed\n");
	  return NULL;
   }

   if (!(grow_init(s->in, NULL, 0))) {
	  fprintf(stderr, "socket_new: grow_init failed\n");
	  grow_kill(s->in);
	  grow_kill(s->out);
	  free(s);
	  return NULL;
   }

   if (!(grow_init(s->out, NULL, 0))) {
	  fprintf(stderr, "socket_new: grow_init failed\n");
	  grow_kill(s->in);
	  grow_kill(s->out);
	  free(s);
	  return NULL;
   }

   /*
	  Initial settings
   */

   s->s = -1;
   s->flags = SOCKET_F_NONE;

   /*
	  Add to front of the linked list
   */

   s->next = sockets;

   if (sockets)
	  sockets->prev = s;

   sockets = s;
#ifdef SOCKET_DEBUG
   num_sockets++;
#endif

   return s;
}

/*
   Deallocate socket and remove from linked list
*/

static void socket_close(socket_t *s)
{
#ifdef ASSERT_DEBUG
   assert(s != NULL);
#endif

   if (s->flags & SOCKET_F_KILL)
	  return;

   /*
	  Remove from libev
   */

   if (s->s != -1) {
	  ev_io_stop(ev, &s->r_eio);
	  ev_io_stop(ev, &s->w_eio);
	  close(s->s);
   }

   /*
	  Deallocate buffers
   */

   if (s->in)
	  grow_kill(s->in);

   if (s->out)
	  grow_kill(s->out);

   /*
	  Flag structure can be removed from linked list
   */

   s->flags |= SOCKET_F_KILL;
}

/*
   Remove socket from linked list and deallocate it
*/

static void socket_remove(socket_t *s)
{
#ifdef ASSERT_DEBUG
   assert(s != NULL);
   assert(s->flags & SOCKET_F_KILL);

   if ((s == sockets) && (s->next))
	  assert(s->next->prev == sockets);

   if (s->prev)
	  assert(s->prev->next == s);

   if (s->next)
	  assert(s->next->prev == s);
#endif

   if (s == sockets)
	  sockets = s->next;

   if (s->prev)
	  s->prev->next = s->next;

   if (s->next)
	  s->next->prev = s->prev;

   free(s);
#ifdef SOCKET_DEBUG
   num_sockets--;
#endif
}

/*
   Accept incoming connection
*/

static inline void socket_accept(EV_P_ struct ev_io *io, int events)
{
   socket_t *ss = NULL;
   struct sockaddr_in addr;
   socklen_t lf = 0;
   int s = 0, ret = 0, fl = 0, i = 0;
   char b[16] = { 0 };

   while(1) {
	  /*
		 Accept the connection
	  */

	  s = accept(ls, (struct sockaddr *)&addr, &lf);
	  if (s == -1) {
		 if (errno == EAGAIN) {
			return;
		 }

		 if (errno == EMFILE) {
			fprintf(stderr, "socket_listen: warning: out of file descriptors\n");
			return;
		 }

		 fprintf(stderr, "socket_listen: accept failed: %d\n", errno);
		 return;
	  }

	  /*
		 If from a networked socket, check that the source IP is allowed
	  */

	  if (socket_file == NULL) {
		 lf = sizeof(addr);
		 getpeername(s, (struct sockaddr *)&addr, &lf);
		 snprintf(b, sizeof(b), "%s", inet_ntoa(addr.sin_addr));

		 i = -1;

		 if (socket_allow) {
			for (i = 0; socket_allow[i]; i++) {
			   if (!(strcmp(b, socket_allow[i])))
				  break;
			}

			if (socket_allow[i] == NULL)
			   i = -1;
		 }

		 if (i == -1) {
			printf("socket: rejected connection from %s:%d\n", b, ntohs(addr.sin_port));
			close(s);
			return;
		 }
	  }

	  /*
		 Set non-blocking I/O
	  */

	  fl = fcntl(s, F_GETFL);
	  if (fl == -1) {
		 close(s);
		 fprintf(stderr, "socket_listen: fcntl failed: %d\n", errno);
		 return;
	  }

	  fl |= O_NONBLOCK;

	  ret = fcntl(s, F_SETFL, fl);
	  if (ret == -1) {
		 close(s);
		 fprintf(stderr, "socket_listen: fcntl failed: %d\n", errno);
		 return;
	  }

	  /*
		 Add to linked list
	  */

	  ss = socket_new();
	  if (ss == NULL) {
		 close(s);
		 fprintf(stderr, "socket_listen: socket_new failed\n");
		 return;
	  }

	  ss->s = s;
	  ss->last_query = time(NULL);

	  /*
		 Add to libev
	  */

	  ss->r_eio.data = ss;
	  ss->w_eio.data = ss;

	  ev_io_init(&ss->r_eio, socket_read, s, EV_READ);
	  ev_io_start(loop, &ss->r_eio);

	  ev_io_init(&ss->w_eio, socket_write, s, EV_WRITE);
	  ev_io_start(loop, &ss->w_eio);

#ifdef SOCKET_DEBUG
	  printf("%p: connected\n", ss);
#endif
   }
}

/*
   Read data from socket
*/

static void socket_read(EV_P_ struct ev_io *io, int events)
{
   ssize_t ret = 0;
   socket_t *s = NULL;
   unsigned char b[SOCKET_MAX_READ_SIZE] = { 0 };
   
   s = io->data;
   s->flags |= SOCKET_F_READ;

#ifdef ASSERT_DEBUG
   assert(s != NULL);
#endif

   if (s->flags & SOCKET_F_KILL) {
	  printf("  socket is kill\n");
	  return;
   }

#ifdef ASSERT_DEBUG
   assert(s->s != -1);
   assert(s->in != NULL);
#endif

   while(s->flags & SOCKET_F_READ) {
	  /*
		 Either processing too slow, or too many queries at once
	  */

	  if (s->in->bytes > SOCKET_MAX_BUFFER_SIZE) {
		 fprintf(stderr, "socket_read: %p: buffer too large\n", s);
		 socket_close(s);
		 socket_remove(s);
		 return;
	  }

	  ret = read(s->s, b, SOCKET_MAX_READ_SIZE);
	  if (ret == -1) {
		 if (errno == EAGAIN) {
			s->flags ^= SOCKET_F_READ;
			return;
		 }

#ifdef SOCKET_DEBUG
		 fprintf(stderr, "socket_read: read failed: %d\n", errno);
#endif
		 socket_close(s);
		 socket_remove(s);
		 return;
	  }

	  if (ret == 0) {
#ifdef SOCKET_DEBUG
		 printf("%p disconnected\n", s);
#endif
		 socket_close(s);
		 socket_remove(s);
		 return;
	  }

	  if (!(grow_inject(s->in, (char *)b, ret))) {
		 fprintf(stderr, "socket_read: grow_inject failed\n");
		 socket_close(s);
		 return;
	  }

#ifdef SOCKET_DEBUG
	  printf("%p: <-- %d bytes\n", s, ret);
#endif

	  /*
		 Pass to packet parser
	  */

	  ret = packet_read(s, s->in);
	  if (!ret) {
		 fprintf(stderr, "socket_listen: packet_read failed\n");
		 socket_close(s);
		 socket_remove(s);
	  }

	  /*
		 If there is data queued up for write, attempt to write it
	  */

	  else if ((!(s->flags & SOCKET_F_KILL)) && (s->out->bytes)) {
		 socket_write(EV_A_ &s->w_eio, 0);
		 break;
	  }
   }
}

/*
   Write data to socket
*/

static void socket_write(EV_P_ struct ev_io *io, int events)
{
   ssize_t ret = 0;
   socket_t *s = NULL;

   s = io->data;

#ifdef ASSERT_DEBUG
   assert(s != NULL);
#endif

   if (s->flags & SOCKET_F_KILL)
	  return;

#ifdef ASSERT_DEBUG
   assert(s->s != -1);
   assert(s->out != NULL);
   assert(s->out->data != NULL);
#endif

   /*
	  Nothing to write
   */

   if (s->out->bytes == 0) {
	  ev_io_stop (EV_A_ io);
	  return;
   }

   while(s->out->bytes) {
	  ret = write(s->s, s->out->data, s->out->bytes);
	  if (ret == -1) {
		 if (errno == EAGAIN) {
			s->flags ^= SOCKET_F_WRITE;
			return;
		 }

		 if (errno != EPIPE)
			fprintf(stderr, "socket_write: write failed: %d\n", errno);

		 socket_close(s);
		 socket_remove(s);
		 return;
	  }

	  if (ret == 0) {
#ifdef SOCKET_DEBUG
		 printf("%p lost\n", s);
#endif
		 socket_close(s);
		 socket_remove(s);
		 return;
	  }

	  if (!(grow_cut(s->out, ret))) {
		 fprintf(stderr, "socket_write: grow_cut failed\n");
		 socket_close(s);
		 socket_remove(s);
		 return;
	  }

#ifdef SOCKET_DEBUG
	  printf("%p: --> %d bytes\n", s, ret);
#endif
   }
}

/*
   libev callback handler for timer
*/

static inline void socket_timer(EV_P_ struct ev_timer *timer, int events)
{
   time_t t = 0;
   socket_t *s = NULL, *os = NULL;

   /*
	  Check for timed out clients
   */

   t = time(NULL);
   if ((t - last_client_check) >= socket_detect_client_timeout) {
      s = sockets;
      if (s)
         os = s->next;

      while(s) {
         os = s->next;

         if ((t - s->last_query) >= socket_client_timeout) {
#ifdef SOCKET_DEBUG
            fprintf(stderr, "%p: timeout\n", s);
#endif
            socket_close(s);
            socket_remove(s);
         }

         s = os;
      }

	  /*
		 Update last time checked
	  */

      last_client_check = t;
   }

   /*
	  Check for shutdown
   */

   if (shutdown_flag)
	  ev_unloop(EV_A_ EVUNLOOP_ALL);
}
