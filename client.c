/*
   $Id: client.c 1014 2011-02-03 16:04:37Z volz0r $

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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "storage.h"
#include "conf.h"
#include "ippp.h"
#include "client.h"

/*
   Default timeout for requests
*/

#define CLIENT_SERVER_TIMEOUT 1

/*
   Client handle
*/

typedef struct __client_handle_ {
   int s,							// Socket
	   timeout;						// Timeout
} client_handle_t;

/*
   Connect to daemon
*/

void *client_connect(void)
{
   struct timeval tv;
   struct sockaddr_un lun;
   struct sockaddr_in addr;
   config_t *config = NULL;
   char *str = NULL, socket_file[107] = { 0 };
   int s = 0, ret = 0, fl = 0, timeout = 0;
   fd_set wfds;
   client_handle_t *handle = NULL;

   timeout = CLIENT_SERVER_TIMEOUT;
   memset(socket_file, 0, sizeof(socket_file));

   /*
	  Load configuration file
   */

   config = config_begin("vusagec.conf");
   if (config == NULL)
	  return NULL;

   /*
	  Disabled?
   */

   str = config_fetch_by_name(config, "Server", "Disable");
   if ((str) && (*str)) {
	  if (!(strcasecmp(str, "True"))) {
		 config_kill(config);
		 return NULL;
	  }
   }

   /*
	  Get timeout
   */

   str = config_fetch_by_name(config, "Server", "Timeout");
   if (str) {
	  fl = atoi(str);
	  if ((fl == -1) || (fl == 0))
		 fprintf(stderr, "client_connect: configuration error: Server::Timeout: %s\n", str);
	  else
		 timeout = fl;
   }

   /*
	  Determine connection type
   */

   str = config_fetch_by_name(config, "Server", "Remote");
   if (str) {
	  ret = ippp_parse(str, &addr);
	  if (!ret) {
		 config_kill(config);
		 fprintf(stderr, "client_connect: configuration error: Server::Remote: %s\n", str);
		 return NULL;
	  }
   }

   else {
	  str = config_fetch_by_name(config, "Server", "Filename");
	  if ((str) && (!(*str))) {
		 config_kill(config);
		 fprintf(stderr, "client_connect: configuration error: Server::Filename\n");
		 return NULL;
	  }

	  fl = strlen(str);
	  if (fl >= sizeof(socket_file))
		 fl = (sizeof(socket_file) - 1);

	  memcpy(socket_file, str, fl);
   }

   config_kill(config);

   /*
	  Allocate a socket
   */

   if (*socket_file)
	  s = socket(PF_UNIX, SOCK_STREAM, 0);
   else
	  s = socket(AF_INET, SOCK_STREAM, 0);

   if (s == -1) {
	  fprintf(stderr, "client_connect: socket failed: %d\n", errno);
	  return NULL;
   }

   /*
	  Set the socket non-blocking
   */

   fl = fcntl(s, F_GETFL);
   if (fl == -1)
	  fprintf(stderr, "client_connect: warning: fcntl failed: %d\n", errno);

   else {
	  fl |= O_NONBLOCK;

	  ret = fcntl(s, F_SETFL, fl);
	  if (ret == -1)
		 fprintf(stderr, "client_connect: warning: fcntl failed: %d\n", errno);
   }

   /*
	  Set socket path
   */

   if (*socket_file) {
	  memset(&lun, 0, sizeof(lun));
	  lun.sun_family = PF_UNIX;
	  memcpy(lun.sun_path, socket_file, strlen(socket_file));
   }

   /*
	  Begin connection
   */

   if (*socket_file)
	  ret = connect(s, (struct sockaddr *)&lun, sizeof(lun));
   else
	  ret = connect(s, (struct sockaddr *)&addr, sizeof(addr));
   
   if (ret == -1) {
	  if (errno != EINPROGRESS) {
		 close(s);
		 fprintf(stderr, "client_connect: connect failed: %d\n", errno);
		 return NULL;
	  }
   }

   /*
	  Allocate a handle
   */

   handle = malloc(sizeof(client_handle_t));
   if (handle == NULL) {
	  close(s);
	  fprintf(stderr, "client_connect: malloc failed\n");
	  return NULL;
   }

   /*
	  Initialize
   */

   memset(handle, 0, sizeof(client_handle_t));

   /*
	  Set configuration values
   */

   handle->s = s;
   handle->timeout = timeout;

   /*
	  If setting O_NONBLOCK failed, check for connect() success
   */

   if (fl == -1) {
	  if (ret != 0) {
		 close(s);
		 fprintf(stderr, "client_connect: connect failed: %d\n", errno);
		 return NULL;
	  }

	  return handle;
   }

   /*
	  Begin timed connection process
   */

   tv.tv_sec = timeout;
   tv.tv_usec = 0;

   FD_ZERO(&wfds);
   FD_SET(s, &wfds);

   ret = select(s + 1, NULL, &wfds, NULL, &tv);
   if (ret == -1) {
	  fprintf(stderr, "client_connect: select failed: %d\n", errno);
	  close(s);
	  return NULL;
   }

   if (ret == 0) {
	  close(s);
	  fprintf(stderr, "client_connect: connect timeout\n");
	  return NULL;
   }

   return handle;
}

/*
   Send query, return response
*/

int client_query(void *vhandle, const char *entry, uint16_t len, storage_t *susage, storage_t *cusage)
{
   int ret = 0;
   fd_set rfds;
   struct timeval tv;
   char b[sizeof(storage_t) * 2] = { 0 };
   client_handle_t *handle = (client_handle_t *)vhandle;

   if (susage)
	  *susage = -1;

   if (cusage)
	  *cusage = -1;

   if (handle == NULL)
	  return 0;
   
   len = htons(len);

   ret = write(handle->s, &len, sizeof(len));
   if (ret != sizeof(len)) {
	  fprintf(stderr, "client_query: write failed: %d (%d)\n", ret, errno);
	  return 0;
   }

   len = ntohs(len);

   ret = write(handle->s, entry, len);
   if (ret != len) {
	  fprintf(stderr, "client_query: write failed: %d (%d)\n", ret, errno);
	  return 0;
   }

   /*
	  Read with timeout
   */

   tv.tv_sec = handle->timeout;
   tv.tv_usec = 0;

   FD_ZERO(&rfds);
   FD_SET(handle->s, &rfds);

   ret = select(handle->s + 1, &rfds, NULL, NULL, &tv);
   if (ret == -1) {
	  fprintf(stderr, "client_query: select failed: %d\n", errno);
	  return 0;
   }

   if (ret == 0) {
	  fprintf(stderr, "client_query: timeout on response\n");
	  return 0;
   }

   /*
	  Read reply into buffer
   */

   ret = read(handle->s, b, (sizeof(storage_t) * 2));
   if (ret == -1) {
	  fprintf(stderr, "client_query: read failed: %d\n", errno);
	  return 0;
   }

   if (ret == 0) {
	  fprintf(stderr, "client_query: lost connection to server\n");
	  return 0;
   }

   if (ret != (sizeof(storage_t) * 2)) {
	  fprintf(stderr, "client_query: smaller than expected response\n");
	  return 0;
   }

   /*
	  Copy buffer into variable space
   */

   if (susage)
	  memcpy(susage, b, sizeof(storage_t));

   if (cusage)
	  memcpy(cusage, (b + sizeof(storage_t)), sizeof(storage_t));

   /*
	  Convert values to local byte order
   */

   if (susage)
	  *susage = ntohll(*susage);

   if (cusage)
	  *cusage = ntohll(*cusage);

   return 1;
}

/*
   Disconnect from daemon
*/

void client_close(void *vhandle)
{
   client_handle_t *handle = (client_handle_t *)vhandle;

   if (handle == NULL)
	  return;

   if (handle->s != -1)
	  close(handle->s);

   free(handle);
}

/*
   Quick and easy API call
*/

int client_query_quick(const char *entry, storage_t *susage, storage_t *cusage)
{
   void *handle = NULL;
   int ret = 0;

   if (entry == NULL)
	  return 0;

   handle = client_connect();
   if (!handle)
	  return 0;

   ret = client_query(handle, entry, strlen(entry), susage, cusage);

   client_close(handle);
   return ret;
}
