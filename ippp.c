/*
   $Id: ippp.c 1014 2011-02-03 16:04:37Z volz0r $

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
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ippp.h"

/*
   Parse an 'IP:PORT' pair and fill a sockaddr_in structure
   Does not mangle the source
*/

int ippp_parse(const char *pair, struct sockaddr_in *addr)
{
   int port = 0;
   char ip[16] = { 0 };
   const char *p = NULL;

#ifdef ASSERT_DEBUG
   assert(pair != NULL);
   assert(addr != NULL);
#endif

   /*
	  Find seperator
   */

   for (p = pair; *p; p++) {
	  if (*p == ':')
		 break;
   }

   if (*p != ':')
	  return 0;

   /*
	  Convert port part to an integer
   */

   port = atoi(p + 1);
   if (port < 1)
	  return 0;

   /*
	  Save IP
   */

   memcpy(ip, pair, (p - pair));
   *(ip + (p - pair)) = '\0';

   /*
	  Fill structure
   */

   memset(addr, 0, sizeof(struct sockaddr_in));

   addr->sin_family = AF_INET;
   addr->sin_port = htons(port);
   addr->sin_addr.s_addr = inet_addr(ip);

   if (addr->sin_addr.s_addr == -1)
	  return 0;

   return 1;
}
