/*
   $Id: query.c 1014 2011-02-03 16:04:37Z volz0r $

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
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include <ctype.h>
#include "../storage.h"
#include "packet.h"
#include "user.h"
#include "query.h"
#include "queue.h"

/*
   Parse a single query from the network
*/

int query_parse(void *handle, char *data, int len)
{
   int ret = 0;
   char *p = NULL;
   storage_t susage = 0, cusage = 0;

#ifdef ASSERT_DEBUG
   assert(handle != NULL);
   assert(data != NULL);
#endif

   for (p = data; *p; p++) {
	  if ((*p >= 'A') && (*p <= 'Z'))
		 *p = tolower(*p);
   }

#ifdef QUERY_DEBUG
   printf("query: %s\n", data);
#endif

   /*
	  Default response 'Not monitored'
   */

   susage = cusage = -1;

   /*
	  Domain counts
   */

   if (*data == '@')
	  domain_get_use(data + 1, &susage, &cusage);

   /*
	  User counts
   */

   else {
	  /*
		 Get user counts
	  */

	  ret = user_get_use(data, &susage, &cusage);

	  /*
		 Put user in new user queue
	  */

	  if (ret == -1)
		 queue_check_newuser(data);
   }

   /*
	  Convert to network byte order
   */

   susage = htonll(susage);
   cusage = htonll(cusage);

   /*
	  Write response
   */

   ret = packet_write(handle, &susage, sizeof(susage));
   if (!ret) {
	  fprintf(stderr, "query_parse: packet_write failed\n");
	  return 1;
   }

   ret = packet_write(handle, &cusage, sizeof(cusage));
   if (!ret) {
	  fprintf(stderr, "query_parse: packet_write failed\n");
	  return 1;
   }

#ifdef QUERY_DEBUG
   printf("query: %s: size=%llu; count=%llu\n", data, ntohll(susage), ntohll(cusage));
#endif
   return 1;
}

