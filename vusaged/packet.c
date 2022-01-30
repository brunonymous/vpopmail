/*
   $Id: packet.c 1014 2011-02-03 16:04:37Z volz0r $

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
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include "grow.h"
#include "query.h"
#include "packet.h"
#include "socket.h"

/*
   Maximum packet size
*/

#define PACKET_MAX_QUERY_SIZE 1024

/*
   Read a packet
   Packet = [<2 BYTE LEN><DATA OF LEN LENGTH>]
*/

int packet_read(void *handle, grow_t *g)
{
   int ret = 0;
   uint16_t qlen = 0;

#ifdef ASSERT_DEBUG
   assert(handle != NULL);
   assert(g != NULL);
   assert(g->data != NULL);
#endif

   while(g->bytes >= sizeof(uint16_t)) {
	  /*
		 Determine if entire packet is present
	  */

	  memcpy(&qlen, g->data, sizeof(uint16_t));

	  qlen = ntohs(qlen);

	  if (qlen == 0) {
#ifdef ASSERT_DEBUG
		 assert(g->bytes >= sizeof(uint16_t));
#endif
#ifdef PACKET_DEBUG
		 printf("packet_read: 0 length packet\n");
#endif
		 grow_cut(g, sizeof(uint16_t));
		 continue;
	  }

	  /*
		 Limit packet size
	  */

	  if (qlen > PACKET_MAX_QUERY_SIZE) {
		 fprintf(stderr, "packet_read: received large query: %d\n", qlen);
		 return 0;
	  }

	  /*
		 Need to read more data
	  */

	  if (g->bytes < (qlen + sizeof(uint16_t))) {
#ifdef PACKET_DEBUG
		 printf("packet_read: waiting on more data\n");
#endif
		 break;
	  }

	  /*
		 Process the query
	  */

#ifdef PACKET_DEBUG
	  printf("packet_read: sending packet over to query_parse\n");
#endif

	  ret = query_parse(handle, (g->data + sizeof(uint16_t)), qlen);
	  if (!ret) {
		 fprintf(stderr, "packet_read: query_parse failed\n");
		 return 0;
	  }

	  /*
		 Done with the data
	  */

	  ret = grow_cut(g, qlen + sizeof(uint16_t));
	  if (!ret) {
		 fprintf(stderr, "packet_read: grow_cut failed\n");
		 return 0;
	  }
   }

   return 1;
}

/*
   Buffer outbound data
*/

int packet_write(void *handle, const void *data, int len)
{
   return socket_buffer(handle, data, len);
}
