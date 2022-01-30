/*
   $Id: vusaged.c 1014 2011-02-03 16:04:37Z volz0r $

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
#include "conf.h"
#include "signal.h"
#include "socket.h"
#include "cache.h"
#include "directory.h"
#include "queue.h"
#include "userstore.h"
#include "shutdown.h"

extern char shutdown_flag;

int main(int argc, char *argv[])
{
   int ret = 0;
   config_t *config = NULL;
   char *filename = "vusaged.conf";

   /*
	  Initialize everything
   */

   if (argc > 1)
	  filename = argv[1];

   config = config_begin(filename);
   if (config == NULL) {
	  fprintf(stderr, "config_read failed\n");
	  return 1;
   }

   printf("config: using %s\n", config->filename);

   ret = shutdown_init();
   if (!ret) {
	  fprintf(stderr, "shutdown_init failed\n");
	  return 1;
   }

   ret = signal_init(config);
   if (!ret) {
	  fprintf(stderr, "signal_init failed\n");
	  return 1;
   }

   ret = directory_init(config);
   if (!ret) {
	  fprintf(stderr, "directory_init failed\n");
	  return 1;
   }

   ret = userstore_init(config);
   if (!ret) {
	  fprintf(stderr, "userstore_init failed\n");
	  return 1;
   }

   ret = cache_init(config);
   if (!ret) {
	  fprintf(stderr, "cache_init failed\n");
	  return 1;
   }

   ret = socket_init(config);
   if (!ret) {
	  fprintf(stderr, "socket_init failed\n");
	  return 1;
   }

   ret = queue_init(config);
   if (!ret) {
	  fprintf(stderr, "queue_init failed\n");
	  return 1;
   }

   config_kill(config);

   printf("vusaged: begin\n");

   /*
	  Begin processing of queries
   */

   while(!shutdown_flag) {
	  /*
		 Read any incoming queries
	  */

	  ret = socket_listen();
	  if (!ret) {
		 fprintf(stderr, "socket_loop failed\n");
		 return 1;
	  }
   }

   /*
	  Wait for workers to finish
   */

   ret = queue_shutdown();
   if (!ret) {
	  fprintf(stderr, "queue_shutdown failed\n");
	  return 1;
   }

   printf("vusaged: end\n");
   return 0;
}
