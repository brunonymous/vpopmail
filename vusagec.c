/*
   $Id: vusagec.c 1014 2011-02-03 16:04:37Z volz0r $

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
#include "client.h"
#include "storage.h"

int main(int argc, char *argv[])
{
#ifdef QUICK_QUERY
   int ret = 0, i = 0;
#else
   void *handle = NULL;
   int i = 0, ret = 0;
#endif
   storage_t uusage = 0, musage = 0;

   if (argc < 2) {
	  printf("Usage: %s <email|@domain> [...]\n", argv[0]);
	  return 1;
   }

#ifdef QUICK_QUERY
   for (i = 1; i < argc; i++) {
	  ret = client_query_quick(argv[i], &uusage, &musage);
	  if (!ret)
		 printf("client_query_quick failed\n");
	  else {
		 if (uusage == -1)
			printf("%s: No data available\n", argv[i]);
		 else
			printf("%s: %llu byte(s) in %llu file(s)\n", *(argv[i]) == '@' ? (argv[i] + 1) : argv[i], uusage, musage);
	  }
   }
#else
   handle = client_connect();
   if (handle == NULL) {
	  printf("client_connect failed\n");
	  return 1;
   }

   for (i = 1; i < argc; i++) {
	  ret = client_query(handle, argv[i], strlen(argv[i]), &uusage, &musage);
	  if (!ret) {
		 printf("client_query failed\n");
		 continue;
	  }

	  if (uusage == -1)
		 printf("%s: No data available\n", argv[i]);
	  else
		 printf("%s: %llu byte(s) in %llu file(s)\n", *(argv[i]) == '@' ? (argv[i] + 1) : argv[i], uusage, musage);
   }

   client_close(handle);
#endif
   return 0;
}
