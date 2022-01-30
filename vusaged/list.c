/*
   $Id: list.c 1014 2011-02-03 16:04:37Z volz0r $

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
#ifdef ASSERT_DEBUG
   #include <assert.h>
#endif
#include "list.h"

/*
   Add an item to the end of the list
   Also establishes a new list
*/

void **list_add(void **list, int *items, const void *ptr)
{
#ifdef ASSERT_DEBUG
   assert(items != NULL);
   assert(ptr != NULL);
#endif

   if (list) {
#ifdef ASSERT_DEBUG
	  assert(*items != 0);
#endif

	  list = realloc(list, (sizeof(void *) * (*items + 1)));
	  if (list == NULL) {
		 fprintf(stderr, "list_add: realloc failed\n");
		 return NULL;
	  }
   }

   else {
#ifdef ASSERT_DEBUG
	  assert(*items == 0);
#endif

	  list = malloc(sizeof(void *));
	  if (list == NULL) {
		 fprintf(stderr, "list_add: malloc failed\n");
		 return NULL;
	  }
   }

   list[(int)(*items)] = (void *)ptr;

   /*
	  Compiler warns about *items++
   */

   *items = (*items + 1);
   return list;
}

/*
   Remove an item from a list
*/

void **list_remove(void **list, int *items, const void *ptr)
{
   void **nlist = NULL;
   int i = 0, k = 0, ki = 0;

#ifdef ASSERT_DEBUG
   assert(list != NULL);
   assert(items != NULL);
   assert(*items > 0);
   assert(ptr != NULL);
#endif

   for (i = 0; i < *items; i++) {
	  if (list[i] == ptr)
		 break;
   }

#ifdef ASSERT_DEBUG
   assert(i != *items);
#endif

   /*
	  List will be empty now
   */

   if (*items == 1) {
	  *items = 0;
	  free(list);
	  return NULL;
   }

   /*
	  Adjust array
   */

   for (k = ki = 0; k < *items; k++) {
	  if (k != i) {
		 list[ki] = list[k];
		 ki++;
	  }
   }

   /*
	  Reallocate list
   */

   nlist = realloc(list, (sizeof(void *) * (*items - 1)));
   if (nlist == NULL) {
	  fprintf(stderr, "list_remove: realloc(%p, %d) failed\n", list, (sizeof(void *) * (*items - 1)));

	  /*
		 This shouldn't happen but let's fix the list
		 to prevent a segfault.  This will leak memory.
	  */

	  nlist = list;
   }

   /*
	  Compiler warns aboout *items-- for some reason
   */

   *items = (*items - 1);
   return nlist;
}

/*
   Deallocate a list
*/

void list_free(void **list, int *items)
{
#ifdef ASSERT_DEBUG
   assert(items != NULL);
#endif

   *items = 0;

   if (list)
	  free(list);
}
