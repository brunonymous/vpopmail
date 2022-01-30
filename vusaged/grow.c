/*
   $Id: grow.c 1014 2011-02-03 16:04:37Z volz0r $

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
#include "grow.h"

/*
   Allocate a new grow structure
*/
grow_t *grow_alloc(void)
{
  grow_t *g = NULL;

  g = (grow_t *)malloc(sizeof(grow_t));
  if (g == NULL)
     return NULL;

  memset((grow_t *)g, 0, sizeof(grow_t));
  return g;
}

/*
   Set up the grow buffer
   Allow user to provide a pre-allocated buffer
   for efficiency
*/
int grow_init(grow_t *g, char *buffer, size_t size)
{
  size_t s = 0;

  g->grow = GROW_BUFFER_ADD;

  /*
    Pre-allocated buffer
  */
  if (buffer) { 
     if ((buffer != g->data) || (g->size != size)) {
        if (g->data)
           free(g->data);

        g->data = buffer;
        g->size = size;
     }     
  }
  
  /*
     Allocate default space
  */
  else { 
     if (size == 0)
        s = GROW_BUFFER_SIZE;
     else
        s = size;

     g->data = (char *)malloc(s + 1);
     if (g->data == NULL)
        return 0;
 
     g->size = s;
     *(g->data) = '\0';
  }

  return 1;
}

/*
   Add new data to the grow buffer
*/
int grow_inject(grow_t *g, char *data, size_t bytes)
{
  void *p = NULL;
  size_t addum = 0;

  /*
     Reallocate space
  */
  if ((g->bytes + bytes) > g->size) {
     if (g->grow < ((g->bytes + bytes) - g->size))
        addum = (((g->bytes + bytes) - g->size) + g->grow + 1);

     else
        addum = g->grow;

     p = realloc((char *)g->data, (g->size + addum + 1));
     if (p == NULL)
        return 0;

     if (p != g->data)
        g->data = p;

     g->size += addum;
  }

  memcpy((char *)(g->data + g->bytes), (char *)data, bytes);
  g->bytes += bytes;

  *(g->data + g->bytes) = '\0';

  return 1;
}

/*
   Restart the contents of the grow structure
*/
void grow_restart(grow_t *g)
{
  if (g->bytes) {
     *(g->data) = '\0';
     g->bytes = 0;
  }
}

/*
   Deallocate space associated with a grow structure
*/
void grow_kill(grow_t *g)
{
  if (g->data)
     free(g->data);

  free(g);
}

/*
   Cut the front off the top of a grow structure
*/
int grow_cut(grow_t *g, size_t len)
{
  if (len > g->bytes)
     return 0;

  /*
     Optimize if we're clearing out the entire buffer
  */
  if (len == g->bytes) {
     grow_restart(g);
     return 1;
  }

  memmove(g->data, g->data + len, g->bytes - len);

  g->bytes -= len;
  *(g->data + g->bytes) = '\0';

  return 1;
}
