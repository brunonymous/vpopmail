/*
   $Id: grow.h 1014 2011-02-03 16:04:37Z volz0r $

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

#ifndef __GROW_H_
 #define __GROW_H_

#define GROW_BUFFER_SIZE 2048
#define GROW_BUFFER_ADD  2048

typedef struct __grow_ {
  char *data;            /* Current buffer and data             */

  size_t bytes,          /* Current length of buffer contents   */
         size,           /* Entire size of buffer area          */
         grow;           /* Length to grow when buffer runs out */
} grow_t;

grow_t *grow_alloc(void);
int grow_init(grow_t *, char *, size_t);
int grow_inject(grow_t *, char *, size_t);
void grow_restart(grow_t *);
void grow_kill(grow_t *);
int grow_cut(grow_t *, size_t);

#endif
