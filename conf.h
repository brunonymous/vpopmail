/*
   $Id: conf.h 1014 2011-02-03 16:04:37Z volz0r $

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

#ifndef __CONFIG_H_
 #define __CONFIG_H_

/*
   Maximum length of a configuration line
*/

#define CONFIG_MAX_LINE 255

/*
   Atom flags
*/

#define CAF_NONE   0
#define CAF_IGNORE 1 /* Dont look at this again (internal) */

/*
   Config flags
*/

#define CF_NONE     0
#define CF_COMMENT  1 /* Inside a comment                   */

typedef struct __config_atom_ {
  char *name,                      /* Atom name (if any)   */
       *data;                      /* Atom data            */

  int flags;                       /* Atom flags           */

  unsigned long line;              /* Atom exists on line  */

  struct __config_atom_ *next;     /* Next atom            */
} config_atom_t;

typedef struct __config_label_ {
  char *name,                      /* Label name           */
       *filename;                  /* From file            */
  
  unsigned long line;              /* Begins on line       */

  struct __config_atom_ *atoms,    /* Label's atoms        */
                        *atail;    /* Last atom            */
  struct __config_label_ *next;    /* Next label           */
} config_label_t;

typedef struct __config_ {
  char *filename,                  /* Current filename     */
       *dir;                       /* Directory of configs */

  int flags;                       /* Config flags         */
  unsigned long line;              /* Current line         */

  struct __config_label_ *labels,  /* Configuration labels */
	                 *ltail;   /* Last label           */
} config_t;

config_t *config_begin(const char *);
config_t *config_read(char *);
void config_kill(config_t *);
char *config_fetch_by_name(config_t *, char *, char *);
char *config_fetch_by_num(config_t *, char *, int);
int config_reference(config_t *, char *);
char *config_fetch(config_t *, char *);
int config_next_reference(config_t *);

#endif /* __CONFIG_H_ */
