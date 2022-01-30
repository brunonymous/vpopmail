/*
   $Id: conf.c 1014 2011-02-03 16:04:37Z volz0r $

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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include "conf.h"
#include "config.h"

int config_wait(char *);
int config_begin_read(config_t *, char *);
void config_label_kill(config_t *);
void config_atom_kill(config_label_t *);
config_t *config_alloc(void);
config_label_t *config_label_alloc(void);
config_atom_t *config_atom_alloc(void);
void config_atom_free(config_atom_t *);
int config_fullpath(const char *, char *, size_t);
int config_contents(config_t *, FILE *);
int config_parse(config_t *, char *);
void config_remove_comments(config_t *, char *);
int config_parse_label(config_t *, char *, char *);
int config_parse_label_atom(config_t *, config_label_t *, char *);
int config_parse_includes(config_t *);
char *config_next_token(char *, char);
char *config_convert_literal(char *);

/*
   Find configuration file
*/

config_t *config_begin(const char *filename)
{
   config_t *c = NULL;
   char b[255] = { 0 };
   int i = 0;
   struct passwd *pw = NULL;
   const char *locs[] = { "etc", "./", NULL };
   
   if (filename == NULL)
	  return NULL;

   /*
          Try vpopmail/etc
   */

   pw = getpwnam("vpopmail");
   if (pw) {
          memset(b, 0, sizeof(b));
          snprintf(b, sizeof(b), "%s/etc/%s", pw->pw_dir, filename);

          c = config_read(b);
          if (c) {
#ifdef CONFIG_DEBUG
                 printf("config: using %s\n", b);
#endif
                 return c;
          }
   }

   c = config_read(b);
   if (c) {
#ifdef CONFIG_DEBUG
	  printf("config: using %s\n", b);
#endif
	  return c;
   }

   /*
	  Try the filename itself
   */

   c = config_read((char *)filename);
   if (c) {
#ifdef CONFIG_DEBUG
	  printf("config: using %s\n", filename);
#endif
	  return c;
   }

   /*
	  Try alternate locations
   */

   for (i = 0; locs[i] != NULL; i++) {
	  memset(b, 0, sizeof(b));
	  snprintf(b, sizeof(b), "%s/%s", locs[i], filename);

	  c = config_read(b);
	  if (c) {
#ifdef CONFIG_DEBUG
		 printf("config: using %s\n", b);
#endif
		 return c;
	  }
   }

#ifdef CONFIG_DEBUG
   printf("config: couldn't locate %s\n", filename);
#endif
   return NULL;
}

config_t *config_read(char *filename)
{
  int ret = 0;
  config_t *c = NULL;

  c = config_alloc();
  if (c == NULL) {
     printf("config: out of memory\n");
     return NULL;
  }

  ret = config_begin_read(c, filename);
  if (!ret) {
     config_kill(c);
//     printf("config: error: failure\n");
     return NULL;
  }

  while(1) {
    ret = config_parse_includes(c);
    if (ret == 2) {
       config_kill(c);
       printf("config: error: failure\n");
       return NULL;
    }

    if (ret == 0)
       break;
  }

  if (c->flags & CF_COMMENT) {
     config_kill(c);
     printf("config: line %lu: error: syntax error: comment runs past EOF\n", c->line);
     return NULL;
  }

  return c;
}

void config_kill(config_t *c)
{
   if (c == NULL)
	  return;

  if (c->filename)
     free(c->filename);

  if (c->labels)
     config_label_kill(c);

  free(c);
}

int config_wait(char *filename)
{
  int ret = 0;
  char tries = 0;
  struct stat st;

  tries = 0;

  for (tries = 0; tries < 60; tries++) {
      ret = stat(filename, &st);
      if (ret == -1)
         return 0;

      /*
         Wait for sticky bit to clear
      */
      if (st.st_mode & S_ISVTX) {
         sleep(2);
         continue;
      }

      else
         break;
  }

  if (tries == 60)
     return 0;

  return 1;
}

int config_begin_read(config_t *c, char *filename)
{
  int ret = 0;
  char b[255] = { 0 };
  FILE *stream = NULL;

  if (c == NULL)
	 return 0;

  if (c->filename) {
     free(c->filename);
     c->filename = NULL;
  }

  memset(b, 0, 255);

  ret = config_fullpath(filename, b, sizeof(b));
  if (!ret)
     return 0;

  c->filename = (char *)malloc(strlen(b) + 1);
  if (c->filename == NULL) {
     printf("config: out of memory\n");
     return 0;
  }

  memset(c->filename, 0, strlen(b) + 1);
  memcpy(c->filename, b, strlen(b));

  ret = config_wait(b);
  if (!ret) {
//     printf("config: couldnt access %s\n", b);
     return 0;
  }

  stream = fopen(b, "r");
  if (stream == NULL) {
     printf("config: cannot open %s for read\n", b);
     return 0;
  }

#ifdef CONFIG_DEBUG
  printf("config: reading %s\n", b);
#endif

  ret = config_contents(c, stream);
  if (!ret) {
     printf("config: failed reading contents of %s\n", filename);
     return 0;
  }

  fclose(stream);

  return 1;
}

void config_label_kill(config_t *c)
{
  config_label_t *l = NULL, *ol = NULL;

  if (c == NULL)
	 return;

  l = c->labels;
  while(l) {
    ol = l;
    l = l->next;

    if (ol->atoms)
       config_atom_kill(ol);

    if (ol->name)
       free(ol->name);

    if (ol->filename)
       free(ol->filename);

    free(ol);
  }
}

void config_atom_kill(config_label_t *l)
{
  config_atom_t *a = NULL, *ao = NULL;

  if (l == NULL)
	 return;

  a = l->atoms;

  while(a) {
    ao = a;
    a = a->next;

    if (ao->name)
       free(ao->name);

    if (ao->data)
       free(ao->data);

    free(ao);
  }
}

config_t *config_alloc(void)
{
  config_t *c = NULL;

  c = (config_t *)malloc(sizeof(config_t));
  if (c == NULL)
     return NULL;

  memset(c, 0, sizeof(config_t));
  
  return c;  
}

config_label_t *config_label_alloc(void)
{
  config_label_t *l = NULL;

  l = (config_label_t *)malloc(sizeof(config_label_t));
  if (l == NULL)
     return NULL;

  memset(l, 0, sizeof(config_label_t));
 
  return l;
}

config_atom_t *config_atom_alloc(void)
{
  config_atom_t *a = NULL;

  a = (config_atom_t *)malloc(sizeof(config_atom_t));
  if (a == NULL)
     return NULL;

  memset(a, 0, sizeof(config_atom_t));
  
  return a;
}

void config_atom_free(config_atom_t *a)
{
   if (a == NULL)
	  return;

  if (a->name)
     free(a->name);
 
  if (a->data)
     free(a->data);

  free(a);
}

/*
   Creates a full path string inside buf from filename argument
*/
int config_fullpath(const char *filename, char *buf, size_t size)
{
  int len = 0;
  char cwd[255] = { 0 }, *p = NULL;

  if (*filename == '/') {
     len = strlen(filename);
     if (len >= size)
        len = (size - 1);

     memcpy(buf, filename, len);

     return 1;
  }

  p = getcwd(cwd, sizeof(cwd) - 1);
  if (p == NULL) {
     printf("config: error: cannot get current working directory\n");
     return 0;
  }

  len = strlen(cwd);
  if ((len + strlen(filename)) >= (size - 1))
     return 0;

  snprintf(buf, size - 1, "%s/%s", cwd, filename);

  return 1;
}

int config_contents(config_t *c, FILE *stream)
{
  int ret = 0;
  char b[CONFIG_MAX_LINE] = { 0 }, *p = NULL;

  if (c == NULL)
	 return 0;

  c->line = 0;

  while(1) {
    memset(b, 0, sizeof(b));
    fgets(b, sizeof(b) - 1, stream);

    if (feof(stream))
       break;

    c->line++;

    for (p = b; *p; p++) {
        if ((*p == '\n') || (*p == '\r'))
           break;
    }

    if ((*p != '\n') && (*p != '\r')) {
       printf("config: line %lu: error: syntax error: line too long\n", c->line);
       return 0;
    }

    *p = '\0';

    if (!(*b))
       continue;

    ret = config_parse(c, b);
    if (!ret)
       return 0;
  }

  return 1;
}

/*
   Main parser function that calls the
   rest to get the job done.
*/
int config_parse(config_t *c, char *data)
{
  int ret = 0;
  char *p = NULL;

  config_remove_comments(c, data);

  if (!(*data))
     return 1;

#ifdef CONFIG_DEBUG
  printf("config: line %lu: parse: [%s]\n", c->line, data);
#endif

  /*
     Wrapped from previous line
     (entire line is label data)
  */
  if ((*data == ' ') || (*data == '\t')) {
     if (c->labels == NULL) {
        printf("config: line %lu: error: syntax error (wrapping without a label)\n", c->line);
        return 0;
     }

     while((*data == ' ') || (*data == '\t'))
        data++;

     if (!(*data))
        return 1;

     ret = config_parse_label(c, NULL, data);
  }

  /*
     Seperate label name, from label data
  */
  else {
     p = config_next_token(data, ':');
     if (p == NULL) {
        printf("config: line %lu: error: syntax error: invalid label declaration\n", c->line);
        return 0;
     }
   
     *p++ = '\0';

     if (!(*data)) {
        printf("config: line %lu: error: syntax error: empty label name\n", c->line);
        return 0;
     }

     while((*p == ' ') || (*p == '\t'))
       p++;

     ret = config_parse_label(c, data, p);
  }

  return ret;
}

/*
   Remove comments from a string
   If the entire string is part of a comment, the first
   byte is set to NULL.

   Examines:
       Da{ Comment }ta
       Data // Comment

   Modifies to:
       Data       
*/
void config_remove_comments(config_t *c, char *data)
{
  int len = 0;
  char *h = NULL, *t = NULL, *p = NULL, *s = NULL;

  if (c == NULL)
	 return;

  t = NULL;
  s = p = data;
  len = strlen(data);

  while(1) {
    if (!(c->flags & CF_COMMENT)) {
       t = config_next_token(s, '/');
       if (t == NULL)
          return;

       if (*(t + 1) == '/') {
          *t = '\0';
          return;
       }

       else if (*(t + 1) == '*') {
          p = (t + 2);
          c->flags |= CF_COMMENT;
       }

       else
          s = (t + 1);
    }

    else {
       h = config_next_token(p, '*');
       if (h == NULL) {
          *data = '\0';
          return;
       }

       if (*(h + 1) == '/') {
          if (t == NULL)
             t = p;

          memcpy(t, h + 2, len - (h - t));
          *(data + (len - (h - t))) = '\0';

          c->flags &= ~CF_COMMENT;
          continue;
       }

       p = (h + 2);
    }
  }
}

/*
   Given an optional label name, and label data, parse
   and add to the configuration linked list.

   The label name is optional, because, if it's NULL,
   this means we're adding to the last entry in the linked list
   for wrapping.

   Examines (labeldata):
      Blahblah; Blah=Blah; Doof; Doof=Doofdoof; etc; etc;
      
*/
int config_parse_label(config_t *c, char *newlabel, char *labeldata)
{
  int ret = 0;
  config_label_t *l = NULL;
  char *h = NULL, *t = NULL, *p = NULL;

  if (c == NULL)
	 return 0;

  /*
     Allocate the label, set it inside the linked list,
     and set the label tail accordingly
  */
  if (newlabel) {
     l = config_label_alloc();
     if (l == NULL) {
        printf("config: out of memory\n");
        return 0;
     }
  }

  else
     l = c->ltail;

  if (l == NULL) {
     printf("config: line %lu: syntax error: no label for wrapping\n", c->line);
     return 0;
  }

  if (newlabel) {
     l->name = config_convert_literal(newlabel);
     if (l->name == NULL) {
        printf("config: line %lu: config_convert_literal failed\n", c->line);
        return 0;
     }

     l->filename = (char *)malloc(strlen(c->filename) + 1);
     if (l->filename == NULL) {
        printf("config: out of memory\n");
        return 0;
     }

     memset(l->filename, 0, strlen(c->filename) + 1);
     memcpy(l->filename, c->filename, strlen(c->filename));
  
     l->line = c->line;

     if (c->ltail) {
        c->ltail->next = l;
        c->ltail = l;
     }
  }

  if (c->labels == NULL)
     c->labels = c->ltail = l;

  /*
     Parse the label data
  */
  h = t = labeldata;

  for (p = config_next_token(h, ';'); p; p = config_next_token(h, ';')) {
      *p++ = '\0';
      h = p;

      while((*t == ' ') || (*t == '\t'))
         t++;

      ret = config_parse_label_atom(c, l, t);
      if (!ret)
         return 0;

      t = p;
  }

  for (t = h; *t; t++) {
      if ((*t != ' ') && (*t != '\t')) {
         printf("config: line %lu: syntax error: no terminating semi-colon\n", c->line);
         return 0;
      }
  }

  return 1;
}

/*
   Create an atom link based on atom data for a label

   Examines:
     Name=Data
     Data
*/
int config_parse_label_atom(config_t *c, config_label_t *l, char *data)
{
  config_atom_t *a = NULL;
  char *p = NULL, *aname = NULL, *adata = NULL, *t = NULL;

  if ((c == NULL) || (l == NULL))
	 return 0;

  a = config_atom_alloc();
  if (a == NULL) {
     printf("config: out of memory\n");
     return 0;
  }

  aname = adata = NULL;

  /*
     See if we have a name value
  */
  p = config_next_token(data, '=');
  if (p) {
     for (t = (p - 1); ((*t == ' ') || (*t == '\t')); t--)
         *t = '\0';

     *p++ = '\0';

     while((*p == ' ') || (*p == '\t'))
       p++;

     if (!(*data)) {
        printf("config: line %lu: syntax error: empty atom name\n", c->line);
        return 0;
     }


     aname = data;
     adata = p;
  }

  else
     adata = data;

  if (aname) {
     a->name = config_convert_literal(aname);    
     if (a->name == NULL) {
        printf("config: line %lu: config_convert_literal failed\n", c->line);
        return 0;
     }
  }

  if (*adata) {
     a->data = config_convert_literal(adata);
     if (a->data == NULL) {
        printf("config: line %lu: config_convert_literal failed\n", c->line);
        return 0;
     }
  }

  else {
     a->data = (char *)malloc(1);
     if (a->data == NULL) {
        printf("config: out of memory\n");
        return 0;
     }

     *(a->data) = '\0';
  }

  if (!(*a->data)) {
     if ((a->name == NULL) || ((a->name) && (!(*a->name)))) {
//	printf("config: line %lu: warning: empty label atom data\n", c->line);
        config_atom_free(a);
        return 1;
     }
  }

  a->line = c->line;

  if (l->atoms == NULL)
     l->atoms = l->atail = a;

  else {
     l->atail->next = a;
     l->atail = a;
  }

  return 1;
}

/*
   Return a configuration by label name, and atom name
*/
char *config_fetch_by_name(config_t *c, char *label, char *aname)
{
  config_label_t *l = NULL;
  config_atom_t *a = NULL;

  if (c == NULL)
	 return NULL;

  if (c->labels == NULL)
     return NULL;

  for (l = c->labels; l; l = l->next) {
      if (!(strcasecmp(l->name, label))) {
         if (l->atoms == NULL)
            continue;

         for (a = l->atoms; a; a = a->next) {
             if (a->name == NULL)
                continue;

             if (!(strcasecmp(a->name, aname)))
                return a->data;
         }
      }
  }

  return NULL;
}

/*
   Returns a configuration by label name, and atom number
*/
char *config_fetch_by_num(config_t *c, char *label, int num)
{  
  int cur = 0;
  config_label_t *l = NULL;
  config_atom_t *a = NULL;

  if (c == NULL)
	 return NULL;

  if (c->labels == NULL)
     return NULL;

  for (l = c->labels; l; l = l->next) {
      if (!(strcasecmp(l->name, label))) {
         if (l->atoms == NULL)
            continue;

         for (cur = 1, a = l->atoms; a; a = a->next, cur++) {
             if (cur == num)
                return a->data;
         }
      }
  }

  return NULL;
}

int config_parse_includes(config_t *c)
{
  int ret = 0;
  config_label_t *l = NULL;
  config_atom_t *a = NULL;

  if (c == NULL)
	 return 0;

  if (c->labels == NULL)
     return 0;

  for (l = c->labels; l; l = l->next) {
      if (!(strcasecmp(l->name, "include"))) {
         if (l->atoms == NULL)
            continue;

         for (a = l->atoms; a; a = a->next) {
             if (a->data) {
                if (!(a->flags & CAF_IGNORE)) {
                   ret = config_begin_read(c, a->data);
                   if (!ret)
                      return 2;

                   a->flags |= CAF_IGNORE;

                   return 1;
                }
             }
         }
      }
  }

  return 0;
}

/*
   Find the next occurance of a token in a string
   Takes into account literals and escaped characters
*/
char *config_next_token(char *str, char c)
{
  char *p = NULL, esc = 0, lit = 0;

  esc = lit = 0;

  for (p = str; *p; p++) {
      /*
         If we're in escape mode, ignore the current
         character, unset escape mode, and move on
      */
      if (esc) {
         esc = 0;
         continue;
      }

      /*
         If we're not in literal mode,
         and we see a backslash, go into escape mode.
      */
      if ((*p == '\\') && (!lit)) {
         esc = 1;
         continue;
      }

      /*
         If we find a quote character, set or unset
         literal mode
      */
      if (*p == '\"') {
         lit = !lit;
         continue;
      }

      /*
         If in literal mode, ignore tokens
      */
      if (lit)
         continue;

      /*
         Points to current token
      */
      if (*p == c)
         break;
  }

  if ((lit) || (esc)) {
     printf("config: warning: syntax error: unterminated literal\n");
     return NULL;
  }

  if (!(*p))
     return NULL;

  return p;
}

/*
   Given a string,
   convert all escapings and literals

   Allocates required space
*/
char *config_convert_literal(char *str)
{
  int len = 0;
  char *p = NULL, *r = NULL, lit = 0, esc = 0, *rp = NULL, byte = 0,
	*t = NULL;

  len = 0;
  esc = lit = 0;

  for (p = str; *p; p++) {
      /*
         If we're in escape mode, ignore the current
         character, unset escape mode, and move on
      */
      if (esc) {
         esc = 0;
         len++; 
         continue;
      }

      /*
         If we're not in literal mode,
         and we see a backslash, go into escape mode.
      */
      if ((*p == '\\') && (!lit)) {
         if ((*(p + 1) >= '0') && (*(p + 1) <= '9')) {
            len++;

            for (t = ++p;;) {
                if ((!(*p)) || ((*p < '0') || (*p > '9')))
                   break;

                else
                   p++;
            }

            if (!(*p))
               break;

	    p--;
            continue;
         }

         else {
            esc = 1;
            continue;
         }
      }

      /*
         If we find a quote character, set or unset
         literal mode
      */
      if (*p == '\"') {
         lit = !lit;
         continue;
      }

      len++;
  }

  r = (char *)malloc(len + 1);
  if (r == NULL) {
     printf("config: config_convert_literal: out of memory\n");
     return NULL;
  }

  memset(r, 0, len + 1);

  rp = r;
  esc = lit = 0;

  for (p = str; *p; p++) {
      /*
         If we're in escape mode, ignore the current
         character, unset escape mode, and move on
      */
      if (esc) {
         esc = 0;
         *rp++ = *p;

         continue;
      }

      /*
         If we're not in literal mode,
         and we see a backslash, go into escape mode.
      */
      if ((*p == '\\') && (!lit)) {
         if ((*(p + 1) >= '0') && (*(p + 1) <= '9')) {
            for (t = ++p;;) {
                if ((!(*p)) || ((*p < '0') || (*p > '9'))) {
                   byte = *p;
                   *p = '\0';
                   *rp++ = atoi(t);
                   *p = byte;

                   break;
                }

                else
                   p++;
            }

            if (!(*p))
               break;

	    p--;
            continue;
         }

         else {
           esc = 1;
           continue;
         }
      }

      /*
         If we find a quote character, set or unset
         literal mode
      */
      if (*p == '\"') {
         lit = !lit;
         continue;
      }

      *rp++ = *p;
  }

  if ((lit) || (esc)) {
     printf("config: error: syntax error: unterminated literal\n");
     return NULL;     
  }

  return r;
}

/*
   Set ltail to reference a label for quick
   config_fetch()
*/
int config_reference(config_t *c, char *label)
{
  config_label_t *l = NULL;

  if (c == NULL)
	 return 0;

  for (l = c->labels; l; l = l->next) {
      if (!(strcasecmp(l->name, label))) {
         c->ltail = l;
         return 1;
      }
  }

  c->ltail = NULL;

  return 0;
}

/*
   Return atoms from previous set reference
   with config_reference_label()
*/
char *config_fetch(config_t *c, char *name)
{
  config_atom_t *a = NULL;

  if (c == NULL)
	 return NULL;

  if (c->ltail == NULL)
     return NULL;

  for (a = c->ltail->atoms; a; a = a->next) {
      if (!(a->flags & CAF_IGNORE)) {
         if (!(strcasecmp(a->name, name)))
            return a->data;
      }
  }

  return NULL;
}

/*
   Find the next label with the same name currently pointed
   to by ltail
*/
int config_next_reference(config_t *c)
{
  char *lname = NULL;
  config_label_t *l = NULL;

  if (c == NULL)
	 return 0;

  if (c->ltail == NULL)
     return 0;

  lname = c->ltail->name;

  for (l = c->ltail->next; l; l = l->next) {
      if (!(strcasecmp(l->name, lname))) {
         c->ltail = l;
         return 1;
      }
  }

  c->ltail = NULL;
  return 0;
}
