/*
 * $Id: vkill.c 1014 2011-02-03 16:04:37Z volz0r $
 * Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
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
#include <unistd.h>
#include <signal.h>
#include <memory.h>
#include <string.h>
#include "config.h"
#include "vpopmail.h"

char ProcessName[MAX_BUFF];

void usage();
void get_options(int argc,char **argv);

int main(int argc,char **argv)
{
  get_options(argc,argv);
  signal_process(ProcessName,  SIGKILL);
  return(0);
}


void usage()
{
  printf( "vkill: usage: process\n");
  printf("options: -v (print the version)\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;
 extern int optind;

  memset(ProcessName, 0, sizeof(ProcessName));

  errflag = 0;
  while( !errflag && (c=getopt(argc,argv,"v")) != -1 ) {
    switch(c) {
      case 'v':
        printf("version: %s\n", VERSION);
        break;
      default:
        errflag = 1;
        break;
    }
  }

  if ( optind < argc  ) {
    snprintf(ProcessName, sizeof(ProcessName), "%s", argv[optind]);
    ++optind;
  }

  if ( ProcessName[0] == 0 || errflag == 1 ) { 
    usage();
    vexit(-1);
  }
}
