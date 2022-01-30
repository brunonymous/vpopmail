/*
 * $Id: vaddaliasdomain.c 1014 2011-02-03 16:04:37Z volz0r $
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
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"


char Domain_a[MAX_BUFF];
char Domain_b[MAX_BUFF];

void usage();
void get_options(int argc,char **argv);

int main(int argc, char *argv[])
{
    int err;
    char *doma;
    char *domb;

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

    get_options(argc,argv);

    /* see if Domain_a or Domain_b exist */
    /* Also, if domain is an alias, convert it to the real domain */ 
    doma = vget_assign(Domain_a, NULL, 0, NULL, NULL);
    domb = vget_assign(Domain_b, NULL, 0, NULL, NULL);

    /* Check if both domains exists */
    if ((doma != NULL) && (domb != NULL))
    {
        printf("Error: Both domains already exist, unable to create alias.\n");
        vexit(-1);
    }
    
    /* Check if none of the domains exists */
    if ((doma == NULL) && (domb == NULL))
    {
        printf("Error: Neither '%s' or '%s'  exist, unable to create alias.\n", Domain_a, Domain_b);
        vexit(-1);
    }
    
    if (doma != NULL)  /* alias Domain_b to real Domain_a */
        err = vaddaliasdomain(Domain_b, Domain_a);
    else               /* alias Domain_a to real Domain_b */
        err = vaddaliasdomain(Domain_a, Domain_b);
    
    if ( err != VA_SUCCESS ) {
        printf("Error: %s\n", verror(err));
        vexit(err);
    }
    return(vexit(0));
}

void usage()
{
    printf("vaddaliasdomain: usage: [options] real_domain alias_domain\n");
    printf("options: -v (print version number)\n");
    printf("note: for backward compatability, you can swap real_domain and alias_domain.\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;

    memset(Domain_a, 0, sizeof(Domain_a));
    memset(Domain_b, 0, sizeof(Domain_b));

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

    if ( optind < argc ) { 
    snprintf(Domain_a, sizeof(Domain_a), "%s", argv[optind]);
        ++optind;
    }

    if ( optind < argc ) {
    snprintf(Domain_b, sizeof(Domain_b), "%s", argv[optind]);
        ++optind;
    }

    if ( Domain_b[0] == 0 || Domain_a[0] == 0 ) { 
        usage();
        vexit(-1);
    }

    if ( strcmp( Domain_a, Domain_b ) == 0 ) {
        printf("Error: real domain and alias domain are the same!\n");
        usage();
        vexit(-1);
    }
}
