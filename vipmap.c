/*
 * $Id: vipmap.c 1014 2011-02-03 16:04:37Z volz0r $
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
#include <memory.h>
#include <string.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

void usage();
void get_options(int argc,char **argv);

int Action;
char Ip[MAX_BUFF];
char Domain[MAX_BUFF];

#define PRINT_IT  0
#define ADD_IT    1
#define DELETE_IT 2

int main(int argc, char *argv[])
{
#ifdef IP_ALIAS_DOMAINS
 int result;
 int first;
#endif

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

	get_options(argc,argv);

#ifdef IP_ALIAS_DOMAINS
	switch(Action) {
	  case ADD_IT:
	  	result = vadd_ip_map(Ip, Domain);
	  	break;
	  case DELETE_IT:
	  	result = vdel_ip_map(Ip, Domain);
	  	break;
	  case PRINT_IT:
	  	first = 1;
	  	while( (result=vshow_ip_map( first, Ip, Domain)) == 1 ) {
			first = 0;
			printf("%s %s\n", Ip, Domain);
		}
	  	break;
	  default:
	  	usage();
		vexit(-1);
	  	break;
	}
#else
    printf("IP aliases are not compiled into vpopmail\n");
    printf("You will need to do the following steps\n");
    printf("make distclean\n");
    printf("./configure --enable-ip-alias-domains=y [your other options]\n");
    printf("make\n");
    printf("make install-strip\n");
#endif

	return(vexit(0));
}

void usage()
{
	printf("vipmap: usage: [options] ip domain\n"); 
	printf("options: -d delete mapping\n"); 
	printf("         -a add mapping\n"); 
	printf("         -p print mapping\n"); 
	printf("         -v show version\n"); 

}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;

	Action = PRINT_IT;
	memset( Ip, 0, sizeof(Ip));
	memset( Domain, 0, sizeof(Ip));

	errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"vpda")) != -1 ) {
		switch(c) {
			case 'v':
				printf("version: %s\n", VERSION);
				break;
			case 'p':
				Action = PRINT_IT;
				break;
			case 'a':
				Action = ADD_IT;
				break;
			case 'd':
				Action = DELETE_IT;
				break;
			default:
				errflag = 1;
				break;
		}
	}

	if ( argc <= 1 ) {
		usage();
		vexit(-1);
	}

	if ( Action == ADD_IT || Action == DELETE_IT ) {
		if ( optind < argc ) {
			snprintf(Ip, sizeof(Ip), "%s", argv[optind]);
			++optind;
		} else {
			usage();
			vexit(-1);
		}

		if ( optind < argc ) {
			snprintf(Domain, sizeof(Domain), "%s", argv[optind]);
			++optind;
		} else {
			usage();
			vexit(-1);
		}
	}
}
