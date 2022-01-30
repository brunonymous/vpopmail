/*
 * $Id: vmkpasswd.c 1014 2011-02-03 16:04:37Z volz0r $
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

char Domain[MAX_BUFF];

void usage();

int main(int argc, char *argv[])
{
#ifdef USE_CDB
 int i;

	if ( argc != 2 ) {  
		usage();
		vexit(-1);
	}

	memset(Domain, 0, sizeof(Domain));

	for(i=1;i<argc;++i){
		if ( Domain[0] == 0 ) {
			snprintf(Domain, sizeof(Domain), "%s", argv[i]);
		}
	}
	lowerit(Domain);
	return(vmkpasswd( Domain ));
#else
	usage();
	return(vexit(0));
#endif

}

void usage()
{
#ifdef USE_CDB
	printf("vmkpasswd: usage: domain \n");
#else
	printf("vmkpasswd: is only needed by the cdb authentication module\n"); 
#endif
}
