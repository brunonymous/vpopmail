/*
 * $Id: vdeldomain.c 1015 2011-02-03 16:33:39Z volz0r $
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

int force=0;

char Domain[MAX_BUFF];

void usage();
void get_options(int argc,char **argv);

int main(int argc, char *argv[])
{
 int err=0;

 domain_entry *entry;
 string_list aliases;
 char parent[MAX_BUFF];
 int  i, doit=1;

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

	get_options(argc,argv);

	entry = get_domain_entries( Domain );
	if (entry==NULL) {
		if( verrori ) {
			printf("Error: Can't get domain entries - %s\n", verror( verrori ));
			vexit(verrori);
		} else {
			printf("Error: Domain does not exist\n");
			vexit(VA_DOMAIN_DOES_NOT_EXIST);
		}
	}

	string_list_init(&aliases, 10);

	while( entry ) {
		if (strcmp(entry->domain, entry->realdomain) != 0) {
			string_list_add(&aliases, entry->domain);
		} else {
			snprintf(parent,sizeof(parent),"%s",entry->domain);
		}

		entry = get_domain_entries(NULL);
	}

	if( aliases.count > 0 && 0 == strncmp(Domain,parent,MAX_BUFF)) {  
		//  Have aliases
		if( force ) {
			printf("Warning: Alias domains deleted:\n");
		} else {
			printf("Warning: Alias domains exist:\n");
			doit=0;
		}

		for(i=0;i<aliases.count;i++) {
			printf ("   %s\n", aliases.values[i]);
		} 
	}

	string_list_free(&aliases);

        if( doit ) {
	if ( (err=vdeldomain(Domain)) != VA_SUCCESS) {
		printf("Error: %s\n", verror(err));
	}
	} else {
		printf("   use -f to force delete of domain and all aliases\n");
	}
	return(vexit(err));
}


void usage()
{
	printf("vdeldomain: usage: [options] domain_name\n");
	printf("options: -v (print version number)\n");
	printf("options: -f (force delete of virtual domains)\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;

	memset(Domain, 0, sizeof(Domain));

	errflag = 0;
	while( !errflag && (c=getopt(argc,argv,"vf")) != -1 ) {
		switch(c) {
			case 'v':
				printf("version: %s\n", VERSION);
				break;
			case 'f':
				force=1;
				break;
			default:
				errflag = 1;
				break;
		}
	}

	if ( optind < argc ) {
		snprintf(Domain, sizeof(Domain), "%s", argv[optind]);
		++optind;
	} else {
		usage();
		vexit(0);
	}
}
