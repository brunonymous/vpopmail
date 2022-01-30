/*
 * $Id: vdeloldusers.c 1014 2011-02-03 16:04:37Z volz0r $
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
#include <time.h>

#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

#ifdef ENABLE_AUTH_LOGGING

#define DEFAULT_AGE  180
#define TOKENS ":\n"

char Domain[MAX_BUFF];
char SqlBuf[MAX_BUFF];
int  Age;
int  EveryDomain;
int  Verbose;
int  Delete;
int  UsersToDelete = 0;

void usage();
void get_options(int argc,char **argv);
void process_all_domains(time_t nowt);
void deloldusers(char *Domain, time_t nowt);

int main(int argc, char *argv[])
{
 time_t nowt;

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

	get_options(argc,argv);

	/* get the time */
	nowt = time(NULL);

	/* subtract the age */
	nowt = nowt - (86400*Age);

    if(EveryDomain == 0) {
        deloldusers(Domain,nowt);
    } else {
        process_all_domains(nowt);
    }

    if( ! UsersToDelete ) {
        printf("no old users found\n");
    }

    if( ! Delete && UsersToDelete) {
        printf(" ** no users were deleted  **\n");
        printf(" ** use -D to delete users **\n");
    }

	return(vexit(0));
}

void usage()
{
	printf("vdeloldusers: usage: [options]\n");
	printf("options: -a age_in_days (will delete accounts older than this date)\n");
	printf("                        (default is 6 months or 180 days)\n");
	printf("         -v (print version number and exit)\n");
	printf("         -d [domain] (process only [domain])\n");
	printf("         -e (process every domain)\n");
    printf("         -D (actually delete users. no users are deleted without this option)\n");
	printf("         -V (verbose -- print old users that will be deleted)\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;

	memset(Domain, 0, sizeof(Domain));
	Age = DEFAULT_AGE;
        EveryDomain = 0;
        Verbose = 0;
        Delete = 0;

	errflag = 0;
	while( !errflag && (c=getopt(argc,argv,"vVDd:a:e")) != -1 ) {
		switch(c) {
			case 'e':
                                EveryDomain = 1;
				break;
			case 'D':
                                Delete = 1;
				break;
			case 'V':
                                Verbose = 1;
				break;
			case 'd':
				snprintf(Domain, sizeof(Domain), "%s", optarg);
                                EveryDomain = 0;
				break;
			case 'a':
				Age = atoi(optarg);
				break;
			case 'v':
				printf("version: %s\n", VERSION);
		        	vexit(-1);
				break;
			default:
				errflag = 1;
				break;
		}
	}

	if (argc <= 1 ) {
		usage();
		vexit(-1);
	}
	if ( ! EveryDomain && strlen(Domain) == 0) {
        printf("error: you must supply either the -e or -d [domain] options\n");
		vexit(-1);
	}
}

void deloldusers(char *Domain, time_t nowt)
{
 time_t mytime;
 static struct vqpasswd *mypw;
 int first = 1;

    while( (mypw = vauth_getall(Domain, first, 0)) != NULL )  {
        first = 0;

        if ( strcmp(mypw->pw_name, "postmaster") == 0 ) {
            if ( Verbose) {
                printf("skipping postmaster@%s\n", Domain);
            }
        } else {
            mytime = vget_lastauth(mypw, Domain);

            if ( mytime != 0 ) {
                if(mytime < nowt) {
                    UsersToDelete = 1;
                    if ( Verbose) {
                        printf("%s@%s\n", mypw->pw_name, Domain);
                    }
                    if( Delete ) {
                        vdeluser(mypw->pw_name, Domain);
                    }
                }
            }
        }
    }       

}

void process_all_domains(time_t nowt)
{
 domain_entry *entry;

    entry = get_domain_entries( Domain );
    if (entry==NULL) {
      if( verrori ) {
        printf("Can't get domain entries - %s\n", verror( verrori ));
        vexit(-1);
      } else {
        printf("What now - %s\n", verror( verrori ));
        vexit(0);
      }
    }

    while( entry ) {
        deloldusers(entry->domain,nowt);
        entry = get_domain_entries(NULL);
    }
}

#else

int main()
{
        printf("auth logging was not enabled, reconfigure with --enable-auth-logging=y\n");
        return(vexit(-1));
}
#endif /* ENABLE_AUTH_LOGGING */
