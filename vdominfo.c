/*
 * $Id: vdominfo.c 1015 2011-02-03 16:33:39Z volz0r $
 * Copyright (C) 2001-2009 Inter7 Internet Technologies, Inc.
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
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"


char Domain[MAX_BUFF];
char RealDomain[MAX_BUFF];
char Dir[MAX_BUFF];
uid_t Uid;
gid_t Gid;

int DisplayName;
int DisplayUid;
int DisplayGid;
int DisplayDir;
int DisplayAll;
int DisplayTotalUsers;
int DisplayRealDomain;

void usage();
void get_options(int argc, char **argv);
void display_domain(char *domain, char *dir, uid_t uid, gid_t gid, char *realdomain);
void display_all_domains();
void display_one_domain( char * Domain );

#define TOKENS ":\n"

extern vdir_type vdir;

int main(int argc, char *argv[])
{
    if( vauth_open( 0 )) {
        vexiterror( stderr, "Initial open." );
    }

    get_options(argc,argv);

    /* did we want to view a single domain domain? */
    if (Domain[0] != 0 ) {
        /* yes, just lookup a single domain */
        display_one_domain( Domain );
    } else {
        display_all_domains();
    }
    return(vexit(0));
}

void usage()
{
    printf("vdominfo: usage: [options] [domain]\n");
    printf("options: -v (print version number)\n");
    printf("         -a (display all fields, this is the default)\n");
    printf("         -n (display domain name)\n");
    printf("         -u (display uid field)\n");
    printf("         -g (display gid field)\n");
    printf("         -d (display domain directory)\n");
    printf("         -t (display total users)\n");
    printf("         -r (display real domain)\n");
}

void get_options(int argc, char **argv)
{
 int c;
 int errflag;
 extern int optind;

    DisplayName = 0;
    DisplayUid = 0;
    DisplayGid = 0;
    DisplayDir = 0;
    DisplayTotalUsers = 0;
    DisplayAll = 1;
	DisplayRealDomain = 0;

    memset(Domain, 0, sizeof(Domain));

    errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"vanugdtr")) != -1 ) {
        switch(c) {
            case 'v':
                printf("version: %s\n", VERSION);
                break;
            case 'n':
                DisplayName = 1;    
                DisplayAll = 0;
                break;
            case 'u':
                DisplayUid = 1;    
                DisplayAll = 0;
                break;
            case 'g':
                DisplayGid = 1;    
                DisplayAll = 0;
                break;
            case 'd':
                DisplayDir = 1;    
                DisplayAll = 0;
                break;
            case 't':
                DisplayTotalUsers = 1;    
                DisplayAll = 0;
                break;
            case 'a':
                DisplayAll = 1;
                break;
            case 'r':
                DisplayRealDomain = 1;
				DisplayAll = 0;
                break;
            default:
                errflag = 1;
                break;
        }
    }

    if ( errflag > 0 ) {
        usage();
        vexit(-1);
    }

    if ( optind < argc ) {
	snprintf(Domain, sizeof(Domain), "%s", argv[optind]); 
        ++optind;
    }
}

void display_domain(char *domain, char *dir, uid_t uid, gid_t gid, char *realdomain)
{
    if ( DisplayAll ) {
        if(strcmp(domain, realdomain)==0)
            printf("domain: %s\n", domain);
        else
           printf("domain: %s (alias of %s)\n", domain, realdomain); 
        printf("uid:    %lu\n", (long unsigned)uid);
        printf("gid:    %lu\n", (long unsigned)gid);
        printf("dir:    %s\n",  dir);
        open_big_dir(realdomain, uid, gid);
        printf("users:  %lu\n",  vdir.cur_users);
        close_big_dir(realdomain,uid,gid);
    } else {
        if ( DisplayName ) {
          if(strcmp(domain, realdomain)==0)
            printf("%s\n", domain);
          else
            printf("%s (alias of %s)\n", domain, realdomain);
        }
        if ( DisplayUid ) printf("%lu\n", (long unsigned)uid);
        if ( DisplayGid ) printf("%lu\n", (long unsigned)gid);
        if ( DisplayDir ) printf("%s\n",  dir);
        if ( DisplayTotalUsers ) {
            open_big_dir(realdomain, uid, gid);
            printf("%lu\n",  vdir.cur_users);
            close_big_dir(realdomain,uid,gid);
        }

		if ( DisplayRealDomain ) printf("%s\n", realdomain);
    }
}

void display_all_domains()
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
	display_domain(entry->domain, entry->path, entry->uid, 
                       entry->gid, entry->realdomain);

	printf ("\n");
        entry = get_domain_entries(NULL);
    }
}

void display_one_domain( char * Domain )
{
 domain_entry *entry;
 string_list aliases;
 int  i;

    entry = get_domain_entries( Domain );
    if (entry==NULL) {
      if( verrori ) {
        printf("Can't get domain entries - %s\n", verror( verrori ));
        vexit(verrori);
      } else {
        printf("Invalid domain name\n");
        vexit(VA_DOMAIN_DOES_NOT_EXIST);
      }
    }

    string_list_init(&aliases, 10);

    while( entry ) {
	if (strcmp(entry->domain, entry->realdomain) != 0) {
// 		printf ("Note:   %s is an alias for %s\n",
//                         entry->domain, entry->realdomain);
                string_list_add(&aliases, entry->domain);

        } else {
		display_domain(entry->domain, entry->path, entry->uid, 
        	               entry->gid, entry->realdomain);
	}

        entry = get_domain_entries(NULL);
    }

    for(i=0;i<aliases.count;i++) {
 	printf ("alias: %s\n", aliases.values[i]);
    } 
    string_list_free(&aliases);
}

