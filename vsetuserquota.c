/*
 * $Id: vsetuserquota.c 1014 2011-02-03 16:04:37Z volz0r $
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
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"


char Email[MAX_BUFF];
char Quota[MAX_BUFF];

void get_options(int argc,char **argv);
void usage();

int main(int argc, char *argv[])
{
 int i;
 int ret;
 static int virgin;
 struct vqpasswd *mypw;

 char User[MAX_BUFF];
 char Domain[MAX_BUFF];

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

	get_options(argc,argv);

	/* Michael Bowe 13th Aug 2003
         * Mmmm, isnt this code redundant? Already in get_options
         *
	*for(i=1;i<argc;++i){
	*	if ( Email[0] == 0 ) {
	*		strncpy( Email, argv[i], MAX_BUFF-1);
	*	} else {
	*		strncpy( Quota, argv[i], MAX_BUFF-1);
	*	}
	*}
	 */

	/* check to see if email address has an @ sign in it */
	if ( strstr(Email, "@") == NULL ) {
		/* user has nominated a domain name rather than an email address */
		snprintf(Domain, sizeof(Domain), "%s", Email);

		virgin = 1;
                /* Check to see if domain exists */
  		if ( vget_assign(Domain, NULL, 0, NULL, NULL)==NULL) {
			printf("Error: %s\n", verror(VA_DOMAIN_DOES_NOT_EXIST));
   			vexit(VA_DOMAIN_DOES_NOT_EXIST);
		}

		/* walk through the whole domain */
		while( (mypw=vauth_getall(Domain, virgin, 1)) != NULL ) {
			virgin = 0;
			if ((ret = vsetuserquota( mypw->pw_name, Domain, Quota )) != VA_SUCCESS) {
			printf("Error: %s\n", verror(ret));
			vexit(ret);
			}
		}

	/* just a single user */
	} else {
		/* Extract the user and domain from the Email address */
                if ((i= parse_email( Email, User, Domain, sizeof(Email))) != 0 ) {
                    printf("Error: %s\n", verror(i));
                    vexit(i);
                }
		/* Check to see if the domain exists */
  		if ( vget_assign(Domain, NULL, 0, NULL, NULL)==NULL) {
			printf("Error: %s\n", verror(VA_DOMAIN_DOES_NOT_EXIST));
   			vexit(VA_DOMAIN_DOES_NOT_EXIST);
		}
		/* Set the quota for the user */
		if ((ret = vsetuserquota( User, Domain, Quota )) != VA_SUCCESS) {
			printf("Error: %s\n", verror(ret));
			vexit(ret);
			}
	}
	return(vexit(0));

}

void usage()
{
	printf("vsetuserquota: [options] email_address|domain_name quota\n"); 
	printf("options:\n");
	printf("-v (print version number)\n");
        printf("\nIf you specify a domain name rather than an email address,\n");
        printf("the quota will be applied to all users in that domain\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;

    memset(Email, 0, sizeof(Email));
    memset(Quota, 0, sizeof(Quota));

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

	/* Grab the email|domain */
	if ( optind < argc ) {
		snprintf(Email, sizeof(Email), "%s", argv[optind]);
		++optind;
	}

        /* Grab the quota */
	if ( optind < argc ) {
		snprintf(Quota, sizeof(Quota), "%s", argv[optind]);
		for(c=0;Quota[c]!=0;++c){
			if ( islower((int)Quota[c]) ) {
				Quota[c] = (char)toupper((int)Quota[c]);
			}
		}
		++optind;
	}

	if ( Email[0] == 0 || Quota[0] == 0 ) { 
		usage();
		vexit(-1);
	}
}
