/*
 * $Id: vadduser.c 1014 2011-02-03 16:04:37Z volz0r $
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

char Email[MAX_BUFF];
char Passwd[MAX_BUFF];
char Quota[MAX_BUFF];
char Gecos[MAX_BUFF];
char Crypted[MAX_BUFF];

int apop;
int RandomPw;
int NoPassword = 0;

void usage();
void get_options(int argc,char **argv);

int main(int argc,char **argv)
{
 int i;
 char User[MAX_BUFF];
 char Domain[MAX_BUFF];
 struct vqpasswd *vpw;

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

    get_options(argc,argv);

    memset (User, 0, sizeof(User));
    memset (Domain, 0, sizeof(Domain));

    /* parse the email address into user and domain
     * If the user didnt specify a domain, the default domain will returned
     */
    if ( (i=parse_email( Email, User, Domain, sizeof(Email))) != 0 ) {
        printf("Error: %s\n", verror(i));
        vexit(i);
    }

    if ( Domain[0] == 0 ) {
      printf("You did not use a full email address for the user name\n");
      printf("Only full email addresses should be used\n");
      vexit(-1);
    }

    //  make sure domain already exists
    if( vget_assign( Domain, NULL, 0, NULL, NULL ) == NULL ) {
        printf( "Error: Domain does not exist\n" );
        vexit(-1);
        }

    //  make sure user does not already exist
    if(( vpw = vauth_getpw( User, Domain )) != NULL ) {
        printf( "Error: User already exists\n" );
        vexit( -1 );
        }

    /* if the comment field is blank, use the user name */
    if ( Gecos[0] == 0 ) {
      snprintf(Gecos, sizeof(Gecos), "%s", User);
    }

    /* get the password if not set on command line */
    if ( (NoPassword == 0) && (*Crypted == '\0') ) {
        if ( *Passwd == '\0' ) {
            /* Prompt the user to enter a password */
	    vgetpasswd(Email, Passwd, sizeof(Passwd));
        }

        if ( *Passwd == '\0' ) {
            printf("Error: No password entered\n");
            usage();
            vexit(-1);
        }
    }

    /* add the user */
    if ( (i=vadduser(User, Domain, Passwd, Gecos, apop )) < 0 ) {
        printf("Error: %s\n", verror(i));
        vexit(i);
    }
    
    /* set the users quota if set on the command line */
    if ( Quota[0] != 0) {
      if (vsetuserquota( User, Domain, Quota ) != 0) {
        printf ("Error in vsetuserquota()\n");
        vexit(-1);
      } 
    }

    /* Check for encrypted password */
    if ( *Crypted != '\0' ) {
        /* User has entered an encrypted password, so store this directly
         * into the auth records for this user
         */
        if(( vpw = vauth_getpw( User,Domain)) == NULL) {
          printf ("Error in vauth_getpw()\n");
          vexit (-1);
        }
        /* Set the crypted pass and get rid of the cleartext pass (if any)
	 * since it won't match the crypted pass. */
        vpw->pw_passwd = Crypted;
        vpw->pw_clear_passwd = "";
        if ( vauth_setpw( vpw, Domain) != 0) {
          printf ("Error in vauth_setpw()\n");
          vexit (-1);
        }
    }

    if ( RandomPw == 1 ) printf("Random password: %s\n", Passwd );

    return(vexit(0));
}


void usage()
{
    printf( "vadduser: usage: [options] email_address [passwd]\n");
    printf("options: -v (print the version)\n");
    printf("         -q quota_in_bytes (sets the users quota, use NOQUOTA for unlimited)\n");
//  printf("         -s (don't rebuild the vpasswd.cdb file, faster for large sites)\n");
    printf("         -c comment (sets the gecos comment field)\n");
    printf("         -e standard_encrypted_password\n");
    printf("         -n no_password\n");
    printf("         -r[len] (generate a len (default 8) char random password)\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;
 
    memset(Email, 0, sizeof(Email));
    memset(Passwd, 0, sizeof(Passwd));
    memset(Quota, 0, sizeof(Quota));
    memset(Gecos, 0, sizeof(Gecos));
    memset(Crypted, 0, sizeof(Crypted));

    apop = USE_POP; 
    RandomPw = 0;

    errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"svc:nq:e:r::")) != -1 ) {
        switch(c) {
          case 'v':
            printf("version: %s\n", VERSION);
            break;
          case 'c':
            snprintf(Gecos, sizeof(Gecos), "%s", optarg);
            break;
          case 'q':
            snprintf(Quota, sizeof(Quota), "%s", optarg);
            break;
          case 'e':
            snprintf(Crypted, sizeof(Crypted), "%s", optarg);
            break;
          case 's':
            fprintf (stderr, "Warning: The -s option has been temporarily disabled.\n");
            /* NoMakeIndex = 1; */
            break;
          case 'n':
            NoPassword = 1;
            break;
          case 'r':
            RandomPw = 1;
            if (optarg)
                vrandom_pass (Passwd, atoi(optarg));
            else
                vrandom_pass (Passwd, 8);
            break;
          default:
            errflag = 1;
            break;
        }
    }

    if ( optind < argc  ) {
	snprintf(Email, sizeof(Email), "%s", argv[optind]);
        ++optind;
    }

    if ( (NoPassword == 0) && (optind < argc) ) {
	snprintf(Passwd, sizeof(Passwd), "%s", argv[optind]);
        ++optind;
    }

    if ( Email[0] == 0 ) { 
        usage();
        vexit(-1);
    }
}
