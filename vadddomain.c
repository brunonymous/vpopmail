/*
 * $Id: vadddomain.c 1014 2011-02-03 16:04:37Z volz0r $
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
char Passwd[MAX_BUFF];
char User[MAX_BUFF];
char Dir[MAX_BUFF];
char Quota[MAX_BUFF];
char BounceEmail[MAX_BUFF];

int  Apop;
int  Bounce;
int  RandomPw;
uid_t Uid;
gid_t Gid;

void usage();
void get_options(int argc, char **argv);

int main(int argc, char *argv[])
{
 int err;
 FILE *fs;

 char a_dir[MAX_BUFF];
 uid_t a_uid;
 gid_t a_gid;

 char TmpBuf1[MAX_BUFF];
 
    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

    get_options(argc,argv);

    /* create the domain */
    if ( (err=vadddomain(Domain,Dir,Uid,Gid)) != VA_SUCCESS ) {
        printf("Error: %s\n", verror(err));
        vexit(err);
    }

    /* create the postmaster account on the domain */
    if ((err=vadduser("postmaster", Domain, Passwd, "Postmaster", Apop )) != 
        VA_SUCCESS ) {
        printf("Error: (vadduser) %s\n", verror(err));
        vexit(err);
    }

    /* set the quota (if one has been nominated) */
    if ( Quota[0] != 0 ) {
        if ((err=vsetuserquota("postmaster", Domain, Quota )) != VA_SUCCESS)
        {
          printf("Error: %s\n", verror(err));
          vexit(err);
        } 
    }

    /* if a catchall has been chosen,
     * then create an appropriate .qmail-default file
     */
    if ( BounceEmail[0] != 0 ) {
        vget_assign(Domain, a_dir, sizeof(a_dir), &a_uid, &a_gid );
        snprintf(TmpBuf1, sizeof(TmpBuf1), "%s/.qmail-default", a_dir);
        if ( (fs = fopen(TmpBuf1, "w+"))!=NULL) {

            /* if catchall address is an email address... */
            if ( strstr(BounceEmail, "@") != NULL ) { 
                fprintf(fs, "| %s/bin/vdelivermail '' %s\n", VPOPMAILDIR, 
                    BounceEmail);
            /* No '@' - so assume catchall is a mailbox name */
            } else {
                fprintf(fs, "| %s/bin/vdelivermail '' %s/%s\n", VPOPMAILDIR,
                    a_dir, BounceEmail);
            }

            fclose(fs);
            chown(TmpBuf1, a_uid, a_gid);

        } else {
            printf("Error: could not open %s\n", TmpBuf1);
            vexit(-1);
        }
    }
    if ( RandomPw == 1 ) printf("Random password: %s\n", Passwd );
    
    return(vexit(0));
}

void usage()
{
	printf("vadddomain: usage: vadddomain [options] virtual_domain [postmaster password]\n");
	printf("options: -v prints the version\n");
	printf("         -q quota_in_bytes (sets the quota for postmaster account)\n");
	printf("         -b (bounces all mail that doesn't match a user, default)\n");
	printf("         -e email_address (forwards all non matching user to this address [*])\n");
	printf("         -u user (sets the uid/gid based on a user in /etc/passwd)\n");
	printf("         -d dir (sets the dir to use for this domain)\n");
	printf("         -i uid (sets the uid to use for this domain)\n");
	printf("         -g gid (sets the gid to use for this domain)\n");
	printf("         -O optimize adding, for bulk adds set this for all\n");
	printf("            except the last one\n");
	printf("         -r[len] (generate a len (default 8) char random postmaster password)\n");
	printf("\n");
	printf(" [*] omit @-sign to deliver directly into user's Maildir: '-e postmaster'\n");
        printf("\n");
        printf("Special bounce messages supported by vdeliver mail:\n");
        printf("   vadddomain -b delete example.com [password]  -  delete all mail to non-existant accounts\n");
        printf("   vadddomain -b bounce-no-mailbox example.com [password] - bounce them \n");
        printf("   vadddimain -b someone@somewhere.com example.com [password] - sent to another address\n");
        printf("   vadddomain -b /path/to/Maildir example.com [password] - sent to a Maildir\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;
 struct passwd *mypw;
 extern char *optarg;
 extern int optind;

    memset(Domain, 0, sizeof(Domain));
    memset(Passwd, 0, sizeof(Passwd));
    memset(User, 0, sizeof(User));
    memset(Quota, 0, sizeof(Quota));
    memset(Dir, 0, sizeof(Dir));
    memset(BounceEmail, 0, sizeof(BounceEmail));

    Uid = VPOPMAILUID;
    Gid = VPOPMAILGID;

    Apop = USE_POP;
    Bounce = 1;
    RandomPw = 0;

    /* grab the options */
    errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"q:be:u:vi:g:d:Or::")) != -1 ) {
	switch(c) {
	case 'v':
	    printf("version: %s\n", VERSION);
	    break;
	case 'd':
	    snprintf(Dir, sizeof(Dir), "%s", optarg);
	    break;
	case 'u':
	    snprintf(User, sizeof(User), "%s", optarg);
	    break;
	case 'q':
	    snprintf(Quota, sizeof(Quota), "%s", optarg);
	    break;
	case 'e':
	    snprintf(BounceEmail, sizeof(BounceEmail), "%s", optarg);
	    break;
	case 'i':
	    Uid = atoi(optarg);
	    break;
	case 'g':
	    Gid = atoi(optarg);
	    break;
	case 'b':
	    Bounce = 1;
	    break;
	case 'O':
            OptimizeAddDomain = 1;
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

    /* if a user account has been nominated... */
    if ( User[0] != 0 ) {
        if ( (mypw = getpwnam(User)) != NULL ) {
            /* if a home dir hasnt been specified,
             * use the one from the etc/passwd file
             */
            if ( Dir[0] == 0 ) {
		snprintf(Dir, sizeof(Dir), "%s", mypw->pw_dir);
            }
            /* Grab the uid/gid from the etc/passwd file */
            Uid = mypw->pw_uid;
            Gid = mypw->pw_gid;
        } else {
            printf("Error: user %s not found in /etc/passwd\n", User);
            vexit(-1);
        }
    }

    /* if a home dir hasnt been chosen, default to the vpopmail dir */
    if ( Dir[0] == 0 ) {
	snprintf(Dir, sizeof(Dir), "%s", VPOPMAILDIR);
    }

    /* Grab the domain */
    if ( optind < argc ) {
	snprintf(Domain, sizeof(Domain), "%s", argv[optind]);
	++optind;
    } else {
      /* if no domain has been chosen, then display usage and exit*/
      usage();
      vexit(0);
    }

    /*  If it already exists, don't waste time entering the password  */
    if( vget_assign(Domain, NULL, 0, NULL, NULL ) != NULL ) {
       printf("Error: %s\n", verror( VA_DOMAIN_ALREADY_EXISTS ));
       vexit( VA_DOMAIN_ALREADY_EXISTS );
    }

    /* Grab the postmaster password */
    if ( optind < argc ) {
	snprintf(Passwd, sizeof(Passwd), "%s", argv[optind]);
	++optind;
    } else if (!RandomPw) {
      /* if no postmaster password specified, then prompt user to enter one */
	vgetpasswd("postmaster", Passwd, sizeof(Passwd));
    }
}
