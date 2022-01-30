/*
 * $Id: vmoduser.c 1014 2011-02-03 16:04:37Z volz0r $
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
char Gecos[MAX_BUFF];
char Dir[MAX_BUFF];
char Passwd[MAX_BUFF];
char Quota[MAX_BUFF];
char Crypted[MAX_BUFF];

int GidFlag = 0;
int QuotaFlag = 0;
int ClearFlags;

void usage();
void get_options(int argc,char **argv);

int main(int argc, char *argv[])
{
 int i; 
 static int virgin = 1;
 struct vqpasswd *mypw;
 char User[MAX_BUFF];
 char Domain[MAX_BUFF];

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

    get_options(argc,argv);

    /* a single email address */
    if ( strstr(Email, "@") != NULL ) {
        if ( (i = parse_email( Email, User, Domain, MAX_BUFF)) != 0 ) {
            printf("Error: %s\n", verror(i));
            vexit(i);
        }

        if ( (mypw = vauth_getpw( User, Domain )) == NULL ) {
            printf("no such user %s@%s\n", User, Domain);
            vexit(-1);
        }
        
        if ( Gecos[0] != 0 ) mypw->pw_gecos = Gecos;
        if ( Dir[0] != 0 ) mypw->pw_dir = Dir;
        if ( Passwd[0] != 0 )  {
            mkpasswd3(Passwd,Crypted, 100);
            mypw->pw_passwd = Crypted;
#ifdef CLEAR_PASS
            mypw->pw_clear_passwd = Passwd;
#endif
        } else if ( Crypted[0] != 0 ) {
            mypw->pw_passwd = Crypted;
        }
        if ( ClearFlags == 1 ) mypw->pw_gid = 0; 
        if ( GidFlag != 0 ) mypw->pw_gid |= GidFlag; 
        if ( QuotaFlag == 1 ) {
            mypw->pw_shell = Quota;
            update_maildirsize(Domain, mypw->pw_dir, Quota);
        }
        if ( (i=vauth_setpw( mypw, Domain )) != 0 ) {
            printf("Error: %s\n", verror(i));
            vexit(i);
        }
    } else {
        virgin = 1;
        while( (mypw=vauth_getall(Email, virgin, 0)) != NULL ) {
            virgin = 0;

            if ( Gecos[0] != 0 ) mypw->pw_gecos = Gecos;
            if ( Dir[0] != 0 ) mypw->pw_dir = Dir;
            if ( Passwd[0] != 0 )  {
                mkpasswd3(Passwd,Crypted, 100);
                mypw->pw_passwd = Crypted;
#ifdef CLEAR_PASS
                mypw->pw_clear_passwd = Passwd;
#endif
            } else if ( Crypted[0] != 0 ) {
                mypw->pw_passwd = Crypted;
            }
            if ( ClearFlags == 1 ) mypw->pw_gid = 0; 
            if ( GidFlag != 0 ) mypw->pw_gid |= GidFlag; 
            if ( QuotaFlag == 1 ) {
                mypw->pw_shell = Quota;
                update_maildirsize(Domain, mypw->pw_dir, Quota);
            }
            if ( (i=vauth_setpw( mypw, Email )) != 0 ) {
                printf("Error: %s\n", verror(i));
                vexit(i);
            }
        }
    }
    return(vexit(0));

}

void usage()
{
    printf( "vmoduser: usage: [options] email_addr or domain (for each user in domain)\n");
    printf("options: -v ( display the vpopmail version number )\n");
    printf("         -n ( don't rebuild the vpasswd.cdb file )\n");
    printf("         -q quota ( set quota )\n");
    printf("         -c comment (set the comment/gecos field )\n");
    printf("         -e encrypted_passwd (set the password field )\n");
    printf("         -C clear_text_passwd (set the password field )\n");
    printf("the following options are bit flags in the gid int field\n");
    printf("         -x ( clear all flags )\n");
    printf("         -d ( don't allow user to change password )\n");
    printf("         -p ( disable POP access )\n");
    printf("         -s ( disable SMTP AUTH access )\n");
    printf("         -w ( disable webmail [IMAP from localhost*] access )\n");
    printf("            ( * full list of webmail server IPs in vchkpw.c )\n");
    printf("         -i ( disable non-webmail IMAP access )\n");
    printf("         -b ( bounce all mail )\n");
    printf("         -o ( user is not subject to domain limits )\n");
    printf("         -r ( disable roaming user/pop-before-smtp )\n");
    printf("         -a ( grant qmailadmin administrator privileges )\n");
    printf("         -S ( grant system administrator privileges - access all domains )\n");
    printf("         -E ( grant expert privileges - edit .qmail files )\n");
    printf("         -f ( disable spamassassin)\n");
    printf("         -F ( delete spam)\n");
    printf("         -m ( disable maildrop)\n");
    printf("  [The following flags aren't used directly by vpopmail but are]\n");
    printf("  [included for other programs that share the user database.]\n");
    printf("         -u ( set no dialup flag )\n");
    printf("         -0 ( set V_USER0 flag )\n"); 
    printf("         -1 ( set V_USER1 flag )\n"); 
    printf("         -2 ( set V_USER2 flag )\n"); 
    printf("         -3 ( set V_USER3 flag )\n"); 

}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;

    memset(Email, 0, sizeof(Email));
    memset(Gecos, 0, sizeof(Gecos));
    memset(Dir, 0, sizeof(Dir));
    memset(Passwd, 0, sizeof(Passwd));
    memset(Crypted, 0, sizeof(Crypted));
    memset(Quota, 0, sizeof(Quota));

    ClearFlags = 0;
    QuotaFlag = 0;
    NoMakeIndex = 0;

    errflag = 0;
    while( (c=getopt(argc,argv,"D:avunxc:q:dpswibro0123he:C:fFSEm")) != -1 ) {
        switch(c) {
            case 'v':
                printf("version: %s\n", VERSION);
                break;
            case 'n':
                NoMakeIndex = 1;
                break;
            case 'x':
                ClearFlags = 1;
                break;
            case 'e':
		snprintf(Crypted, sizeof(Crypted), "%s", optarg);
                break;
            case 'C':
                snprintf(Passwd, sizeof(Passwd), "%s", optarg);
                break;
            case 'D':
		snprintf(Dir, sizeof(Dir), "%s", optarg);
		break;
            case 'c':
		snprintf(Gecos, sizeof(Gecos), "%s", optarg);
                break;
            case 'q':
                QuotaFlag = 1;
                snprintf (Quota, sizeof(Quota), "%s",
			format_maildirquota(optarg));
                break;
            case 'd':
                GidFlag |= NO_PASSWD_CHNG;
                break;
            case 'p':
                GidFlag |= NO_POP;
                break;
            case 's':
                GidFlag |= NO_SMTP;
                break;
            case 'w':
                GidFlag |= NO_WEBMAIL;
                break;
            case 'i':
                GidFlag |= NO_IMAP;
                break;
            case 'b':
                GidFlag |= BOUNCE_MAIL;
                break;
            case 'o':
                GidFlag |= V_OVERRIDE;
                break;
            case 'r':
                GidFlag |= NO_RELAY;
                break;
            case 'u':
                GidFlag |= NO_DIALUP;
                break;
            case '0':
                GidFlag |= V_USER0;
                break;
            case '1':
                GidFlag |= V_USER1;
                break;
            case '2':
                GidFlag |= V_USER2;
                break;
            case '3':
                GidFlag |= V_USER3;
                break;
            case 'a':
                GidFlag |= QA_ADMIN;
                break;
            case 'S':
                if ( getuid()==0 ) GidFlag |= SA_ADMIN;
                break;
            case 'E':
                if ( getuid()==0 ) GidFlag |= SA_EXPERT;
                break;
            case 'f':
                GidFlag |= NO_SPAMASSASSIN;
                break;
            case 'F':
                GidFlag |= DELETE_SPAM;
                break;
            case 'm':
                GidFlag |= NO_MAILDROP;
                break;
            case 'h':
                usage();
                vexit(0);
            default:
                errflag = 1;
                break;
        }
    }

    if ( optind < argc ) {
	snprintf(Email, sizeof(Email), "%s", argv[optind]);
        ++optind;
    }

    if ( Email[0] == 0 ) { 
        usage();
        vexit(-1);
    }
}
