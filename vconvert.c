/*
 * $Id: vconvert.c 1014 2011-02-03 16:04:37Z volz0r $
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
#include <pwd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#include "vmysql.h"


#ifdef HAS_SHADOW
#include <shadow.h>
#endif

int do_all_domains();

char User[MAX_BUFF];
char Passwd[MAX_BUFF];
char Gecos[MAX_BUFF];
char Dir[MAX_BUFF];

#define MYSQL_SITE_ARG "-m"
#define CDB_SITE_ARG   "-c"
#define ETC_SITE_ARG   "-e"
#define ETC_FILE_ARG   "-f"
#define PASSWD_FILE_ARG "-p"

#define MYSQL_SITE     1
#define CDB_SITE       2
#define ETC_SITE       3
#define PASSWD_SITE    4
#define SQWEBMAIL_SITE 5

#define FORMAT_NOFORMAT 0 
#define FORMAT_USERPASS 1 

#define PASSWD_TOKENS " :\n\t"

int FromFormat;
int ToFormat;
int Debug;

int conv_domain( char *); 

int set_sqwebmail_pass( char *);
int cdb_to_default( char *);
int sql_to_cdb( char *);
int etc_to_default( char *);
void usage();
void get_options(int argc, char **argv);
int passwd_to_vpopmail( char *domain );

char PasswdFile[MAX_BUFF];
int  PasswdFormat;

int main(int argc, char *argv[])
{
	if( vauth_open( 1 )) {
		vexiterror( stderr, "Initial open." );
	}

	get_options(argc,argv);

	if ( optind == argc ) {
		do_all_domains();
	} else {
		for(;optind<argc;++optind){
			printf("converting %s ", argv[optind]);
			lowerit(argv[optind]);
			if ( conv_domain( argv[optind] ) != 0 ) {
				printf("domain conversion failed\n");
				/* should exit -1 here? */
			} else {
				printf("done\n");
			}
		}
	}
	return(vexit(0));
}

int do_all_domains()
{
 domain_entry *e;

    e = get_domain_entries("");
    while( e ) {
 
        if( strcmp( e->realdomain, e->domain ) != 0 ) {  //  is an alias
           printf( "%s is an alias of %s.\n", 
                   e->domain, e->realdomain );
        } else {
            printf( "converting %s...    ", e->realdomain );

            if ( conv_domain( e->realdomain ) != 0 ) {
                printf("domain conversion failed\n");
                /* should vexit -1 here? */
            } else {
                printf("done\n");
            }
        }

        e = get_domain_entries( NULL );
    }

    return(0);
}


int conv_domain( char *domain )
{

	switch ( FromFormat ) {
		case SQWEBMAIL_SITE:
			return(set_sqwebmail_pass( domain));
			break;
		case MYSQL_SITE:
			switch (ToFormat) {
				case CDB_SITE:
					return(sql_to_cdb( domain));
				default:
					printf("unknown conversion\n");
					return(-1);
			}
			break;
		case CDB_SITE:
			return(cdb_to_default( domain));
			break;
		case ETC_SITE:
			switch ( ToFormat ) {
				case MYSQL_SITE: 
					return(etc_to_default( domain));
				case CDB_SITE:
					return(etc_to_default( domain ));
				default:
					printf("unknown conversion\n");
					return(-1);
			}
			break;
		case PASSWD_SITE:
			return( passwd_to_vpopmail( domain ));
		default: 
			printf("unknown converstion\n");
			return(-1);
	}
	printf(".");
}

int cdb_to_default( char *domain )
{
#ifdef USE_SQL
 FILE *fs;
 char tmpbuf[MAX_BUFF];
 struct vqpasswd *pw;

 int domain_str_len = strlen( domain );
 char domain_dir[MAX_BUFF];
 FILE *assign_fs;
 static char assignbuf[MAX_BUFF];
 int i, colon_count, dir_count;
 int bFoundDomain = 0;
 char assign_file[MAX_BUFF];
 uid_t uid;
 gid_t gid;

    snprintf(assign_file, sizeof(assign_file), "%s/users/assign",  QMAILDIR);      
    if ( (assign_fs=fopen(assign_file, "r"))==NULL ) {
       snprintf(tmpbuf, sizeof(tmpbuf), "could not open qmail assign file at %s\n", assign_file);
       perror(tmpbuf);
       return(-1);
    }
    while ( fgets(assignbuf, sizeof(assignbuf), assign_fs) != NULL && !bFoundDomain )
    {
	/* search for the matching domain record */
	if ( strncmp( domain, &assignbuf[1], domain_str_len ) == 0 )
	{
		bFoundDomain = 1;

		/* found match, now get directory */
		for ( i=1, colon_count = 0;
		      colon_count < 4;
		      colon_count++, i++ )
		{
			for( ; 
			     assignbuf[i]!=':';
			     ++i )
				; /* skip non-colon characters */
		}
	
		/* found 4th colon, so get the directory name */
		for( dir_count = 0; 
		     assignbuf[i]!=':';
		     ++i, dir_count++ )
		{
			domain_dir[dir_count] = assignbuf[i];
		}
		domain_dir[dir_count] = 0;  /* null termination */
	}
    }
    
    fclose(assign_fs);

    vauth_deldomain(domain);
    vdel_dir_control(domain);
    vauth_adddomain(domain);

    vget_assign(domain, Dir, sizeof(Dir), &uid, &gid );
#ifdef USERS_BIG_DIR
    open_big_dir (domain, uid, gid);
#endif
    snprintf(tmpbuf, sizeof(tmpbuf), "%s/vpasswd", Dir);
    fs = fopen(tmpbuf,"r");
    if ( fs == NULL ) return(-1);

    while( (pw=vgetent(fs)) != NULL ) {
      if (vauth_adduser(pw->pw_name, domain, pw->pw_passwd, 
                        pw->pw_gecos, pw->pw_dir, pw->pw_uid) != 0) {
        printf("User %s domain %s did not add\n", pw->pw_name, domain);
        continue;
      }
      vauth_setpw(pw, domain);
#ifdef USERS_BIG_DIR
      next_big_dir (uid, gid);  /* increment user count */
#endif
    }
    fclose(fs);
#ifdef USERS_BIG_DIR
    close_big_dir (domain, uid, gid);
#endif
#endif /* USE_SQL */
    return(0);
}

int sql_to_cdb( char *domain)
{
#ifdef USE_SQL
 struct vqpasswd *pw;
 FILE *fs;
 char tmpbuf[MAX_BUFF];

        if (vget_assign(domain, Dir, sizeof(Dir), NULL, NULL ) == NULL) {
		printf("Error. Domain not found\n");
		return (-1);
	}
	snprintf(tmpbuf, sizeof(tmpbuf), "%s/vpasswd", Dir);
	if ( (fs = fopen(tmpbuf,"w")) == NULL ) {
		printf("could not open vpasswd file %s\n", tmpbuf);
		return(-1);
	}
	pw = vauth_getall(domain, 1, 1);
	while( pw != NULL ) {
#ifdef CLEAR_PASS
		fprintf(fs, "%s:%s:%d:%d:%s:%s:%s:%s\n",
			pw->pw_name,
			pw->pw_passwd,
			pw->pw_uid,
			pw->pw_gid,
			pw->pw_gecos,
			pw->pw_dir,
			pw->pw_shell,
			pw->pw_clear_passwd);
#else /* CLEAR_PASS */ 
		fprintf(fs, "%s:%s:%d:%d:%s:%s:%s\n", 
			pw->pw_name,
			pw->pw_passwd,
			pw->pw_uid,
			pw->pw_gid,
			pw->pw_gecos,
			pw->pw_dir,
			pw->pw_shell);
#endif /* CLEAR_PASS */
		pw = vauth_getall(domain, 0, 1);
	}
	fclose(fs);
	printf("%s done\n", domain);
#endif /* USE_SQL */
	return(0);
}

int etc_to_default( char *domain )
{
 struct passwd *mypw;
 struct vqpasswd *newpw = NULL;
 char *passwd;
 int i;
#ifdef HAS_SHADOW
 struct spwd *smypw;
#endif

	while( (mypw = getpwent()) != NULL ) {
#ifdef HAS_SHADOW
		if ( (smypw = getspnam(mypw->pw_name)) == NULL) continue;
		i = strlen(smypw->sp_pwdp)+1;
		passwd = malloc(i);
		snprintf( passwd, i, "%s", smypw->sp_pwdp );
#else
		i = strlen(mypw->pw_passwd)+1;
		passwd = malloc(i);
		snprintf( passwd, i, "%s", mypw->pw_passwd );
#endif
		if ( strlen(passwd) > 2 ) {
			if (vadduser( mypw->pw_name, domain, "xxxx", 
				mypw->pw_gecos, USE_POP) != 0) {
				printf("user %s domain %s did not add\n", 
					mypw->pw_name, domain);
				continue;
			}
			newpw = vauth_getpw( mypw->pw_name, domain);
			newpw->pw_passwd = passwd;
			vauth_setpw( newpw, domain);
		} else {
			printf("skipping %s\n", mypw->pw_name);
		}
		free(passwd);
	}
	return(0);
}

void usage()
{
	fprintf(stdout, "vconvert: usage\n");
	fprintf(stdout, " The first option sets which format to convert FROM,\n");
	fprintf(stdout, " the second option sets which format to convert TO.\n");
	fprintf(stdout, " -e = etc format\n"); 
	fprintf(stdout, " -c = cdb format\n"); 
	fprintf(stdout, " -m = sql format\n"); 
	fprintf(stdout, " -S = set sqwebmail passwords\n"); 
	fprintf(stdout, " -v = version\n"); 
	fprintf(stdout, " -d = debug info\n"); 
	/*
	fprintf(stdout, " [-f file] lets you override /etc/passwd as the\n"); 
	fprintf(stdout, " default file to use for -e option\n"); 
	*/

}

void get_options(int argc, char **argv)
{
 int c;
 int errflag;

	errflag = 0;
	FromFormat = -1;
	ToFormat = -1;
	PasswdFile[0] = 0;
	PasswdFormat = 0;
	Debug = 0;

	while( !errflag && (c=getopt(argc,argv,"mcep:Svd")) != -1 ) {
		switch(c) {
			case 'd':
				Debug = 1;
				break;
			case 'v':
				printf("version: %s\n", VERSION);
				break;
			case 'S':
				FromFormat = SQWEBMAIL_SITE;
				ToFormat = SQWEBMAIL_SITE;
				break;
			case 'm':
				if ( FromFormat == -1 ) FromFormat = MYSQL_SITE;
				else ToFormat = MYSQL_SITE;
				break;
			case 'c':
				if ( FromFormat == -1 ) FromFormat = CDB_SITE;
				else ToFormat = CDB_SITE;
				break;
			case 'e':
				if ( FromFormat == -1 ) FromFormat = ETC_SITE;
				else ToFormat = ETC_SITE;
				break;
			case 'p':
				if ( FromFormat == -1 ) FromFormat = PASSWD_SITE;
				else ToFormat = PASSWD_SITE;
				PasswdFormat = FORMAT_USERPASS;
				snprintf(PasswdFile, sizeof(PasswdFile), "%s", optarg);
				break;
			default:
				errflag = 1;
				break;
		}
	}
	if ( FromFormat == -1 || ToFormat == -1 || errflag > 0 ) {
		usage();
		vexit(-1);
	}
}

int passwd_to_vpopmail( char *domain )
{
 FILE *fs,*fs1;
 char tmpbuf[MAX_BUFF];
 char tmpbuf1[MAX_BUFF];
 char *user;
 char *crypted_passwd;
 struct vqpasswd *mypw;
 int err = 0;


	if ( (fs=fopen(PasswdFile, "r")) == NULL) {
		printf("Could not open passwd file %s\n", PasswdFile);
		perror("fopen");
		return(-1);
	}

	while( fgets(tmpbuf, sizeof(tmpbuf), fs) != NULL ) {
		if ( (user=strtok(tmpbuf, PASSWD_TOKENS))==NULL) continue;
		if ( (crypted_passwd=strtok(NULL, PASSWD_TOKENS))==NULL) continue;
		snprintf(Gecos, sizeof(Gecos), "%s", user);

	    if ( (err=vadduser(user, domain, "foob", user, USE_POP )) < 0 ) {
	        printf("Error: %s\n", verror(err));
			break;
		}

		if ( (mypw = vauth_getpw( user, domain )) == NULL ) {
			printf("no such user %s@%s\n", user, domain);
			break;
		}

		mypw->pw_passwd = crypted_passwd;
		if ( (err=vauth_setpw( mypw, domain )) != 0 ) {
			printf("Error: %s\n", verror(err));
			break;
		}
		snprintf(tmpbuf1, sizeof(tmpbuf1), 
                    "%s/Maildir/sqwebmail-pass", mypw->pw_dir);
		if ( (fs1=fopen(tmpbuf1, "w")) == NULL) {
			break;
		}
		fprintf(fs1, "\t%s", crypted_passwd);
		fclose(fs1);

	}
	fclose(fs);
	return(err);
}

int set_sqwebmail_pass( char *domain)
{
 struct vqpasswd *pw;

	if ( Debug == 1 ) {
		printf("Setting sqwebmail passwords for %s\n", domain);
	}

	pw = vauth_getall(domain, 1, 0);
	while( pw != NULL ) {
		if ( Debug == 1 ) {
			printf("%s\n", pw->pw_name);
		}
    		vsqwebmail_pass( pw->pw_dir, pw->pw_passwd, 
			VPOPMAILUID, VPOPMAILGID);
		pw = vauth_getall(domain, 0, 0);
	}
	return(0);
}

