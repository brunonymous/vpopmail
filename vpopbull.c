/*
 * $Id: vpopbull.c 1014 2011-02-03 16:04:37Z volz0r $
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
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"


#define MSG_BUF_SIZE  32768
#define TOKENS ":\r\n"

static char EmailFile[MAX_BUFF];
static char CurDir[MAX_BUFF];
static char ExcludeFile[MAX_BUFF];
static char Domain[MAX_BUFF];
static char TmpBuf[MAX_BUFF];

static char MsgBuf[MSG_BUF_SIZE];

static int Verbose;
static int DoNothing;

#define COPY_IT          0
#define HARD_LINK_IT     1
#define SYMBOLIC_LINK_IT 2

static int DeliveryMethod = COPY_IT;
int InsertDate = 1;
int EmailFileFlag = 0;
int ExcludeFileFlag = 0;

int process_domain(char *,  FILE *, FILE *);
int copy_email( FILE *, char *, char *, struct vqpasswd *);
int in_exclude_list( FILE *, char *, char *);
void get_options(int argc,char **argv);
void usage();

int main(int argc, char *argv[])
{
 FILE *fsi = NULL;
 FILE *fsx = NULL;
 char *domain;
 char *domain_dir = NULL;
 static struct stat statbuf;
 domain_entry *entry;

  memset(TmpBuf,0,sizeof(TmpBuf));
  memset(MsgBuf,0,sizeof(MsgBuf));

  Verbose = 0;
  DoNothing = 0;

  if ( argc == 1 ) {
    usage();
    vexit(-1);
  }

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

  get_options(argc,argv);

  getcwd(CurDir,sizeof(CurDir));

  if ( EmailFileFlag == 1 ) {
    if ( (fsi = fopen(EmailFile, "r")) == NULL ) {
        fprintf(stderr, "Could not open file %s\n", EmailFile);
        vexit(-1);
    } else {
        /* make sure the file size is not 0 */
        stat(EmailFile, &statbuf);
        if(statbuf.st_size == 0) {
            fprintf(stderr, "Error: %s is empty\n", EmailFile);
            vexit(-1);
        }
        /* check for existing date header */
        while (fgets (TmpBuf, sizeof(TmpBuf), fsi) != NULL) {
            /* check for end of headers (blank line) */
            if (*TmpBuf == '\n') break;

            if (strncasecmp ("Date: ", TmpBuf, 6) == 0) {
                InsertDate = 0;
                break;
            }
        }
        rewind(fsi);
    }
  } else if (! DoNothing) {
    /* require -f [email_file] */
    fprintf(stderr, "Error: email_file not specified\n");
    usage();
    vexit(-1);
  }

  if ( ExcludeFileFlag == 1 ) {
    if ( (fsx = fopen(ExcludeFile, "r")) == NULL ) {
        fprintf(stderr, "Could not open file %s\n", ExcludeFile);
        vexit(-1);
    }
  }

  if (( EmailFile[0] != 0 || DoNothing == 1) && Domain[0] != 0 ) {

    /* Process list of domains */
    domain = strtok(Domain, " ");
    while (domain != NULL ) {
        if((vget_assign(domain, domain_dir, sizeof(domain_dir), NULL, NULL)) != NULL) {
            process_domain(domain,  fsi, fsx );
        } else {
            fprintf(stderr, "Error: domain %s does not exist\n", domain);
        }
        domain = strtok(NULL, " ");
    }
    vexit(0);

  } else if ( (EmailFile[0] != 0 || DoNothing == 1)  && Domain[0] == 0 ) {

    entry = get_domain_entries( "" );
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
      if (strcmp (entry->domain, entry->realdomain) != 0) {
        if (Verbose) {
          fprintf (stderr, "skipping %s (alias of %s)\n", 
                   entry->domain, entry->realdomain);
        }
      } else {
        chdir(entry->path);
        process_domain(entry->realdomain,  fsi, fsx );
      }
    entry = get_domain_entries(NULL);
    }
  }
  return(vexit(0));

}

int process_domain(domain, fsi, fsx )
 char *domain;
 FILE *fsi;
 FILE *fsx;
{
 char filename[MAX_BUFF];
 char hostname[MAX_BUFF];
 static struct vqpasswd *pwent;
 time_t tm;
 int pid;
 int first = 1;

	gethostname(hostname,sizeof(hostname));
	pid=getpid();
	time (&tm);
	snprintf(filename, sizeof(filename), "%lu.%lu.%s",(long unsigned)tm,
		(long unsigned)pid,hostname);

	first = 1;
	while( (pwent = vauth_getall(domain, first, 1)) != NULL )  {
		first = 0;

		if ( !in_exclude_list( fsx, domain, pwent->pw_name) ) {
			if (DoNothing) {
				printf("%s@%s\n", pwent->pw_name, domain);
			} else {
				if(copy_email( fsi, filename, domain, pwent) != 0) {
					fprintf(stderr, "%s@%s: ERROR COPYING TO %s\n", pwent->pw_name, 
						domain, pwent->pw_dir);
				} else if (Verbose) {
					printf("%s@%s\n", pwent->pw_name, domain);
                		}
			}
		}
	}	
	return(0);
}

int copy_email( fs_file, filename, domain, pwent)
 FILE *fs_file;
 char *filename;
 char *domain;
 struct vqpasswd *pwent;
{
 static char tmpbuf[MAX_BUFF];
 static char tmpbuf1[MAX_BUFF];
 FILE *fs;
 int count;
 struct stat mystatbuf;
 uid_t uid;
 gid_t gid;

    /* At this point, we know that the user exists in the auth backend.
     * Now we need to run some other checks before we can copy the
     * bulletin into their maildir...
     */

    /* test to see if the user has been allocated a userdir yet.
     * Some of the auth backends (eg MySQL) allow users to be inserted
     * into authsystem while leaving their dir blank. The idea here is
     * that this information will get allocated/updated the first time
     * the user does an AUTH or receives a msg.
     */

    if ( pwent->pw_dir == NULL || pwent->pw_dir[0]==0 ) {

       /* A dir hasnt been allocated to this user yet.
        * Try and allocate one now
        */

       /* retrieve the domain's uid/gid
        * (required for the call to make_user_dir()
        */
        if (vget_assign(domain, NULL, 0, &uid, &gid) == NULL) {
            fprintf(stderr, "Failed to vget_assign() for %s\n", domain);
            return (-1);
        }

        if ( make_user_dir(pwent->pw_name, domain, uid, gid) == NULL) {
            fprintf(stderr, "Auto creation of maildir failed for %s@%s\n", pwent->pw_name, domain);
            return(-1);
        }

        /* Re-read pwent, because we need to lookup the newly created
         * pw_dir entry
         */
        if ((pwent=vauth_getpw(pwent->pw_name, domain)) == NULL ) {
           fprintf(stderr, "Failed to vauth_getpw() for %s@%s\n", pwent->pw_name, domain);
           return(-1);
        }
    }

    /* At this point, a dir must have been allocated to the user
     * in the auth backend. So the next thing to do is test to see
     * if the dir exists on the filesystem or not. If the dir doesnt
     * exist, then we will try and create it
     */ 
    if ( stat(pwent->pw_dir, &mystatbuf ) == -1 ) {
        if ( vmake_maildir(domain, pwent->pw_dir )!= VA_SUCCESS ) {
            fprintf(stderr, "Auto creation of maildir failed for %s@%s\n", pwent->pw_name, domain);
            return(-1);
        }
    }

	snprintf(tmpbuf, sizeof(tmpbuf), "%s/Maildir/new/%s", pwent->pw_dir, filename );
	
	if ( DeliveryMethod == COPY_IT ) {
		rewind(fs_file);
		if ( (fs = fopen(tmpbuf, "w+")) == NULL ) {
			return(-1);
		}
		fprintf(fs, "To: %s@%s\n", pwent->pw_name, domain); 
		if (InsertDate) fprintf(fs, "%s", date_header());
	
		while((count=fread(MsgBuf,sizeof(char),MSG_BUF_SIZE,fs_file)) 
				!= 0 ) {
			fwrite( MsgBuf, sizeof(char), count, fs );
		}
		fclose(fs);
	} else if ( DeliveryMethod == HARD_LINK_IT ) {
		if (*EmailFile == '/')
			snprintf(tmpbuf1, sizeof(tmpbuf1), "%s", EmailFile);
		else
			snprintf(tmpbuf1, sizeof(tmpbuf1), "%s/%s", CurDir, EmailFile);
		if ( link( tmpbuf1, tmpbuf) < 0 ) {
			perror("link");
		}
	} else if ( DeliveryMethod == SYMBOLIC_LINK_IT ) {
		if (*EmailFile == '/')
			snprintf(tmpbuf1, sizeof(tmpbuf1), "%s", EmailFile);
		else
			snprintf(tmpbuf1, sizeof(tmpbuf1), "%s/%s", CurDir, EmailFile);
		if ( symlink( tmpbuf1, tmpbuf) < 0 ) {
			perror("symlink");
		}
	} else {
		fprintf(stderr, "no delivery method set\n");
		return -1;
	}
	/* fix permissions */
	chown(tmpbuf, VPOPMAILUID, VPOPMAILGID);
	chmod(tmpbuf, 0600);
	return(0);
}

int in_exclude_list( FILE *fsx, char *domain, char *user )
{
 static char tmpbuf[MAX_BUFF];
 static char emailaddr[MAX_BUFF];
 int  i;

	if ( fsx == NULL ) {
		return(0);
	}
	rewind(fsx);

	snprintf(emailaddr, sizeof(emailaddr), "%s@%s", user, domain);

	while (fgets(tmpbuf, sizeof(tmpbuf), fsx) != NULL) {
		for(i=0;tmpbuf[i]!=0;++i) if (tmpbuf[i]=='\n') tmpbuf[i]=0;
		if ( strcmp( tmpbuf, emailaddr ) == 0 ) {
			return(1);
		}	
	}
	return(0);
}

void get_options(int argc, char **argv)
{
 int n = 0;
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;

    memset(Domain, 0, sizeof(Domain));
    memset(EmailFile, 0, sizeof(EmailFile));
    memset(ExcludeFile, 0, sizeof(ExcludeFile));

    errflag = 0;
    EmailFileFlag = 0;
    ExcludeFileFlag = 0;
    while( !errflag && (c=getopt(argc,argv,"Vvcshnf:e:")) != -1 ) {
        switch(c) {
            case 'v':
                printf("version: %s\n", VERSION);
                break;
            case 'V':
                Verbose = 1;
                break;
            case 's':
                DeliveryMethod = SYMBOLIC_LINK_IT; 
                break;
            case 'c':
                DeliveryMethod = COPY_IT; 
                break;
            case 'f':
                EmailFileFlag = 1;
		snprintf(EmailFile, sizeof(EmailFile), "%s", optarg);
                break;
            case 'e':
                ExcludeFileFlag = 1;
		snprintf(ExcludeFile, sizeof(ExcludeFile), "%s", optarg);
                break;
            case 'h':
                DeliveryMethod = HARD_LINK_IT; 
                break;
            case 'n':
                DoNothing = 1;
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

    n = 0;
    while ( optind < argc ) { 
        if((n=1)) strncat(Domain, " ", sizeof(Domain)-strlen(Domain)-1);
        strncat(Domain, argv[optind], sizeof(Domain)-strlen(Domain)-1);
        n = 1;
        ++optind;
    }
}

void usage()
{
	printf("usage: vpopbull [options] -f [email_file] [virtual_domain] [...]\n");
	printf("       -v (print version number)\n");
	printf("       -V (verbose)\n");
	printf("       -f email_file (file with message contents)\n");
	printf("       -e exclude_email_addr_file (list of addresses to exclude)\n");
	printf("       -n (don't mail. Use with -V to list accounts)\n");
	printf("       -c (default, copy file)\n"); 
	printf("       -h (use hard links)\n"); 
	printf("       -s (use symbolic links)\n"); 
}
