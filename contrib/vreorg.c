/*
 * vreorg 
 *
 * re-organizes the user directory layout for optimal efficency 
 *
 * part of the vpopmail package
 *
 * Copyright (C) 2001 Inter7 Internet Technologies, Inc.
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
#include "safestring.h"


#define MAX_BUFF 500
char Domain[MAX_BUFF];
char OldDir[MAX_BUFF];
char User[MAX_BUFF];
int  DisplayDebug;
static vdir_type vdir;

char DomainDir[MAX_BUFF];
char TmpBuf[MAX_BUFF];
#define TOKENS " /t/n"

void usage();
void get_options(int argc, char **argv);
int vread_cdb_dir_control(vdir_type *vdir, char *domain);

int main(int argc, char **argv)
{
 FILE *fs;
 int first;
 struct passwd *pw;
 char *tmpstr;
 uid_t uid;
 gid_t gid;
 
    get_options(argc,argv);

    fs = fopen("/usr/tmp/vreorg", "w+");
    if ( fs == NULL ) {
	perror("vreorg:");
	exit(errno);
    }	
    first = 1;
    printf("getting user list\n");
    while( (pw=vauth_getall(Domain, first, 0))){
 	first = 0;
	fprintf(fs, "%s %s %s\n", pw->pw_user, Domain, pw->pw_dir);
    } 
    rewind(fs);
    printf("done.\n");
    vget_assign(Domain, DomainDir, MAX_BUFF, &uid, &gid); 

    /* reset dir control external to this program */
    printf("resetting the directory layout status\n");
    vdel_dir_control(Domain);
    
    printf("working on users\n");
    while ( fgets(TmpBuf, MAX_BUFF, fs) != NULL ) {

	/* user */
	tmpstr = strtok(TmpBuf, TOKENS);
	if ( tmpstr == NULL ) continue;
	strcpy( User, tmpstr);

	/* domain */
	tmpstr = strtok(NULL, TOKENS);
	if ( tmpstr == NULL ) continue;
	strcpy( Domain, tmpstr);

	/* old dir */
	tmpstr = strtok(NULL, TOKENS);
	if ( tmpstr == NULL ) continue;
	strcpy( OldDir, tmpstr);

	/* get next dir */
	open_big_dir(Domain);
    	tmpstr = next_big_dir(uid, gid);
	close_big_dir(Domain, uid, gid); 

	/* get old pw struct */
    	pw = vauth_getpw( User, Domain);

	/* get space for pw_dir */
    	pw->pw_dir = malloc(MAX_BUFF);

	/* format new directory string */
        if ( slen(tmpstr) > 0 ) {
	    sprintf(pw->pw_dir, "%s/%s/%s", DomainDir, tmpstr, User);
	} else {
	    sprintf(pw->pw_dir, "%s/%s", DomainDir, User);
	}
        printf("%s@%s old %s new %s ", User, Domain, OldDir, pw->pw_dir);

	/* update database */
	vauth_setpw( pw, domain );

	/* move directory */
	rename(OldDir, pw->pw_dir);

	/* free directory memory */
	free(pw->pw_dir);
	printf("done\n");

    }
    fclose(fs);
    unlink("/usr/tmp/vreorg");

    exit(0);

}

void usage()
{
	printf("vreorg: usage: [options] domain\n");
	printf("options: -v (print version number)\n");
	printf("         -p (display debug info)\n");
}

void get_options(int argc, char **argv)
{
 int c;
 int errflag;

    DisplayDebug = 0;

    memset(Domain, 0, MAX_BUFF);

    errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"vp")) != -1 ) {
	switch(c) {
	    case 'v':
	tmpstr = strtok(NULL, TOKENS);
	if ( tmpstr == NULL ) continue;
	strcpy( Domain, tmpstr);

	

    /* walk through list and move directories */


    exit(0);

}

void usage()
{
	printf("vreorg: usage: [options] domain\n");
	printf("options: -v (print version number)\n");
	printf("         -p (display debug info)\n");
}

void get_options(int argc, char **argv)
{
 int c;
 int errflag;

    DisplayDebug = 0;

    memset(Domain, 0, MAX_BUFF);

    errflag = 0;
    while( !errflag && (c=getopt(argc,argv,"vp")) != -1 ) {
	switch(c) {
	    case 'v':
		printf("version: %s\n", VERSION);
		break;
	    case 'p':
		DisplayDebug = 1;	
		break;
	    default:
		errflag = 1;
		break;
	}
    }

    if ( errflag > 0 ) {
	usage();
	exit(-1);
    }

    if ( optind < argc ) { 
	scopy(Domain, argv[optind], MAX_BUFF);
	++optind;
    }

    if ( Domain[0] == 0 ) {
	usage();
	exit(-1);
    }
}
