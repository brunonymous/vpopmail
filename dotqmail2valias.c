/*
 * $Id: dotqmail2valias.c 1014 2011-02-03 16:04:37Z volz0r $
 * Copyright (C) 2004-2009 Inter7 Internet Technologies, Inc.
 *
 * Copyright (C) 2003-2004 Tom Collins
 * Initial version of this program sponsored by ACIS Pty Ltd.
 *
 * Based on "vconvert.c,v 1.2 2003/10/20 18:59:57" in vpopmail 5.4.
 * Copyright (C) 1999-2003 Inter7 Internet Technologies, Inc.
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
#include <sys/types.h>
#include <dirent.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

/* Default behavior is to do nothing if there are already valias table 
 * entries for a dotqmail file to be processed.  Define one of the 
 * following settings to do something instead of nothing.
 */

/* To delete the existing valias table entries and replace them
 * with contents of current .qmail files, define
 * DELETE_OLD_VALIAS_ENTRIES.
 */
/* #define DELETE_OLD_VALIAS_ENTRIES */

/* To delete .qmail files that have matching valias table
 * entries (instead of attempting to convert them),
 * define DELETE_OLD_DOTQMAIL_FILES.
 */
/* #define DELETE_OLD_DOTQMAIL_FILES */

int Debug = 0;
int AllDomains = 0;

int do_all_domains();
int conv_domain( char *); 
void usage();
void get_options(int argc, char **argv);

/* replace all occurrences of c1 in s with c2 */
void strreplace (char *s, char c1, char c2)
{
	char *p;
	
	for (p = s; *p != '\0'; p++) if (*p == c1) *p = c2;
}

int main(int argc, char *argv[])
{
#ifndef VALIAS
	fprintf (stderr, "You must enable valiases (./configure --enable-valias) to use this program.\n");
	return -1;
#endif

	if( vauth_open( 1 )) {
		vexiterror( stderr, "Initial open." );
	}

	get_options(argc,argv);

	if ( optind == argc ) {
		if (AllDomains)
			do_all_domains();
		else {
			usage();
			return -1;
		}
	} else {
		for(;optind<argc;++optind){
			lowerit(argv[optind]);
			printf("converting %s\n", argv[optind]);
			if ( conv_domain( argv[optind] ) != 0 ) {
				fprintf(stderr, "conversion of %s failed\n", argv[optind]);
				/* should exit -1 here? */
			}
		}
	}
	return(vexit(0));
}

int do_all_domains()
{
 FILE *fs;
 char assign_file[MAX_BUFF];
 static char tmpbuf[MAX_BUFF];
 int i;

    snprintf(assign_file, sizeof(assign_file), "%s/users/assign",  QMAILDIR); 
    if ( (fs=fopen(assign_file, "r"))==NULL ) {
       snprintf(tmpbuf, sizeof(tmpbuf), "could not open qmail assign file at %s\n", assign_file);
       perror(tmpbuf);
       vexit(-1);
    }
    while ( fgets(tmpbuf, sizeof(tmpbuf),fs) != NULL ) {
        if (*tmpbuf != '+') continue;  /* ignore non-domain entries */
        for(i=1;tmpbuf[i]!=':';++i);
        tmpbuf[i-1] = 0;
        /* ignore non-domain entries */
        if (strchr (tmpbuf, '.') == NULL) continue;
	if ( tmpbuf[1] != '\n' ) {
            printf("converting %s\n", &tmpbuf[1] );
            if ( conv_domain( &tmpbuf[1] ) != 0 ) {
                printf("conversion of %s failed\n", &tmpbuf[1]);
                /* should vexit -1 here? */
            }
        }
    }
    fclose(fs);
    return(0);
}


int conv_domain( char *domain )
{
	char domcopy[MAX_BUFF];
	char domainpath[MAX_BUFF];
	char username[MAX_BUFF];
	char alias_line[MAX_ALIAS_LINE];
	char *p;
	
	DIR *domaindir;
	struct dirent *direntry;
	char dotqmail_fn[MAX_BUFF];
	FILE *dotqmail_fs;
	
	int notlist;
	int linecount;
	
	snprintf (domcopy, sizeof(domcopy), "%s", domain);
	if (vget_assign (domcopy, domainpath, sizeof(domainpath), NULL, NULL) == NULL) {
		fprintf (stderr, "Error, domain %s not found in users/cdb.\n", domain);
		return -1;
	}
	if (strcmp (domain, domcopy) != 0) {
		fprintf (stderr, "Skipping %s (alias of %s).\n", domain, domcopy);
		return -1;
	}
	
	if ((domaindir = opendir (domainpath)) == NULL) {
		fprintf (stderr, "Error, couldn't open %s.\n", domainpath);
		return -1;
	}
	
	while ((direntry = readdir(domaindir)) != NULL) {
		/* don't process .qmail-default */
		if (strcmp (".qmail-default", direntry->d_name) == 0) continue;

		/* process all other files starting with ".qmail-" */
		if (strncmp (".qmail-", direntry->d_name, 7) == 0) {
			snprintf (username, sizeof(username), "%s", &direntry->d_name[7]);
			snprintf (dotqmail_fn, sizeof(dotqmail_fn), "%s/%s", domainpath, direntry->d_name);

			/* convert to email address (change ':' to '.') */
			strreplace (username, ':', '.');
			printf ("  checking %s@%s...", username, domain);
			
			/* Does a VALIAS already exist for the file?  If so, throw an error. */
			if (valias_select (username, domain) != NULL) {
				#ifdef DELETE_OLD_VALIAS_ENTRIES
					valias_delete (username, domain);
				#else
					#ifdef DELETE_OLD_DOTQMAIL_FILES
						printf ("valias already exists, deleting %s.\n", direntry->d_name);
						unlink (dotqmail_fn);
						continue;
					#else
						printf ("valias already exists, skipping.\n");
						continue;
					#endif
				#endif
			}
			
			/* Open the .qmail-alias file */
			if ((dotqmail_fs = fopen (dotqmail_fn, "r")) == NULL ) {
				printf ("Error opening %s, skipping.\n", dotqmail_fn);
				continue;
			}
			
			/* if first line matches "|[^ ]+/ezmlm-", then it's a list and shouldn't get converted */
			/* ! note that .qmail-list-owner has ezmlm-warn on second line ! */
			notlist = 1;
			linecount = 0;
			while (notlist && (fgets (alias_line, sizeof(alias_line), dotqmail_fs) != NULL)) {
				linecount++;
				/* Determine if this is an ezmlm list (which shouldn't be converted to valias) */
				/* if line is program delivery, and contains string "/ezmlm-" before the first " ",
				   then it is a list. */
				if (alias_line[0] == '|') {
					char *p1, *p2;
					p1 = strstr (alias_line, "/ezmlm-");
					p2 = strchr (alias_line, ' ');
					if ( (p1 != NULL) && (p2 == NULL || p1 < p2) ) {
						printf ("mailing list, skipping.\n");
						notlist = 0;
					}
				}
				
				/* strip trailing newline (if present) */
				p = strchr (alias_line, '\n');
				if (p) *p = '\0';
				valias_insert (username, domain, alias_line);
			}
			fclose (dotqmail_fs);
			if (notlist) {
				printf (" converted %u entries.\n", linecount);
				unlink (dotqmail_fn);
			} else {
				/* it's a list, so remove the valias entries we created */
				valias_delete (username, domain);
			}
		}
	}
	
	closedir (domaindir);
	return 0;
}


void usage()
{
	fprintf(stdout, "usage: dotqmail2valias [options] [domainlist]\n");
	fprintf(stdout, "  Converts .qmail-alias files for listed domains to valias format.\n");
	fprintf(stdout, "  Options:\n");
	fprintf(stdout, "    -a = convert all domains\n");
	fprintf(stdout, "    -v = version\n");
	fprintf(stdout, "    -d = debug info\n");
}

void get_options(int argc, char **argv)
{
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;

	errflag = 0;
	Debug = 0;

	while( !errflag && (c=getopt(argc,argv,":avd")) != -1 ) {
		switch(c) {
			case 'a':
				AllDomains = 1;
				break;
			case 'd':
				Debug = 1;
				break;
			case 'v':
				printf("version: %s\n", VERSION);
				break;
			default:
				errflag = 1;
				break;
		}
	}
	if (errflag > 0) {
		usage();
		vexit(-1);
	}
}

