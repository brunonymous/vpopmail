/*
 * $Id: valias.c 1014 2011-02-03 16:04:37Z volz0r $
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
char Alias[MAX_BUFF];
char Domain[MAX_BUFF];
char AliasLine[MAX_BUFF];

#define VALIAS_SELECT 0
#define VALIAS_INSERT 1
#define VALIAS_DELETE 2
#define VALIAS_NAMES  3

int AliasAction;
int AliasExists;
char *valias_select_names( char *domain );
char *valias_select_names_next();
void  valias_select_names_end();

void usage();
void get_options(int argc,char **argv);

int main(int argc, char *argv[])
{
 char *tmpalias;

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

	get_options(argc,argv);

	switch( AliasAction ) {
	case VALIAS_SELECT:
		/* did the user nominate an email address or a domain? */
		if ( strstr(Email, "@") == NULL ) {
			/* display all aliases for domain */
			tmpalias = valias_select_all( Alias, Email );
			if (tmpalias == NULL) vexit(-1);
			while (tmpalias != NULL ) {
				printf("%s@%s -> %s\n", Alias, Email, tmpalias);
                                fflush(stdout);
				tmpalias = valias_select_all_next(Alias);
			}
		} else {
			/* display aliases for Alias@Domain */
			tmpalias = valias_select( Alias, Domain );
			if (tmpalias == NULL) vexit(-1);
			while (tmpalias != NULL ) {
				printf("%s@%s -> %s\n", Alias, Domain,tmpalias);
				tmpalias = valias_select_next();
			}
		}
		break;

	case VALIAS_NAMES:
		/* did the user nominate an email address or a domain? */
		if ( strstr(Email, "@") == NULL ) {
			/* display all aliases for domain */
			tmpalias = valias_select_names( Email );
			if (tmpalias == NULL) vexit(-1);
			while (tmpalias != NULL ) {
				printf("%s\n", tmpalias);
				tmpalias = valias_select_names_next();
			}
                        valias_select_names_end();
		} else {
                        fprintf(stderr, "Please enter domain name only.\n" );
			vexit(-1);
		}
		break;

	case VALIAS_INSERT:
		/* check to see if it already exists */
		AliasExists = 0;
		tmpalias = valias_select( Alias, Domain );
		while (tmpalias != NULL ) {
			if (strcmp (tmpalias, AliasLine) == 0) AliasExists = 1;
			tmpalias = valias_select_next();
		}
		if (AliasExists) {
			fprintf (stderr, "Error: alias %s -> %s already exists.\n",
				Email, AliasLine);
			vexit(-1);
		} else {
			valias_insert( Alias, Domain, AliasLine );
		}
		break;

	case VALIAS_DELETE:
		valias_delete( Alias, Domain );
		break;

        default:
		fprintf(stderr, "error, Alias Action '%d' is invalid\n", 
			AliasAction);
		break;
	}
	return(vexit(0));
}

void usage()
{
	printf( "valias: usage: [options] email_address \n");
	printf("options: -v ( display the vpopmail version number )\n");
	printf("         -n ( show alias names, use just domain )\n");
	printf("         -s ( show aliases, can use just domain )\n");
	printf("         -d ( delete alias )\n");
	printf("         -i alias_line (insert alias line)\n");
	printf("\n");
	printf("Example: valias -i fred@inter7.com bob@inter7.com\n");
	printf("         (adds alias from bob@inter7.com to fred@inter7.com\n");
}

void get_options(int argc,char **argv)
{
 int c;
 int i;
 extern char *optarg;
 extern int optind;

	memset(Alias, 0, sizeof(Alias));
	memset(Email, 0, sizeof(Email));
	memset(Domain, 0, sizeof(Domain));
	memset(AliasLine, 0, sizeof(AliasLine));
	AliasAction = VALIAS_SELECT;

    	while( (c=getopt(argc,argv,"vnsdi:")) != -1 ) {
		switch(c) {
		case 'v':
			printf("version: %s\n", VERSION);
			break;
		case 'n':
			AliasAction = VALIAS_NAMES;
			break;
		case 's':
			AliasAction = VALIAS_SELECT;
			break;
		case 'd':
			AliasAction = VALIAS_DELETE;
			break;
		case 'i':
			AliasAction = VALIAS_INSERT;
			snprintf(AliasLine, sizeof(AliasLine), "%s", optarg);
			break;
		default:
			usage();
			exit(-2);
		}
	}

	if ( optind < argc ) {
		snprintf(Email, sizeof(Email), "%s", argv[optind]);
                if ( (i = parse_email( Email, Alias, Domain, sizeof(Alias))) != 0 ) {
                  fprintf(stderr, "Error: %s\n", verror(i));
                  vexit(i);
                }
		++optind;
	} 

	if ( Email[0] == 0 ) {
		fprintf(stderr, "must supply alias email address\n");
		usage();
		vexit(-1);
	}
}
