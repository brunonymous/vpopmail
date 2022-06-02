/*
 * Roberto Puzzanghera - https://notes.sagredo.eu
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

/*
 * This program can be useful to quickly create domain aliases records in the aliasdomains MySQL table
 * when switching to the dovecot's sql driver.
 *
 * To save ALL your existing aliasdomains to MySQL just do like this:
 *
 * vsavealiasdomain -A
 *
 * Type 'vsavealiasdomain -h' for more options.
 *
 * Look at the documentation concerning the sql-aliasdomains feature in the doc/README.sql-aliasdomains file
 * or at https://notes.sagredo.eu/en/qmail-notes-185/dovecot-vpopmail-auth-driver-removal-migrating-to-the-sql-driver-241.html
 * web page.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

char Domain[MAX_BUFF];
char Alias[MAX_BUFF];
int SaveAll;

void usage();
void get_options(int argc, char **argv);
void save_all_aliases();
void save_one_real_domain_aliases( char *Domain );
void save_alias( char *Domain, char *Alias );
#ifndef SQL_ALIASDOMAINS
int  vcreate_sql_aliasdomain(char *Domain, char *Alias);
#endif

int main(int argc, char *argv[])
{
	if( vauth_open( 0 )) {
		vexiterror( stderr, "Initial open." );
	}

#ifndef SQL_ALIASDOMAINS
	printf("\nPlease use option --enable-sql-aliasdomains at configure time\n\n");
	exit(-1);
#else
	get_options(argc,argv);

	/* did we want to save all aliases of one single domain? */
	if ( Domain[0] > 0 && Alias[0] == 0 ) {
        	save_one_real_domain_aliases( Domain );
	}
	/* did we want to save just an alias of a particular domain? */
	else if ( Domain[0] > 0 && Alias[0] > 0 ) {
	        save_alias( Domain, Alias );
	}
	/* save all aliases of all domains */
	else if ( SaveAll == 1 ) {
        	save_all_aliases();
	}
	else {
		usage();
	}
	return(vexit(0));
#endif
}

void usage()
{
    printf("\nUsage: vsavealiasdomains [options] [real_domain] [alias_domain]\n");
    printf("options:          -v (print version number)\n");
    printf("                  -h (help)\n");
    printf("                  -A (saves all aliases of all domains to MySQL)\n");
    printf("vsavealiasdomains domain (saves all aliases of a domain to MySQL)\n");
    printf("vsavealiasdomains real_domain alias_domain (saves an alias domain to MySQL)\n\n");
}

void get_options(int argc, char **argv)
{
	int c;
	int errflag;
	extern int optind;

	SaveAll = 0;

	memset(Domain, 0, sizeof(Domain));

	errflag = 0;
	while( !errflag && (c=getopt(argc,argv,"vAh")) != -1 ) {
        	switch(c) {
			case 'v':
		                printf("version: %s\n", VERSION);
        		        break;

			case 'A':
	                	SaveAll = 1;
		                break;

			case 'h':
				errflag = 1;
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

	if ( optind < argc ) {
		snprintf(Alias, sizeof(Alias), "%s", argv[optind]);
	        ++optind;
	}

	if ( Domain[0]>0 && Alias[0]>0 && strcmp( Domain, Alias ) == 0 ) {
        	printf("Error: real domain and alias domain are the same!\n");
	        usage();
        	vexit(-1);
	}
}

#ifdef SQL_ALIASDOMAINS
/*
 * Save all aliases of all real domains to database
 */
void save_all_aliases()
{
	domain_entry *entry;
	entry = get_domain_entries("");

	if (entry==NULL) {
		if( verrori ) {
			printf("Can't get domain entries - %s\n", verror( verrori ));
			vexit(-1);
		} else {
			printf("No domain found\n");
			vexit(0);
		}
	}

        int i = 0;
        while( entry ) {
                /* we won't save realdomain/realdomain pairs */
                if ( strcmp(entry->realdomain,entry->domain) != 0 ) {
                        vcreate_sql_aliasdomain(entry->realdomain, entry->domain);
                        printf ("Alias: %s Real domain: %s saved\n", entry->domain, entry->realdomain);
			++i;
                }
                entry = get_domain_entries(NULL);
        }
        if ( i == 0 ) {
                printf ("No aliases found\n");
        }
}


/*
 * Save all aliases of domain Domain to database
 */
void save_one_real_domain_aliases( char *Domain )
{
	domain_entry *entry;
	entry = get_domain_entries ( Domain );

	if (entry==NULL) {
		if( verrori ) {
			printf("Can't get domain entries - %s\n", verror( verrori ));
			vexit(-1);
		} else {
			printf("%s does not exist\n", Domain);
			vexit(0);
		}
	}

	int i = 0;
	while( entry ) {
		/* we won't save realdomain/realdomain pairs */
		if ( strcmp(entry->realdomain,entry->domain) != 0 ) {
			vcreate_sql_aliasdomain(entry->realdomain, entry->domain);
			printf ("Alias: %s  Real domain: %s     saved\n", entry->domain, entry->realdomain);
			i++;
		}
		entry = get_domain_entries(NULL);
	}
        if ( i == 0 ) {
        	printf ("No aliases found for domain %s\n", Domain);
        }
}


/*
 * Save the pair Alias/Domain to database
 */
void save_alias( char *Domain, char *Alias )
{
        domain_entry *entry;
        entry = get_domain_entries ( Domain );

        if (entry==NULL) {
                if( verrori ) {
                        printf("Can't get domain entries - %s\n", verror( verrori ));
                        vexit(-1);
                } else {
                        printf("%s does not exist\n", Domain);
                        vexit(0);
                }
        }

        int i = 0;
        while( entry ) {
                /* we won't save realdomain/realdomain pairs */
                if ( strcmp(Alias,entry->domain) == 0  && strcmp(entry->realdomain,entry->domain) != 0 ) {
                        vcreate_sql_aliasdomain(entry->realdomain, entry->domain);
                        printf ("Alias: %s  Real domain: %s     saved\n", entry->domain, entry->realdomain);
                        i++;
                }
                entry = get_domain_entries(NULL);
        }
        if ( i == 0 ) {
                printf ("No alias %s found for domain %s\n", Alias, Domain);
        }
}
#endif
