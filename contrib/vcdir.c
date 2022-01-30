/*
 * vcdir 
 *
 * converts .dir-control files into sql table 
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


#define MAX_BUFF 500
char Domain[MAX_BUFF];
char Dir[MAX_BUFF];
int  DisplayDebug;
static vdir_type vdir;

void usage();
void get_options(int argc, char **argv);
int vread_cdb_dir_control(vdir_type *vdir, char *domain);

int main(int argc, char **argv)
{
 
    get_options(argc,argv);

    sprintf(Dir, "%s/domains/%s", VPOPMAILDIR, Domain);
    if ( chdir(Dir) != 0 ) {
	perror("Change to domain directory");
	exit(-1);
    }

    memset(&vdir,0,sizeof(vdir_type));
    vread_cdb_dir_control(&vdir, Domain);
    vwrite_dir_control(&vdir, Domain, 0, 0);

    exit(0);

}

void usage()
{
	printf("vcdir: usage: [options] domain\n");
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
    while( !errflag && (c=getopt(argc,argv,"anpugcdqv")) != -1 ) {
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
	strncpy(Domain, argv[optind], MAX_BUFF);
	++optind;
    }

    if ( Domain[0] == 0 ) {
	usage();
	exit(-1);
    }
}

int vread_cdb_dir_control(vdir_type *vdir, char *domain)
{ 
 FILE *fs;

	if ( (fs = fopen(".dir-control", "r")) == NULL ) {
		int i;

		vdir->cur_users = 0;
		for(i=0;i<MAX_DIR_LEVELS;++i){
			vdir->level_start[i] = 0;
			vdir->level_end[i] = MAX_DIR_LIST-1;
			vdir->level_index[i] = 0;
		}
		vdir->level_mod[0] = 0;
		vdir->level_mod[1] = 2;
		vdir->level_mod[2] = 4;
		vdir->level_cur = 0;
		vdir->level_max = MAX_DIR_LEVELS;
		vdir->the_dir[0] = 0;
		return(-1);
	} 

	fscanf(fs, "%lu\n", &vdir->cur_users);
	fscanf(fs, "%d\n", &vdir->level_cur);
	fscanf(fs, "%d\n", &vdir->level_max);
	fscanf(fs, "%d %d %d\n", 
		&vdir->level_start[0],
		&vdir->level_start[1],
		&vdir->level_start[2]);
	fscanf(fs, "%d %d %d\n", 
		&vdir->level_end[0],
		&vdir->level_end[1],
		&vdir->level_end[2]);
	fscanf(fs, "%d %d %d\n", 
		&vdir->level_mod[0],
		&vdir->level_mod[1],
		&vdir->level_mod[2]);
	fscanf(fs, "%d %d %d\n", 
		&vdir->level_index[0],
		&vdir->level_index[1],
		&vdir->level_index[2]);
	fscanf(fs, "%s\n", vdir->the_dir); 

	fclose(fs);

	return(0);
}
