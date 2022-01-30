/*
 * $Id: bigdir.c 1014 2011-02-03 16:04:37Z volz0r $
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
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "file_lock.h"
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

vdir_type vdir;

static char dirlist[MAX_DIR_LIST] =
"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

int open_big_dir(char *domain, uid_t uid, gid_t gid)
{
	memset(&vdir,0,sizeof(vdir_type));
	vread_dir_control(&vdir, domain, uid, gid);
	return(0);
}

int close_big_dir(char *domain, uid_t uid, gid_t gid)
{
	vwrite_dir_control(&vdir, domain, uid, gid);
	return(0);
}

int dec_dir_control(char *domain, uid_t uid, gid_t gid)
{
	open_big_dir(domain, uid, gid);
	--vdir.cur_users;
	close_big_dir(domain, uid, gid);
	return(0);
}

char *next_big_dir(uid_t uid, gid_t gid)
{
	inc_dir_control(&vdir);
	if ( vdir.the_dir[0] != 0 ) {
	    r_mkdir(vdir.the_dir, uid, gid);
	}
	return(vdir.the_dir);
}

char *inc_dir( vdir_type *vdir, int in_level ) 
{

	if ( vdir->the_dir[vdir->level_mod[in_level]] == 
		dirlist[vdir->level_end[in_level]] ) {
		vdir->the_dir[vdir->level_mod[in_level]] = 
			dirlist[vdir->level_start[in_level]];
		vdir->level_index[in_level] = vdir->level_start[in_level];
		if ( in_level > 0 ) inc_dir(vdir, in_level-1);
	} else {
		vdir->the_dir[vdir->level_mod[in_level]] = next_char( 
			vdir->the_dir[vdir->level_mod[in_level]], 
			vdir->level_start[in_level], 
			vdir->level_end[in_level] ); 
		++vdir->level_index[in_level];
	}
	return(vdir->the_dir);
}

char next_char(char in_char, int in_start, int in_end )
{
 int i;

	for(i=in_start;i<in_end+1 && dirlist[i] != in_char;++i);
	 ++i;
	if ( i >= in_end+1 ) i = in_start;
	return(dirlist[i]);
}

int inc_dir_control(vdir_type *vdir)
{
	++vdir->cur_users;
	if ( vdir->cur_users%MAX_USERS_PER_LEVEL == 0 ) {
		if ( strlen(vdir->the_dir) == 0 ) {
			vdir->the_dir[0] = dirlist[vdir->level_start[0]];
			vdir->the_dir[1] = 0; 
			return(0);
		}

		if ( vdir->level_index[vdir->level_cur] == 
	     	vdir->level_end[vdir->level_cur] ) {
			switch (vdir->level_cur) {
		    	case 0:
				inc_dir( vdir, vdir->level_cur );
				++vdir->level_cur;
				strcat(vdir->the_dir, "/" );
				break;
		    	case 1:
				if ( vdir->level_index[0]==vdir->level_end[0] &&
			     	     vdir->level_index[1]==vdir->level_end[1]) {
					inc_dir( vdir, vdir->level_cur );
					++vdir->level_cur;
					strcat(vdir->the_dir, "/");
				}
				break;
			}
		}
		inc_dir( vdir, vdir->level_cur );
	}
	return(0);
}

void print_control()
{
	/*printf("cur users %ul\n", vdir.cur_users);*/
	printf("dir = %s\n", vdir.the_dir);
	/*
	printf("level_cur = %d\n", vdir.level_cur);
	printf("level_max = %d\n", vdir.level_max);
	printf("d level_index 0 = %d 1 = %d 2 = %d\n",
		vdir.level_index[0],
		vdir.level_index[1],
		vdir.level_index[2]);
	printf("level_start 0 = %d 1 = %d 2 = %d\n",
		vdir.level_start[0],
		vdir.level_start[1],
		vdir.level_start[2]);
	printf("level_end 0 = %d 1 = %d 2 = %d\n",
		vdir.level_end[0],
		vdir.level_end[1],
		vdir.level_end[2]);
	printf("level_mod 0 = %d 1 = %d 2 = %d\n",
		vdir.level_mod[0],
		vdir.level_mod[1],
		vdir.level_mod[2]);

	*/
}
