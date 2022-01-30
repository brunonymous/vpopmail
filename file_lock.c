/*
 * $Id: file_lock.c 1014 2011-02-03 16:04:37Z volz0r $
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
 *
 */
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>	/* for perror() */
#include <errno.h>	/* for perror() */
#include <fcntl.h>
#include "file_lock.h"
#include "config.h"
#ifdef FILE_LOCKING

int
lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
	struct flock	lock;

	lock.l_type	= type;		/* F_RDLCK, F_WRLCK, F_UNLCK */
	lock.l_start	= offset;	/* byte offset, relative to l_whence */
	lock.l_whence	= whence;	/* SEEK_SET, SEEK_CUR, SEEK_END */
	lock.l_len	= len;		/* #bytes (0 means to EOF) */

	return( fcntl(fd, cmd, &lock) );
}


pid_t
lock_test(int fd, int type, off_t offset, int whence, off_t len)
{
	struct flock	lock;

	lock.l_type	= type;		/* F_RDLCK, F_WRLCK, F_UNLCK */
	lock.l_start	= offset;	/* byte offset, relative to l_whence */
	lock.l_whence	= whence;	/* SEEK_SET, SEEK_CUR, SEEK_END */
	lock.l_len	= len;		/* #bytes (0 means to EOF) */

	if (fcntl(fd, F_GETLK, &lock) < 0)
	{
		return(0);
	}

	if (lock.l_type == F_UNLCK)
		return(0);	/* false, region is not locked yb another proc */
	return(lock.l_pid);	/* true, return pid of lock owner */
}

int get_read_lock(int fd)
{
 int try = 0;

	while(read_lock(fd, 0, SEEK_SET, 0) < 0)
	{
		if (errno == EAGAIN || errno == EACCES || errno ==ENOLCK ) 
		{
			/* there might be other errors cases in which
			* you might try again. 
			*/
			if (++try < MAX_TRY_RLOCK) {
				(void) sleep(2);
				continue;
			}
			(void) fprintf(stderr,"File busy try again later!\n");
			return(-1);
		}

		return(-2);
	}
	return(0);
}

int get_write_lock( int fd ) 
{
 int try = 0;

	while(write_lock(fd, 0, SEEK_SET, 0) < 0)
	{
		if (errno == EAGAIN || errno == EACCES || errno == ENOLCK ) 
		{
			/* there might be other errors cases in which
			* you might try again. 
			*/
			if (++try < MAX_TRY_RLOCK) {
				(void) sleep(2);
				continue;
			}
			(void) fprintf(stderr,"File busy try again later!\n");
			return(-1);
		}
		return(-2);
	}
	return(0);
}
#endif
