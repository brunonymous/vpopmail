/*
 * $Id: file_lock.h 1014 2011-02-03 16:04:37Z volz0r $
 * Copyright (C) 2000-2009 Inter7 Internet Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License  
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * functions straight out of Richard Steven's 
 * "Advanced Programming in the UNIX Environment"
 * 
 * Translated into bytes by Eric Peters (eric@peters.org)
 * August 19, 2000
 */
#ifndef VPOPMAIL_FILELOCK_H
#define VPOPMAIL_FILELOCK_H

#define MAX_TRY_RLOCK	10
#define MAX_TRY_WLOCK	15

int
lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len);

#define read_lock(fd, offset, whence, len) \
		lock_reg(fd, F_SETLK, F_RDLCK, offset, whence, len)

#define readw_lock(fd, offset, whence, len) \
		lock_reg(fd, F_SETLKW, F_RDLCK, offset, whence, len)

#define write_lock(fd, offset, whence, len) \
		lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)

#define writew_lock(fd, offset, whence, len) \
		lock_reg(fd, F_SETLKW, F_WRLCK, offset, whence, len)

#define unlock_lock(fd, offset, whence, len) \
		lock_reg(fd, F_SETLK, F_UNLCK, offset, whence, len)


pid_t
lock_test(int fd, int type, off_t offset, int whence, off_t len);

#define is_readlock(fd, offset, whence, len) \
		lock_test(fd, F_RDLCK, offset, whence, len)

#define is_writelock(fd, offset, whence, len) \
		lock_test(fd, F_WRLCK, offset, whence, len)

int get_read_lock( int fd );
int get_write_lock( int fd );
#endif
