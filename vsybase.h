/*
 * $Id: vsybase.h 1014 2011-02-03 16:04:37Z volz0r $
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
#ifndef VPOPMAIL_SYBASE_H
#define VPOPMAIL_SYBASE_H

/* Edit to match your set up */ 
#define SYBASE_SERVER        ""
#define SYBASE_USER          "sa"
#define SYBASE_PASSWD        ""
#define SYBASE_APP           "vpopmail"
/* End of setup section*/

/* defaults - no need to change */
#define SYBASE_DEFAULT_TABLE "vpopmail"
#define SYBASE_DATABASE "vpopmail"
#define SYBASE_DOT_CHAR '_'
#define SYBASE_LARGE_USERS_TABLE "users"

/* small site table layout */
#define SMALL_TABLE_LAYOUT "pw_name char(32) not null, \
pw_domain varchar(223) not null, \
pw_passwd varchar(255) not null, \
pw_uid int, \
pw_gid int, \
pw_gecos varchar(255), \
pw_dir varchar(255), \
pw_shell varchar(255), primary key (pw_name, pw_domain) "

/* large site table layout */
#define LARGE_TABLE_LAYOUT "pw_name char(32) not null, \
pw_passwd varchar(255) not null, \
pw_uid int, \
pw_gid int, \
pw_gecos varchar(255), \
pw_dir varchar(255), \
pw_shell varchar(255), primary key(pw_name)"

#define RELAY_TABLE_LAYOUT "ip_addr char(18) not null, timestamp char(12), primary key(ip_addr)"

#define SMALL_SITE 0
#define LARGE_SITE 1

char *vauth_munch_domain(char *);
int vauth_open( int will_update );

int vauth_adddomain_size(char *, int);
int vauth_deldomain_size(char *, int);
int vauth_adduser_size(char *, char *, char *, char *, char *, int, int);
int vauth_deluser_size(char *, char *, int);
int vauth_vpasswd_size( char *, char *, char *, int, int);
int vauth_setquota_size( char *, char *, char *, int);
struct vqpasswd *vauth_getpw_size(char *, char *, int);
struct vqpasswd *vauth_user_size(char *, char *, char*, char *, int);
struct vqpasswd *vauth_getall_size(char *, int, int, int);
int vauth_setpw_size( struct vqpasswd *, char *, int);

#define LARGE_INSERT "insert into  %s \
( pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell ) \
values \
( '%s', '%s', %d, 0, '%s', '%s', '%s' )"

#define SMALL_INSERT "insert into  %s \
( pw_name, pw_domain, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell ) \
values \
( '%s', '%s', '%s', %d, 0, '%s', '%s', '%s' )"

#define LARGE_SELECT "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell from %s where pw_name = '%s'"

#define SMALL_SELECT "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell from %s where pw_name = '%s' and pw_domain = '%s'"

#define LARGE_GETALL "select pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, \
pw_dir, pw_shell from %s"

#define SMALL_GETALL "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell from %s where pw_domain = '%s'"

#define LARGE_SETPW "update %s set pw_passwd = '%s', \
pw_uid = %d, pw_gid = %d, pw_gecos = '%s', pw_dir = '%s', pw_shell = '%s' \
where pw_name = '%s'" 

#define SMALL_SETPW "update %s set pw_passwd = '%s', \
pw_uid = %d, pw_gid = %d, pw_gecos = '%s', pw_dir = '%s', pw_shell = '%s' \
where pw_name = '%s' and pw_domain = '%s'"

#endif
