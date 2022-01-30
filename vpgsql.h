/*
 * $Id: vpgsql.h 1014 2011-02-03 16:04:37Z volz0r $
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
#ifndef VPOPMAIL_PGSQL_H
#define VPOPMAIL_PGSQL_H

#include "config.h"

/* Edit to match your set up */
#define DB "vpopmail"
#define PG_CONNECT "user=postgres dbname=" DB

// char replacing spaces and dashes
#define SQL_DOT_CHAR    '_'

#define PGSQL_DEFAULT_TABLE "vpopmail"
#define PGSQL_LARGE_USERS_TABLE "users"

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define TABLE_LAYOUT "pw_name varchar(32) NOT NULL, \
pw_domain varchar(96) NOT NULL, \
pw_passwd varchar(40), \
pw_uid int4, pw_gid int4, \
pw_gecos varchar(48), \
pw_dir varchar(160), \
pw_shell varchar(20), \
pw_clear_passwd varchar(16), \
PRIMARY KEY(\"pw_domain\", \"pw_name\")"
#else
#define TABLE_LAYOUT "pw_name varchar(32) NOT NULL, \
pw_domain varchar(96) NOT NULL, \
pw_passwd varchar(40), \
pw_uid int4, pw_gid int4, \
pw_gecos varchar(48), \
pw_dir varchar(160), \
pw_shell varchar(20), \
PRIMARY KEY (pw_name, pw_domain ) "
#endif
#else
#ifdef CLEAR_PASS
#define TABLE_LAYOUT "pw_name varchar(32) NOT NULL, \
pw_passwd varchar(40), \
pw_uid int4, pw_gid int4, \
pw_gecos varchar(48), \
pw_dir varchar(160), \
pw_shell varchar(20), \
pw_clear_passwd varchar(16), \
PRIMARY KEY (pw_name ) "
#else
#define TABLE_LAYOUT "pw_name varchar(32) NOT NULL, \
pw_passwd varchar(40), \
pw_uid int4, pw_gid int4, \
pw_gecos varchar(48), \
pw_dir varchar(160), \
pw_shell varchar(20), \
PRIMARY KEY (pw_name ) "
#endif
#endif

#define RELAY_TABLE_LAYOUT "ip_addr varchar(18) NOT NULL, \
timestamp bigint DEFAULT 0 NOT NULL, PRIMARY KEY (ip_addr)"

#define LASTAUTH_TABLE_LAYOUT \
"userid varchar(32) NOT NULL, \
domain varchar(96) NOT NULL,\
remote_ip varchar(18) NOT NULL,  \
timestamp bigint default 0 NOT NULL, \
PRIMARY key (userid, domain)"

char *vauth_munch_domain(char *);

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

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define INSERT "INSERT INTO \"%s\" \
( pw_name, pw_domain, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
, pw_clear_passwd ) VALUES ( '%s', '%s', '%s', %d, 0, '%s', '%s', '%s' ,'%s' )"
#else
#define INSERT "INSERT INTO \"%s\" \
( pw_name, pw_domain, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
) VALUES ( '%s', '%s', '%s', %d, 0, '%s', '%s', '%s' )"
#endif
#else
#ifdef CLEAR_PASS
#define INSERT "INSERT INTO \"%s\" \
( pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
, pw_clear_passwd ) VALUES ( '%s', \
'%s', %d, 0, '%s', '%s', '%s' ,'%s' )"
#else
#define INSERT "INSERT INTO \"%s\" \
( pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
 ) VALUES ( '%s', '%s', %d, 0, '%s', '%s', '%s' )"
#endif
#endif

#ifdef MANY_DOMAINS
#define DELETE_USER "DELETE FROM \"%s\" where pw_name = '%s' \
and pw_domain = '%s' " 
#else
#define DELETE_USER "DELETE FROM \"%s\" where pw_name = '%s' "
#endif

#ifdef MANY_DOMAINS
#define SETQUOTA "UPDATE \"%s\" SET pw_shell = '%s' WHERE pw_name = '%s' \
AND pw_domain = '%s' "
#else
#define SETQUOTA "UPDATE \"%s\" SET pw_shell = '%s' WHERE pw_name = '%s' "
#endif

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define USER_SELECT "SELECT pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell , pw_clear_passwd \
FROM \"%s\" WHERE pw_name = '%s' AND pw_domain = '%s'"
#else
#define USER_SELECT "SELECT pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell \
FROM \"%s\" WHERE pw_name = '%s' AND pw_domain = '%s' "
#endif
#else
#ifdef CLEAR_PASS
#define USER_SELECT "SELECT pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell , pw_clear_passwd \
FROM \"%s\" WHERE pw_name = '%s'" 
#else
#define USER_SELECT "SELECT pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell \
FROM \"%s\" WHERE pw_name = '%s' "
#endif
#endif

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define GETALL "SELECT pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell, \
pw_clear_passwd FROM \"%s\" WHERE pw_domain = '%s'"
#else
#define GETALL "SELECT pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
FROM \"%s\" WHERE pw_domain = '%s'"
#endif
#else
#ifdef CLEAR_PASS
#define GETALL "SELECT pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell, \
pw_clear_passwd FROM \"%s\""
#else
#define GETALL "SELECT pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell FROM \"%s\" "
#endif
#endif

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define SETPW "UPDATE \"%s\" SET pw_passwd = '%s', \
pw_uid = %d, pw_gid = %d, pw_gecos = '%s', pw_dir = '%s', \
pw_shell = '%s', pw_clear_passwd = '%s' \
WHERE pw_name = '%s' AND pw_domain = '%s' "
#else
#define SETPW "UPDATE \"%s\" SET pw_passwd = '%s', \
pw_uid = %d, pw_gid = %d, pw_gecos = '%s', pw_dir = '%s', \
pw_shell = '%s' WHERE pw_name = '%s' AND pw_domain = '%s' "
#endif
#else
#ifdef CLEAR_PASS
#define SETPW "UPDATE \"%s\" SET pw_passwd = '%s', \
pw_uid = %d, pw_gid = %d, pw_gecos = '%s', pw_dir = '%s', \
pw_shell = '%s', pw_clear_passwd = '%s' WHERE pw_name = '%s' "
#else
#define SETPW "UPDATE \"%s\" SET pw_passwd = '%s', \
pw_uid = %d, pw_gid = %d, pw_gecos = '%s', pw_dir = '%s', \
pw_shell = '%s' WHERE pw_name = '%s' "
#endif
#endif

#ifdef IP_ALIAS_DOMAINS
#define IP_ALIAS_TABLE_LAYOUT "ip_addr varchar(18) NOT NULL, domain varchar(96), PRIMARY KEY (ip_addr)"
#endif

#define DIR_CONTROL_TABLE_LAYOUT "domain varchar(96) NOT NULL, cur_users int4, \
level_cur int4, level_max int4, \
level_start0 int4, level_start1 int4, level_start2 int4, \
level_end0 int4, level_end1 int4, level_end2 int4, \
level_mod0 int4, level_mod1 int4, level_mod2 int4, \
level_index0 int4, level_index1 int4, level_index2 int4, the_dir varchar(160),\
PRIMARY KEY (domain) "

#define DIR_CONTROL_SELECT "cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir"

#define VALIAS_TABLE_LAYOUT "alias varchar(32) NOT NULL, \
domain varchar(96) NOT NULL, \
valias_line varchar(160) NOT NULL"
#define VALIAS_INDEX_LAYOUT "(alias, domain)"
#endif

#ifdef ENABLE_SQL_LOGGING
#define VLOG_TABLE_LAYOUT "id serial, \
      userid char(32), passwd CHAR(32), \
      domain CHAR(96), logon VARCHAR(200), \
      remoteip char(18), message VARCHAR(255), \
      timestamp bigint default 0 NOT NULL, error INT, \
      INDEX user_idx (user), \
      INDEX domain_idx (domain), INDEX remoteip_idx (remoteip), \
      INDEX error_idx (error), INDEX message_idx (message)"
#endif
