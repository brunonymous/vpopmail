/*
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
#ifndef VPOPMAIL_MYSQL_H
#define VPOPMAIL_MYSQL_H

/* NOTE: As of vpopmail 5.3.25, MySQL connection info is stored in
   ~vpopmail/etc/vpopmail.mysql.  The format of the file is as follows:
   
   read server|read port|read user|read password|read database
   update server|update port|update user|update password|update database
   
   Comments (lines starting with '#') are allowed.  The first line contains
   connection information for READING from the database.  The second (optional)
   line contains connection information for UPDATING the database.  If the
   second line is left out, then vpopmail will use the same settings for
   reading and updating.
   
   Port should be the actual port, or 0 for default.
   
   For example:
   
   # This is the MySQL configuration file for vpopmail.
   localhost|0|readonly|somepass|vpopmail
   localhost|0|root|secret|vpopmail
   
 */

/* defaults - no need to change */
#define MYSQL_DEFAULT_TABLE "vpopmail"
#define MYSQL_DOT_CHAR '_'
#define MYSQL_LARGE_USERS_TABLE "users"

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define TABLE_LAYOUT "pw_name char(64) not null, \
pw_domain char(96) not NULL, \
pw_passwd char(128), \
pw_uid int, pw_gid int, \
pw_gecos char(64), \
pw_dir char(160), \
pw_shell char(20), \
pw_clear_passwd char(16), \
primary key (pw_name, pw_domain ) "
#else
#define TABLE_LAYOUT "pw_name char(64) not null, \
pw_domain char(96) not null, \
pw_passwd char(128), \
pw_uid int, pw_gid int, \
pw_gecos char(64), \
pw_dir char(160), \
pw_shell char(20), \
primary key (pw_name, pw_domain ) "
#endif
#else
#ifdef CLEAR_PASS
#define TABLE_LAYOUT "pw_name char(64) not null, \
pw_passwd char(128), \
pw_uid int, pw_gid int, \
pw_gecos char(64), \
pw_dir char(160), \
pw_shell char(20), \
pw_clear_passwd char(16), \
primary key (pw_name ) "
#else
#define TABLE_LAYOUT "pw_name char(64) not null, \
pw_passwd char(128), \
pw_uid int, pw_gid int, \
pw_gecos char(64), \
pw_dir char(160), \
pw_shell char(20), \
primary key (pw_name ) "
#endif
#endif

#define RELAY_TABLE_LAYOUT "ip_addr char(18) not null, \
timestamp char(12), primary key (ip_addr)"

#define LASTAUTH_TABLE_LAYOUT \
"user char(32) NOT NULL, \
domain char(96) NOT NULL,\
remote_ip char(18) not null,  \
timestamp bigint default 0 NOT NULL, \
primary key (user, domain)"

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
#define INSERT "insert into `%s` \
( pw_name, pw_domain, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
, pw_clear_passwd ) values ( \"%s\", \"%s\", \
\"%s\", %d, 0, \"%s\", \"%s\", \"%s\" ,\"%s\" )"
#else
#define INSERT "insert into `%s` \
( pw_name, pw_domain, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
) values ( \"%s\", \"%s\", \
\"%s\", %d, 0, \"%s\", \"%s\", \"%s\" )"
#endif
#else
#ifdef CLEAR_PASS
#define INSERT "insert into `%s` \
( pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
, pw_clear_passwd ) values ( \"%s\", \
\"%s\", %d, 0, \"%s\", \"%s\", \"%s\" ,\"%s\" )"
#else
#define INSERT "insert into `%s` \
( pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
 ) values ( \"%s\", \
\"%s\", %d, 0, \"%s\", \"%s\", \"%s\" )"
#endif
#endif

#ifdef MANY_DOMAINS
#define DELETE_USER "delete from `%s` where pw_name = \"%s\" \
and pw_domain = \"%s\" " 
#else
#define DELETE_USER "delete from `%s` where pw_name = \"%s\" "
#endif


#ifdef MANY_DOMAINS
#define SETQUOTA "update `%s` set pw_shell = \"%s\" where pw_name = \"%s\" \
and pw_domain = \"%s\" "
#else
#define SETQUOTA "update `%s` set pw_shell = \"%s\" where pw_name = \"%s\" "
#endif

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define USER_SELECT "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell , pw_clear_passwd \
from `%s` where pw_name = \"%s\" and pw_domain = \"%s\" "
#else
#define USER_SELECT "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell \
from `%s` where pw_name = \"%s\" and pw_domain = \"%s\" "
#endif
#else
#ifdef CLEAR_PASS
#define USER_SELECT "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell , pw_clear_passwd \
from `%s` where pw_name = \"%s\" " 
#else
#define USER_SELECT "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell \
from `%s` where pw_name = \"%s\"  "
#endif
#endif

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define GETALL "select pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell, \
pw_clear_passwd from `%s` where pw_domain = \"%s\""
#else
#define GETALL "select pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
from `%s` where pw_domain = \"%s\""
#endif
#else
#ifdef CLEAR_PASS
#define GETALL "select pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell, \
pw_clear_passwd from `%s`"
#else
#define GETALL "select pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell from `%s` "
#endif
#endif

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define SETPW "update `%s` set pw_passwd = \"%s\", \
pw_uid = %d, pw_gid = %d, pw_gecos = \"%s\", pw_dir = \"%s\", \
pw_shell = \"%s\" \
, pw_clear_passwd = \"%s\" \
where pw_name = \"%s\" \
and pw_domain = \"%s\" "
#else
#define SETPW "update `%s` set pw_passwd = \"%s\", \
pw_uid = %d, pw_gid = %d, pw_gecos = \"%s\", pw_dir = \"%s\", \
pw_shell = \"%s\" \
where pw_name = \"%s\" \
and pw_domain = \"%s\" "
#endif
#else
#ifdef CLEAR_PASS
#define SETPW "update `%s` set pw_passwd = \"%s\", \
pw_uid = %d, pw_gid = %d, pw_gecos = \"%s\", pw_dir = \"%s\", \
pw_shell = \"%s\" \
, pw_clear_passwd = \"%s\" \
where pw_name = \"%s\" "
#else
#define SETPW "update `%s` set pw_passwd = \"%s\", \
pw_uid = %d, pw_gid = %d, pw_gecos = \"%s\", pw_dir = \"%s\", \
pw_shell = \"%s\" \
where pw_name = \"%s\" "
#endif
#endif

#ifdef IP_ALIAS_DOMAINS
#define IP_ALIAS_TABLE_LAYOUT "ip_addr char(18) not null, domain char(96),  primary key(ip_addr)"
#endif

#define DIR_CONTROL_TABLE_LAYOUT "domain char(96) not null, cur_users int, \
level_cur int, level_max int, \
level_start0 int, level_start1 int, level_start2 int, \
level_end0 int, level_end1 int, level_end2 int, \
level_mod0 int, level_mod1 int, level_mod2 int, \
level_index0 int , level_index1 int, level_index2 int, the_dir char(160), \
primary key (domain) "

#define DIR_CONTROL_SELECT "cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir"

#ifdef DEFAULT_DELIVERY
#define VALIAS_TABLE_LAYOUT \
"id INT NOT NULL AUTO_INCREMENT, \
valias_type tinyint(1) NOT NULL DEFAULT 1 COMMENT '1=forwarder 0=lda', \
alias char(32) NOT NULL, \
domain char(96) NOT NULL, \
valias_line text NOT NULL, \
copy tinyint(1) NOT NULL DEFAULT 0 COMMENT '0=redirect 1=copy&redirect', \
INDEX (alias, domain), \
INDEX (alias, domain, valias_type), \
PRIMARY KEY (id)"
#else
#define VALIAS_TABLE_LAYOUT "id int(11) PRIMARY KEY AUTO_INCREMENT, \
alias char(32) NOT NULL, \
domain char(96) NOT NULL, \
valias_line text NOT NULL, \
INDEX (alias, domain)"
#endif

#endif

#ifdef ENABLE_SQL_LOGGING
#define VLOG_TABLE_LAYOUT "id BIGINT PRIMARY KEY AUTO_INCREMENT, \
      user char(32), passwd CHAR(32), \
      domain CHAR(96), logon VARCHAR(200), \
      remoteip char(18), message VARCHAR(255), \
      timestamp bigint default 0 NOT NULL, error INT, \
      INDEX user_idx (user), \
      INDEX domain_idx (domain), INDEX remoteip_idx (remoteip), \
      INDEX error_idx (error), INDEX message_idx (message)"
#endif

#ifdef ENABLE_MYSQL_LIMITS
#define LIMITS_TABLE_LAYOUT "domain CHAR(96) PRIMARY KEY, \
      maxpopaccounts           INT(10) NOT NULL DEFAULT -1, \
      maxaliases               INT(10) NOT NULL DEFAULT -1, \
      maxforwards              INT(10) NOT NULL DEFAULT -1, \
      maxautoresponders        INT(10) NOT NULL DEFAULT -1, \
      maxmailinglists          INT(10) NOT NULL DEFAULT -1, \
      diskquota                BIGINT UNSIGNED NOT NULL DEFAULT 0, \
      maxmsgcount              BIGINT UNSIGNED NOT NULL DEFAULT 0, \
      defaultquota             BIGINT UNSIGNED NOT NULL DEFAULT 0, \
      defaultmaxmsgcount       BIGINT UNSIGNED NOT NULL DEFAULT 0, \
      disable_pop              TINYINT(1) NOT NULL DEFAULT 0, \
      disable_imap             TINYINT(1) NOT NULL DEFAULT 0, \
      disable_dialup           TINYINT(1) NOT NULL DEFAULT 0, \
      disable_passwordchanging TINYINT(1) NOT NULL DEFAULT 0, \
      disable_webmail          TINYINT(1) NOT NULL DEFAULT 0, \
      disable_relay            TINYINT(1) NOT NULL DEFAULT 0, \
      disable_smtp             TINYINT(1) NOT NULL DEFAULT 0, \
      disable_spamassassin     TINYINT(1) NOT NULL DEFAULT 0, \
      delete_spam              TINYINT(1) NOT NULL DEFAULT 0, \
      disable_maildrop		   TINYINT(1) NOT NULL DEFAULT 0, \
      perm_account             TINYINT(2) NOT NULL DEFAULT 0, \
      perm_alias               TINYINT(2) NOT NULL DEFAULT 0, \
      perm_forward             TINYINT(2) NOT NULL DEFAULT 0, \
      perm_autoresponder       TINYINT(2) NOT NULL DEFAULT 0, \
      perm_maillist            TINYINT(4) NOT NULL DEFAULT 0, \
      perm_quota               TINYINT(2) NOT NULL DEFAULT 0, \
      perm_defaultquota        TINYINT(2) NOT NULL DEFAULT 0"
#endif

void vcreate_aliasdomains_table();
int vdelete_sql_aliasdomain(char *alias);
int vcreate_sql_aliasdomain(char *domain, char *alias);

#define ALIASDOMAINS_TABLE_LAYOUT "alias varchar(100) NOT NULL, \
      domain varchar(100) NOT NULL, \
      PRIMARY KEY (alias)"

int vcreate_sql_procedures();
