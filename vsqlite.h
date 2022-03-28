#ifndef VPOPMAIL_SQLITE3_H
#define VPOPMAIL_SQLITE3_H

#define SQLITE_DEFAULT_TABLE "vpopmail"
#define SQLITE_DOT_CHAR '_'
#define SQLITE_LARGE_USERS_TABLE "users"

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define TABLE_LAYOUT \
  "pw_name text not null, \
pw_domain text not NULL, \
pw_passwd text, \
pw_uid integer, pw_gid integer, \
pw_gecos text, \
pw_dir text, \
pw_shell text, \
pw_clear_passwd text, \
primary key (pw_name, pw_domain ) "
#else
#define TABLE_LAYOUT \
  "pw_name text not null, \
pw_domain text not null, \
pw_passwd text, \
pw_uid integer, pw_gid integer, \
pw_gecos text, \
pw_dir text, \
pw_shell text, \
primary key (pw_name, pw_domain ) "
#endif
#else
#ifdef CLEAR_PASS
#define TABLE_LAYOUT \
  "pw_name text not null, \
pw_passwd text, \
pw_uid integer, pw_gid integer, \
pw_gecos text, \
pw_dir text, \
pw_shell text, \
pw_clear_passwd text, \
primary key (pw_name ) "
#else
#define TABLE_LAYOUT \
  "pw_name text not null, \
pw_passwd text, \
pw_uid integer, pw_gid integer, \
pw_gecos text, \
pw_dir text, \
pw_shell text, \
primary key (pw_name ) "
#endif
#endif

#define RELAY_TABLE_LAYOUT \
  "ip_addr text not null, \
timestamp text, primary key (ip_addr)"

#define LASTAUTH_TABLE_LAYOUT \
  "user text NOT NULL, \
domain text NOT NULL,\
remote_ip text not null,  \
timestamp integer default 0 NOT NULL, \
primary key (user, domain)"

char *vauth_munch_domain(char *);

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define INSERT \
  "insert into `%s` \
( pw_name, pw_domain, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
, pw_clear_passwd ) values ( \"%s\", \"%s\", \
\"%s\", %d, 0, \"%s\", \"%s\", \"%s\" ,\"%s\" )"
#else
#define INSERT \
  "insert into `%s` \
( pw_name, pw_domain, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
) values ( \"%s\", \"%s\", \
\"%s\", %d, 0, \"%s\", \"%s\", \"%s\" )"
#endif
#else
#ifdef CLEAR_PASS
#define INSERT \
  "insert into `%s` \
( pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
, pw_clear_passwd ) values ( \"%s\", \
\"%s\", %d, 0, \"%s\", \"%s\", \"%s\" ,\"%s\" )"
#else
#define INSERT \
  "insert into `%s` \
( pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
 ) values ( \"%s\", \
\"%s\", %d, 0, \"%s\", \"%s\", \"%s\" )"
#endif
#endif

#ifdef MANY_DOMAINS
#define DELETE_USER \
  "delete from `%s` where pw_name = \"%s\" \
and pw_domain = \"%s\" "
#else
#define DELETE_USER "delete from `%s` where pw_name = \"%s\" "
#endif

#ifdef MANY_DOMAINS
#define SETQUOTA \
  "update `%s` set pw_shell = \"%s\" where pw_name = \"%s\" \
and pw_domain = \"%s\" "
#else
#define SETQUOTA "update `%s` set pw_shell = \"%s\" where pw_name = \"%s\" "
#endif

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define USER_SELECT \
  "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell , pw_clear_passwd \
from `%s` where pw_name = \"%s\" and pw_domain = \"%s\" "
#else
#define USER_SELECT \
  "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell \
from `%s` where pw_name = \"%s\" and pw_domain = \"%s\" "
#endif
#else
#ifdef CLEAR_PASS
#define USER_SELECT \
  "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell , pw_clear_passwd \
from `%s` where pw_name = \"%s\" "
#else
#define USER_SELECT \
  "select pw_name, pw_passwd, pw_uid, pw_gid, \
pw_gecos, pw_dir, pw_shell \
from `%s` where pw_name = \"%s\"  "
#endif
#endif

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define GETALL \
  "select pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell, \
pw_clear_passwd from `%s` where pw_domain = \"%s\""
#else
#define GETALL \
  "select pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell \
from `%s` where pw_domain = \"%s\""
#endif
#else
#ifdef CLEAR_PASS
#define GETALL \
  "select pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell, \
pw_clear_passwd from `%s`"
#else
#define GETALL \
  "select pw_name, \
pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir, pw_shell from `%s` "
#endif
#endif

#ifdef MANY_DOMAINS
#ifdef CLEAR_PASS
#define SETPW \
  "update `%s` set pw_passwd = \"%s\", \
pw_uid = %d, pw_gid = %d, pw_gecos = \"%s\", pw_dir = \"%s\", \
pw_shell = \"%s\" \
, pw_clear_passwd = \"%s\" \
where pw_name = \"%s\" \
and pw_domain = \"%s\" "
#else
#define SETPW \
  "update `%s` set pw_passwd = \"%s\", \
pw_uid = %d, pw_gid = %d, pw_gecos = \"%s\", pw_dir = \"%s\", \
pw_shell = \"%s\" \
where pw_name = \"%s\" \
and pw_domain = \"%s\" "
#endif
#else
#ifdef CLEAR_PASS
#define SETPW \
  "update `%s` set pw_passwd = \"%s\", \
pw_uid = %d, pw_gid = %d, pw_gecos = \"%s\", pw_dir = \"%s\", \
pw_shell = \"%s\" \
, pw_clear_passwd = \"%s\" \
where pw_name = \"%s\" "
#else
#define SETPW \
  "update `%s` set pw_passwd = \"%s\", \
pw_uid = %d, pw_gid = %d, pw_gecos = \"%s\", pw_dir = \"%s\", \
pw_shell = \"%s\" \
where pw_name = \"%s\" "
#endif
#endif

#ifdef IP_ALIAS_DOMAINS
#define IP_ALIAS_TABLE_LAYOUT \
  "ip_addr text not null, domain text,  primary key(ip_addr)"
#endif

#define DIR_CONTROL_TABLE_LAYOUT \
  "domain text not null, cur_users integer, \
level_cur integer, level_max integer, \
level_start0 integer, level_start1 integer, level_start2 integer, \
level_end0 integer, level_end1 integer, level_end2 integer, \
level_mod0 integer, level_mod1 integer, level_mod2 integer, \
level_index0 integer , level_index1 integer, level_index2 integer, the_dir text, \
primary key (domain) "

#define DIR_CONTROL_SELECT \
  "cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir"

#define VALIAS_TABLE_LAYOUT \
  "alias text not null, \
domain text not null, \
valias_line text not null"
#define VALIAS_INDEX_LAYOUT "alias, domain"

#ifdef ENABLE_SQL_LOGGING
#define VLOG_TABLE_LAYOUT \
  "id integer PRIMARY KEY AUTO_INCREMENT, \
      user text, passwd text, \
      domain text, logon text, \
      remoteip text, message text, \
      timestamp integer default 0 NOT NULL, error integer, \
      INDEX user_idx (user), \
      INDEX domain_idx (domain), INDEX remoteip_idx (remoteip), \
      INDEX error_idx (error), INDEX message_idx (message)"
#endif

#ifdef ENABLE_MYSQL_LIMITS
#define LIMITS_TABLE_LAYOUT \
  "domain text PRIMARY KEY, \
      maxpopaccounts           integer NOT NULL DEFAULT -1, \
      maxaliases               integer NOT NULL DEFAULT -1, \
      maxforwards              integer NOT NULL DEFAULT -1, \
      maxautoresponders        integer NOT NULL DEFAULT -1, \
      maxmailinglists          integer NOT NULL DEFAULT -1, \
      diskquota                integer NOT NULL DEFAULT 0, \
      maxmsgcount              integer NOT NULL DEFAULT 0, \
      defaultquota             integer NOT NULL DEFAULT 0, \
      defaultmaxmsgcount       integer NOT NULL DEFAULT 0, \
      disable_pop              integer NOT NULL DEFAULT 0, \
      disable_imap             integer NOT NULL DEFAULT 0, \
      disable_dialup           integer NOT NULL DEFAULT 0, \
      disable_passwordchanging integer NOT NULL DEFAULT 0, \
      disable_webmail          integer NOT NULL DEFAULT 0, \
      disable_relay            integer NOT NULL DEFAULT 0, \
      disable_smtp             integer NOT NULL DEFAULT 0, \
      disable_spamassassin     integer NOT NULL DEFAULT 0, \
      delete_spam              integer NOT NULL DEFAULT 0, \
      disable_maildrop		   integer NOT NULL DEFAULT 0, \
      perm_account             integer NOT NULL DEFAULT 0, \
      perm_alias               integer NOT NULL DEFAULT 0, \
      perm_forward             integer NOT NULL DEFAULT 0, \
      perm_autoresponder       integer NOT NULL DEFAULT 0, \
      perm_maillist            integer NOT NULL DEFAULT 0, \
      perm_quota               integer NOT NULL DEFAULT 0, \
      perm_defaultquota        integer NOT NULL DEFAULT 0"
#endif

void vcreate_aliasdomains_table();
int vdelete_sql_aliasdomain(char *alias);
int vcreate_sql_aliasdomain(char *domain, char *alias);

#define ALIASDOMAINS_TABLE_LAYOUT \
  "alias text NOT NULL, \
      domain text NOT NULL, \
      PRIMARY KEY (alias)"

#endif /* VPOPMAIL_SQLITE3_H */
