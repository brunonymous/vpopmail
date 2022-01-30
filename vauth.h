/*
 * $Id: vauth.h 1014 2011-02-03 16:04:37Z volz0r $
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

#ifndef VPOPMAIL_VAUTH_H
#define VPOPMAIL_VAUTH_H

#include <unistd.h>

#ifdef IP_ALIAS_DOMAINS
#define IP_ALIAS_MAP_FILE "etc/ip_alias_map"
#define IP_ALIAS_TOKENS " \t\n"
#endif

#define NULL_REMOTE_IP "0.0.0.0"

/* Note that the new pw_flags field should be used for all access checks.
 * It is a combination of the user's pw_gid and the domain-wide limits.
 * For backward compatability, code can check for VQPASSWD_HAS_PW_FLAGS
 * and fall back on the pw_gid if it's undefined.
 */

#define VQPASSWD_HAS_PW_FLAGS

struct vqpasswd {
  char *pw_name;		/* Username.  */
  char *pw_passwd;		/* Password.  */
  uid_t pw_uid;			/* User ID (not used?).  */
  gid_t pw_gid;			/* user-specific permissions/limits  */
  gid_t pw_flags;		/* permissions/limits (gid | domain limits) */
  char *pw_gecos;		/* Real name.  */
  char *pw_dir;			/* Home directory.  */
  char *pw_shell;		/* User Quota (or NOQUOTA)  */
  char *pw_clear_passwd;	/* Clear password.  */
};

int vauth_open( int will_update );

int vauth_adddomain(char *);
int vauth_deldomain(char *);

int vauth_adduser(char *username, char *domain, char *passwd, char *gecos, char * dir, int apop);

int vauth_crypt(char *user,char *domain,char *clear_pass,struct vqpasswd *vpw);
int vauth_deluser(char *, char *);
int vauth_setquota( char *, char *, char *);
struct vqpasswd *vauth_getpw(char *, char *);
int vauth_setpw(struct vqpasswd *, char *);
struct vqpasswd *vauth_getall(char *, int, int);
void vauth_end_getall();
int vmkpasswd( char *domain );
void vclose();
void vclose1();

int vset_lastauth( char *user, char *domain, char *remoteip);
time_t vget_lastauth( struct vqpasswd *pw, char *domain);
char *vget_lastauthip( struct vqpasswd *pw, char *domain);

/* these routines are used to admin ip aliased domains */
#ifdef IP_ALIAS_DOMAINS
int vget_ip_map( char *ip, char *domain, int domain_size);
int vadd_ip_map( char *ip, char *domain);
int vdel_ip_map( char *ip, char *domain); 
int vshow_ip_map( int first, char *ip, char *domain);
#endif

#define MAX_DIR_LEVELS        3
#define MAX_USERS_PER_LEVEL 100

#define MAX_DIR_NAME  300
typedef struct {
	int level_cur;
	int level_max;
	int level_start[MAX_DIR_LEVELS];
	int level_end[MAX_DIR_LEVELS];
	int level_mod[MAX_DIR_LEVELS];
	int level_index[MAX_DIR_LEVELS]; /* current spot in dir list */ 
	long unsigned cur_users;
	char the_dir[MAX_DIR_NAME];
} vdir_type;

#define MAX_DIR_LIST 62

int open_big_dir(char *domain, uid_t uid, gid_t gid);
int close_big_dir(char *domain, uid_t uid, gid_t gid);
char *next_big_dir(uid_t uid, gid_t gid);
char *inc_dir(vdir_type *, int);
char next_char(char, int, int);
int inc_dir_control(vdir_type *);
int dec_dir_control(char *domain, uid_t uid, gid_t gid);
void print_control();

int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid );
int vwrite_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid);
int vdel_dir_control(char *domain);

char *valias_select( char *alias, char *domain );
char *valias_select_next();
char *valias_select_all( char *alias, char *domain );
char *valias_select_all_next(char *alias);
int valias_insert( char *alias, char *domain, char *alias_line);
int valias_remove( char *alias, char *domain, char *alias_line);
int valias_delete( char *alias, char *domain);
int valias_delete_domain( char *domain);

/* Log to MySQL Added by David Wartell to support MySQL logging */
int logsql(int verror, char *TheUser, char *TheDomain, char *ThePass, char *TheName, char *IpAddr, char *LogLine);
#endif

