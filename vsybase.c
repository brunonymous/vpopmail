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
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <sybfront.h>
#include <sybdb.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#include "vlimits.h"
#include "vsybase.h"

static int is_open = 0;
static LOGINREC *login;
static DBPROCESS *dbproc;

#define SQL_BUF_SIZE 2048
static char SqlBuf[SQL_BUF_SIZE];
static char SqlBuf1[SQL_BUF_SIZE];

#define SMALL_BUFF 200
char IUser[SMALL_BUFF];
char IPass[SMALL_BUFF];
char IGecos[SMALL_BUFF];
char IDir[SMALL_BUFF];
char IShell[SMALL_BUFF];

void vcreate_relay_table();

int err_handler(dbproc, severity, dberr, oserr, dberrstr, oserrstr)
DBPROCESS       *dbproc;
int             severity;
int             dberr;
int             oserr;
char            *dberrstr;
char            *oserrstr;
{
        if ((dbproc == NULL) || (DBDEAD(dbproc))) {
                return(INT_EXIT);
        } else {
                return(INT_CANCEL);
        }
}

int msg_handler(dbproc, msgno, msgstate, severity, msgtext,
                srvname, procname, line)

DBPROCESS       *dbproc;
DBINT           msgno;
int             msgstate;
int             severity;
char            *msgtext;
char            *srvname;
char            *procname;
DBUSMALLINT     line;

{
        return(0);
}


int vauth_open( int will_update )
{
#ifdef VPOPMAIL_DEBUG
show_trace = ( getenv("VPSHOW_TRACE") != NULL);
show_query = ( getenv("VPSHOW_QUERY") != NULL);
dump_data  = ( getenv("VPDUMP_DATA")  != NULL);
#endif

#ifdef VPOPMAIL_DEBUG
    if( show_trace ) {
        fprintf( stderr, "vauth_open()\n");
    }
#endif 


/*
 *  If the connection to this authentication database can fail
 *  you should test access here.  If it works, return 0, else 
 *  return VA_NO_AUTH_CONNECTION.  You can also set the string 
 *  sqlerr to some short descriptive text about the problem, 
 *  and allocate a much longer string, pointed to by last_query
 *  that can be displayed in an error message returned because
 *  of this problem.
 *
 */

	if ( is_open == 1 ) return(0);

	is_open = 1;

	if ( dbinit() == FAIL ) return(-1);

	dberrhandle(err_handler);
	dbmsghandle(msg_handler);
	login=dblogin();

        DBSETLUSER(login, SYBASE_USER);
        DBSETLPWD(login, SYBASE_PASSWD);
        DBSETLAPP(login, SYBASE_APP);

        dbproc = dbopen(login,SYBASE_SERVER);

	if ( dbuse(dbproc, SYBASE_DATABASE) == FAIL ) {
		dbcancel(dbproc);

		snprintf( SqlBuf, sizeof(SqlBuf), "create database %s", SYBASE_DATABASE );
		dbcmd(dbproc, SqlBuf);
		dbsqlexec(dbproc);
		while(dbresults(dbproc) != NO_MORE_RESULTS)
			continue;
		dbuse(dbproc, SYBASE_DATABASE);

	}
	return(0);
}

int vauth_adddomain( char *domain )
{
	return(vauth_adddomain_size( domain, SITE_SIZE ));
}

int vauth_adddomain_size( char *domain, int site_size )
{
 char *tmpstr = NULL;
	
	vauth_open();
	vset_default_domain( domain );

	if ( site_size == LARGE_SITE ) {
		tmpstr = vauth_munch_domain( domain );
		snprintf( SqlBuf1, sizeof (SqlBuf1), "create table %s ( %s )",
			 tmpstr, LARGE_TABLE_LAYOUT );
	} else {
		snprintf( SqlBuf1, sizeof (SqlBuf1), "create table %s ( %s )",
			SYBASE_DEFAULT_TABLE, SMALL_TABLE_LAYOUT);
	}	

	dbcmd(dbproc, SqlBuf1);
	dbsqlexec(dbproc);
	while(dbresults(dbproc) != NO_MORE_RESULTS)
		continue;

	return(0);
}


int vauth_adduser(char *user, char *domain, char *pass, char *gecos, 
	char *dir, int apop )
{
	return(vauth_adduser_size(user, domain, pass, gecos, dir, apop, SITE_SIZE ));
}

int vauth_adduser_size(char *user, char *domain, char *pass, char *gecos, 
	char *dir, int apop, int site_size )
{
 char *domstr;
 int pop;
 char dom_dir[156];
 int uid, gid;
 char dirbuf[200];
 char quota[30];

	vauth_open();
	vset_default_domain( domain );

	strncpy( quota, "NOQUOTA", 30 );

	if ( apop == 0 ) {
		pop = 1;
	} else {
		pop = 2;
	}	
	domstr = vauth_munch_domain( domain );
	if ( site_size == LARGE_SITE && (domain == NULL || domain[0] == 0) ) {
		domstr = SYBASE_LARGE_USERS_TABLE;
	}

	if ( strlen(domain) <= 0 ) {
		if ( strlen(dir) > 0 ) {
			snprintf(dirbuf, sizeof(dirbuf), "%s/users/%s/%s", VPOPMAILDIR, dir, user);
		} else {
			snprintf(dirbuf, sizeof(dirbuf), "%s/users/%s", VPOPMAILDIR, user);
		}
	} else {
		vget_assign(domain, dom_dir, 156, &uid, &gid );
		if ( strlen(dir) > 0 ) {
			snprintf(dirbuf, sizeof(dirbuf), "%s/%s/%s", dom_dir, dir, user);
		} else {
			snprintf(dirbuf, sizeof(dirbuf), "%s/%s", dom_dir, user);
		}
	}

	if ( site_size == LARGE_SITE ) {
		qnprintf( SqlBuf, sizeof(SqlBuf), LARGE_INSERT, domstr,  
		user, pass, pop, gecos, dirbuf, quota);
	} else {
		qnprintf( SqlBuf, sizeof(SqlBuf), SMALL_INSERT, SYBASE_DEFAULT_TABLE,
		user, domain, pass, pop, gecos, dirbuf, quota);
	}

	dbcmd(dbproc, SqlBuf);
	if ( dbsqlexec(dbproc) == FAIL || dbresults(dbproc)== FAIL ) { 
		if ( site_size == LARGE_SITE ) {
			vauth_adddomain_size( SYBASE_LARGE_USERS_TABLE, LARGE_SITE );

			dbcmd(dbproc, SqlBuf);
			if ( dbsqlexec(dbproc)==FAIL || dbresults(dbproc)== FAIL ) { 
				fprintf(stderr, "sybase adduser failed\n");
				return(-1);
			}
			dbcancel(dbproc);

		} else {
			fprintf(stderr, "sybase adduser failed\n");
			return(-1);
		}
	} 
	dbcancel(dbproc);
	return(0);

}

struct vqpasswd *vauth_getpw(char *user, char *domain)
{
	return(vauth_getpw_size( user, domain, SITE_SIZE ));
}

struct vqpasswd *vauth_getpw_size(char *user, char *domain, int site_size)
{
 char in_domain[156];
 char *domstr;
 static struct vqpasswd pwent;

	lowerit(user);
	lowerit(domain);

	snprintf(in_domain, sizeof(in_domain), "%s", domain);

	vauth_open();
	vset_default_domain( in_domain );

	domstr = vauth_munch_domain( in_domain );
	if ( domstr == NULL || domstr[0] == 0 ) {
		domstr = SYBASE_LARGE_USERS_TABLE;
	}

	if ( site_size == LARGE_SITE ) {
		qnprintf( SqlBuf, sizeof(SqlBuf), LARGE_SELECT, domstr, user);
	} else {
		qnprintf( SqlBuf, sizeof(SqlBuf), SMALL_SELECT, SYBASE_DEFAULT_TABLE, user, in_domain);
	}

	dbcmd(dbproc, SqlBuf);
	if ( dbsqlexec(dbproc) == FAIL || dbresults(dbproc)== FAIL ) { 
		printf("vsql_getpw: failed select\n");
		return(NULL);
	}

	pwent.pw_name   = IUser;
	pwent.pw_passwd = IPass;
	pwent.pw_gecos  = IGecos;
	pwent.pw_dir    = IDir;
	pwent.pw_shell  = IShell;

	dbbind(dbproc, 1, NTBSTRINGBIND, (DBINT)0, (BYTE *)pwent.pw_name);
	dbbind(dbproc, 2, NTBSTRINGBIND, (DBINT)0, (BYTE *)pwent.pw_passwd);
	dbbind(dbproc, 3, INTBIND, (DBINT)0, (BYTE *)&pwent.pw_uid);
	dbbind(dbproc, 4, INTBIND, (DBINT)0, (BYTE *)&pwent.pw_gid);
	dbbind(dbproc, 5, NTBSTRINGBIND, (DBINT)0, (BYTE *)pwent.pw_gecos);
	dbbind(dbproc, 6, NTBSTRINGBIND, (DBINT)0, (BYTE *)pwent.pw_dir);
	dbbind(dbproc, 7, NTBSTRINGBIND, (DBINT)0, (BYTE *)pwent.pw_shell);

	mem_size = 0;
	while( dbnextrow(dbproc) != NO_MORE_ROWS ) {
		++mem_size;
	}
	dbcancel(dbproc);
	if ( mem_size == 0 ) return(NULL);

	vlimits_setflags (&pwent, in_domain);

	return(&pwent);
}

int vauth_deldomain( char *domain )
{
	return(vauth_deldomain_size( domain, SITE_SIZE ));
}

int vauth_deldomain_size( char *domain, int site_size )
{
 char *tmpstr;

	vauth_open();
	vset_default_domain( domain );
	tmpstr = vauth_munch_domain( domain );

	if ( site_size == LARGE_SITE ) {
		snprintf( SqlBuf, sizeof(SqlBuf), "drop table %s", tmpstr);
	} else {
		qnprintf( SqlBuf, sizeof(SqlBuf), "delete from %s where pw_domain = '%s'",
			SYBASE_DEFAULT_TABLE, domain );
	}

	dbcmd(dbproc, SqlBuf);
	if ( dbsqlexec(dbproc) == FAIL || dbresults(dbproc)== FAIL ) { 
		return(-1);
	} 
	dbcancel(dbproc);
	return(0);
}

int vauth_deluser( char *user, char *domain )
{
	return(vauth_deluser_size( user, domain, SITE_SIZE)); 
}

int vauth_deluser_size( char *user, char *domain, int site_size )
{
 char *tmpstr;

	vauth_open();
	vset_default_domain( domain );

	if ( site_size == LARGE_SITE ) {
		if ( domain == NULL || domain[0] == 0 ) {
			tmpstr = SYBASE_LARGE_USERS_TABLE;
		} else {
			tmpstr = vauth_munch_domain( domain );
		}
		qnprintf( SqlBuf, sizeof(SqlBuf), "delete from %s where pw_name = '%s'", 
			tmpstr, user );
	} else {
		qnprintf( SqlBuf, sizeof(SqlBuf), 
		"delete from %s where pw_name = '%s' and pw_domain = '%s'", 
			SYBASE_DEFAULT_TABLE, user, domain );
	}
	dbcmd(dbproc, SqlBuf);
	if ( dbsqlexec(dbproc) == FAIL || dbresults(dbproc)== FAIL ) { 
		fprintf(stderr, "sybase query\n");
		return(-1);
	} 
	dbcancel(dbproc);
	return(0);
}

int vauth_setquota( char *user, char *domain, char *quota)
{
	return(vauth_setquota_size( user, domain, quota, SITE_SIZE));
}

int vauth_setquota_size( char *user, char *domain, char *quota, int site_size)
{
 char *tmpstr;

	vauth_open();
	vset_default_domain( domain );

	if ( site_size == LARGE_SITE ) {
		tmpstr = vauth_munch_domain( domain );
		qnprintf( SqlBuf, sizeof(SqlBuf), 
			"update %s set pw_shell = '%s' where pw_name = '%s'", 
			tmpstr, quota, user );
	} else {
		qnprintf( SqlBuf, sizeof(SqlBuf), 
			"update %s set pw_shell = '%s' where pw_name = '%s' and pw_domain = '%s'", 
			SYBASE_DEFAULT_TABLE, quota, user, domain );
	}
	dbcmd(dbproc, SqlBuf);
	if ( dbsqlexec(dbproc) == FAIL || dbresults(dbproc)== FAIL ) { 
		fprintf(stderr, "sybase query\n");
		return(-1);
	} 
	dbcancel(dbproc);
	return(0);
}

int vauth_vpasswd( char *user, char *domain, char *pass, int apop )
{
	return(vauth_vpasswd_size( user, domain, pass, apop, SITE_SIZE ));
}

int vauth_vpasswd_size( char *user, char *domain, char *pass, 
			int apop, int site_size )
{
 char *tmpstr;
 uid_t uid;
 gid_t gid;
 uid_t myuid;

 	myuid = geteuid();
	vget_assign(domain,NULL,0,&uid,&gid);
	if (myuid != 0 && myuid != uid ) {
		return(VA_BAD_UID);
	}

	vauth_open();
	vset_default_domain( domain );

	if ( site_size == LARGE_SITE ) {
		tmpstr = vauth_munch_domain( domain );
		qnprintf( SqlBuf, sizeof(SqlBuf), 
			"update %s set pw_passwd = '%s' where pw_name = '%s'", 
			tmpstr, pass, user );
	} else {
		qnprintf( SqlBuf, sizeof(SqlBuf), 
			"update %s set pw_passwd = '%s' where pw_name = '%s' and pw_domain = '%s'", 
			SYBASE_DEFAULT_TABLE, pass, user, domain );
	}
	dbcmd(dbproc, SqlBuf);
	if ( dbsqlexec(dbproc) == FAIL || dbresults(dbproc)== FAIL ) { 
		fprintf(stderr, "sybase query\n");
		return(-1);
	} 
	dbcancel(dbproc);
	return(0);
}

void vauth_end_getall()
{
}

struct vqpasswd *vauth_getall(char *domain, int first, int sortit)
{
	return(vauth_getall_size(domain, first, sortit, SITE_SIZE));
}

struct vqpasswd *vauth_getall_size(char *domain, int first, int sortit, int site_size)
{
 char *domstr = NULL;
 static struct vqpasswd pwent;
 static int more = 0;

	vset_default_domain( domain );

	if ( site_size == LARGE_SITE ) {
		domstr = vauth_munch_domain( domain );
	}

	if ( first == 1 ) {
		vauth_open();

		if ( site_size == LARGE_SITE ) {
			qnprintf( SqlBuf, sizeof(SqlBuf), LARGE_GETALL, domstr);
		} else {
			qnprintf( SqlBuf, sizeof(SqlBuf), SMALL_GETALL, SYBASE_DEFAULT_TABLE, domain);
		}
		if ( sortit == 1 ) {
			strcat( SqlBuf, " order by pw_name");
		}
		dbcmd(dbproc, SqlBuf);
		if ( dbsqlexec(dbproc) == FAIL || dbresults(dbproc)== FAIL ) { 
			printf("vsql_getpw: failed select\n");
			return(NULL);
		}
	} else if ( more == 0 ) {
		return(NULL);
	}

	pwent.pw_name   = IUser;
	pwent.pw_passwd = IPass;
	pwent.pw_gecos  = IGecos;
	pwent.pw_dir    = IDir;
	pwent.pw_shell  = IShell;

	if ( dbnextrow(dbproc) != NO_MORE_ROWS ) {
		strncpy(pwent.pw_name,(char *)dbretdata(dbproc,1),SMALL_BUFF);
		strncpy(pwent.pw_passwd,(char *)dbretdata(dbproc,2),SMALL_BUFF);
		pwent.pw_uid    = atoi(dbretdata(dbproc,3));
		pwent.pw_gid    = atoi(dbretdata(dbproc,4));
		strncpy(pwent.pw_gecos,dbretdata(dbproc,5),SMALL_BUFF);
		strncpy(pwent.pw_dir,dbretdata(dbproc,6),SMALL_BUFF);
		strncpy(pwent.pw_shell, dbretdata(dbproc,7),SMALL_BUFF);
		more = 1;
		vlimits_setflags(&pwent,domain);
		return(&pwent);
	}
	more = 0;
	dbcancel(dbproc);
	return(NULL);
}

char *vauth_munch_domain( char *domain )
{
 int i;
 static char tmpbuf[50];

	if ( domain == NULL || domain[0] == 0 ) return(domain);

	for(i=0;domain[i]!=0;++i){
		tmpbuf[i] = domain[i];
		if ( domain[i] == '.' || domain[i] == '-' ) {
			tmpbuf[i] = SYBASE_DOT_CHAR;
		}
	}
	tmpbuf[i] = 0; 
	return(tmpbuf);
}

int vauth_setpw( struct vqpasswd *inpw, char *domain )
{
	return(vauth_setpw_size( inpw, domain, SITE_SIZE));
}

int vauth_setpw_size( struct vqpasswd *inpw, char *domain, int site_size)
{
 char *tmpstr;
 uid_t myuid;
 uid_t uid;
 gid_t gid;
 
#ifdef USE_ONCHANGE
 char user_domain[MAX_BUFF];
#endif  

 	myuid = geteuid();
	if ( myuid != VPOPMAIL && myuid != 0 ) return(VA_BAD_UID);
	
#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", inpw->pw_name, domain);  
  on_change("mod_user", user_domain, "-", 0, 0);
#endif

	vauth_open();
	vset_default_domain( domain );

	if ( site_size == LARGE_SITE ) {
		tmpstr = vauth_munch_domain( domain );
		qnprintf( SqlBuf, sizeof(SqlBuf), LARGE_SETPW,
			tmpstr, 
			inpw->pw_passwd, 
			inpw->pw_uid,
			inpw->pw_gid, 
			inpw->pw_gecos, 
			inpw->pw_dir, 
			inpw->pw_shell, 
			inpw->pw_name );
	} else {
		qnprintf( SqlBuf, sizeof(SqlBuf), SMALL_SETPW,
			SYBASE_DEFAULT_TABLE, 
			inpw->pw_passwd, 
			inpw->pw_uid, 
			inpw->pw_gid, 
			inpw->pw_gecos, 
			inpw->pw_dir, 
			inpw->pw_shell, 
			inpw->pw_name, 
			domain);
	}

	dbcmd(dbproc, SqlBuf);
	if ( dbsqlexec(dbproc) == FAIL || dbresults(dbproc)== FAIL ) { 
		fprintf(stderr, "sybase query\n");
		return(-1);
	} 
	dbcancel(dbproc);

#ifdef SQWEBMAIL_PASS
	tmpstr = vget_assign(domain, NULL, 0, &uid, &gid );
    vsqwebmail_pass( inpw->pw_dir, inpw->pw_passwd, uid, gid);
#endif

#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", inpw->pw_name, domain);  
  on_change("mod_user", user_domain, "-", 1, 1);
#endif

	return(0);
}

void vclear_open_smtp(time_t clear_minutes, time_t mytime)
{
/*
 time_t delete_time;
 int err;
	
	if ( (err=vauth_open()) != 0 ) exit(0);
	delete_time = mytime - clear_minutes;

	snprintf( SqlBuf, sizeof(SqlBuf), "delete from relay where timestamp <= %d", 
		(int)delete_time);
	if (mysql_query(&mysql,SqlBuf)) {
		vcreate_relay_table();
		return;
	}
*/
}

int vmkpasswd( char *domain )
{
	return(0);
}

void vclose()
{
	if ( is_open == 1 ) {
		is_open = 0;
		dbclose(proc);
	}
}

#ifdef IP_ALIAS_DOMAINS
int vget_ip_map( char *ip, char *domain, int domain_size)
{
	if ( ip == NULL || strlen(ip) <= 0 ) return(0);
	return(0);
}

int vadd_ip_map( char *ip, char *domain) 
{
	return(0);
}

int vdel_ip_map( char *ip, char *domain) 
{
	return(0);
}

int vshow_ip_map( int first, char *ip, char *domain);
{
	return(0);
}
#endif

int vauth_crypt(char *user,char *domain,char *clear_pass,struct vqpasswd *vpw)
{
  const char *c;
	const char *p;
  if ( vpw == NULL ) return(-1);
	p = vpw->pw_passwd;
	
  /* if needed remove {XXX-CRYPT}$ */
	if (p[0] == '{') {
		const char *k = strchr(p, '}');
		if (k != NULL) p = k + 1;
	}
	
  c = crypt(clear_pass, p);
  if (c == NULL) return (-1);
  return(strcmp(c, p));
}
