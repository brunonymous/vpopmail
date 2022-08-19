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
#include <ctype.h>
#include <pwd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <libpq-fe.h> /* required pgsql front-end headers */

#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#include "vlimits.h"
#include "vpgsql.h"

//  Variables to control debug output
#ifdef VPOPMAIL_DEBUG
int show_trace=0;
int show_query=0;
int dump_data=0;
#endif

const char *pgsql_server_default = "localhost";
const char *pgsql_database_default = "vpopmail";
const char *pgsql_user_default = "postgres";
const char *pgsql_password_default = "";
const char *pgsql_socket_default = "0";
 
char PGSQL_SERVER[256];
char PGSQL_SOCKET[8];
int PGSQL_PORT;
char PGSQL_DATABASE[64];
char PGSQL_USER[64];
char PGSQL_PASSWORD[128];

/* pgsql has no built-in replication, yet.
   #ifdef PGSQL_REPLICATION
   static PGconn *pgc_read;
   #else
   #define pgc_read pgc_update
   #endif

   #ifdef PGSQL_REPLICATION
   static int read_open = 0;
   #else
   #define read_open update_open
   #endif
   #ifdef PGSQL_REPLICATION	
   static PGresult *res_read = NULL;
   #else
   #define res_read res_update
   #endif
*/

/* 
   read-only and read-write connections 
   to be implemented later...
static PGconn *pgc_update;
static PGconn *pgc_read;
static PGconn *pgc_read_getall;
*/

static PGconn *pgc; /* pointer to pgsql connection */
static int is_open = 0;

#define SQL_BUF_SIZE 2048
static char SqlBufRead[SQL_BUF_SIZE];
static char SqlBufUpdate[SQL_BUF_SIZE];

#define SMALL_BUFF 200
char IUser[SMALL_BUFF];
char IPass[SMALL_BUFF];
char IGecos[SMALL_BUFF];
char IDir[SMALL_BUFF];
char IShell[SMALL_BUFF];
char IClearPass[SMALL_BUFF];

void vcreate_dir_control(char *domain);
void vcreate_vlog_table();

#ifdef POP_AUTH_OPEN_RELAY
void vcreate_relay_table();
#endif

#ifdef VALIAS
void vcreate_valias_table();
#endif

#ifdef ENABLE_AUTH_LOGGING
void vcreate_lastauth_table();
#endif

/* pgsql BEGIN TRANSACTION ********/
int pg_begin(void)
{
  PGresult *pgres;
  pgres=PQexec(pgc, "BEGIN");
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "pg_begin: %s\n", PQerrorMessage(pgc));
    if (pgres) PQclear (pgres);
    return -1;
  }
  PQclear(pgres);
  return 0;
}                                       

/* pgsql END TRANSACTION ********/
int pg_end(void)
{
  PGresult *pgres;
  pgres=PQexec(pgc, "END");
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "pg_end: %s\n", PQerrorMessage(pgc));
    if (pgres) PQclear (pgres);
    return -1;
  }
  PQclear(pgres);
  return 0;
}                                                   

int load_connection_info() {

    FILE *fp;
    char conn_info[256];
    char config[256];
    int eof;
    char *p;
    char *p2;
    static int loaded = 0;
    
    if (loaded) return 0;
    loaded = 1;
    
    sprintf(config, "%s/etc/%s", VPOPMAILDIR, "vpopmail.pgsql");

    fp = fopen(config, "r");
    if (fp == NULL) {
        fprintf(stderr, "vpgsql: can't read settings from %s\n", config);
        return(VA_NO_AUTH_CONNECTION);
    }
    
    /* skip comments and blank lines */
    do {
        eof = (fgets (conn_info, sizeof(conn_info), fp) == NULL);
    } while (!eof && ((*conn_info == '#') || (*conn_info == '\n')));

    if (eof) {
        /* no valid data read, return error */
        fprintf(stderr, "vpgsql: no valid settings in %s\n", config);
        fclose(fp);
        return(VA_NO_AUTH_CONNECTION);
    }
    fclose(fp);
    
    p = conn_info;
    p2 = strchr(p, '|');
    if (p2 == NULL) return VA_PARSE_ERROR;
    if (p != p2) {
        strncpy(PGSQL_SERVER, p, p2 - p);
    } else {
        strcpy(PGSQL_SERVER, pgsql_server_default);
    }
        
    p = p2 + 1;
    p2 = strchr(p, '|');
    if (p2 == NULL) return VA_PARSE_ERROR;
    if (p != p2) {
        strncpy(PGSQL_SOCKET, p, p2 - p);
    } else {
        strcpy(PGSQL_SOCKET, pgsql_socket_default);
    }
    PGSQL_PORT = atoi(PGSQL_SOCKET);
    
    p = p2 + 1;
    p2 = strchr(p, '|');
    if (p2 == NULL) return VA_PARSE_ERROR;
    if (p != p2) {
        strncpy(PGSQL_USER, p, p2 - p);
    } else {
        strcpy(PGSQL_USER, pgsql_user_default);
    }
        
    p = p2 + 1;
    p2 = strchr(p, '|');
    if (p2 == NULL) return VA_PARSE_ERROR;
    if (p != p2) {
        strncpy(PGSQL_PASSWORD, p, p2 - p);
    } else {
        strcpy(PGSQL_PASSWORD, pgsql_password_default);
    }
        
    p = p2 + 1;
    p2 = strchr(p, '\n');
    if (p2 == NULL) return VA_PARSE_ERROR;
    if (p != p2) {
        strncpy(PGSQL_DATABASE, p, p2 - p);
    } else {
        strcpy(PGSQL_DATABASE, pgsql_database_default);
    }
          
    return 0;
}

/*** Open a connection to pgsql ***/
int vauth_open( int will_update )
{
    char dbconnect[512];
    int r;

#ifdef VPOPMAIL_DEBUG
show_trace = ( getenv("VPSHOW_TRACE") != NULL);
show_query = ( getenv("VPSHOW_QUERY") != NULL);
dump_data  = ( getenv("VPDUMP_DATA")  != NULL);
#endif

#ifdef VPOPMAIL_DEBUG
    if( show_trace ) {
        fprintf( stderr, "vauth_open(%d)\n",will_update);
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

  if ( is_open != 0 ) return(0);
  is_open = 1;
  verrori = 0;
  
  verrori = load_connection_info();
  if (verrori) return -1;

  /* Try to connect to the pgserver with the specified database. */
  if (strlen(PGSQL_SERVER) != 0) {
    if (strlen(PGSQL_PASSWORD) != 0) {
       r = snprintf(dbconnect, 512, "host=%s port=%d user=%s password=%s dbname=%s", 
        PGSQL_SERVER, PGSQL_PORT, PGSQL_USER, PGSQL_PASSWORD, PGSQL_DATABASE);
    } else {
      r = snprintf(dbconnect, 512, "host=%s port=%d user=%s dbname=%s", 
        PGSQL_SERVER, PGSQL_PORT, PGSQL_USER, PGSQL_DATABASE);
    }
  } else {
    if (strlen(PGSQL_PASSWORD) != 0) {    
      r = snprintf(dbconnect, 512, "user=%s password=%s dbname=%s", 
        PGSQL_USER, PGSQL_PASSWORD, PGSQL_DATABASE);
    } else {
      r = snprintf(dbconnect, 512, "user=%s dbname=%s", PGSQL_USER, PGSQL_DATABASE);
    }
  }
  if (r == -1) {
    fprintf(stderr, "vauth_open: string buffer too short\n");
    return -1;
  }
  pgc = PQconnectdb(dbconnect);
  
  if( PQstatus(pgc) == CONNECTION_BAD) {
    fprintf(stderr, "vauth_open: can't connect: %s\n", PQerrorMessage(pgc));
    return VA_NO_AUTH_CONNECTION;
  }	
  return(0);
}

int vauth_create_table (char *table, char *layout, int showerror)
{
  int err;
  PGresult *pgres;
  char SqlBufCreate[SQL_BUF_SIZE];
  
  if ((err = vauth_open(1))) return (err);

  snprintf(SqlBufCreate, SQL_BUF_SIZE,
    "CREATE TABLE %s ( %s )", table, layout);
  pgres=PQexec(pgc, SqlBufCreate);
  if (!pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK) {
    err = -1;
    if (showerror)
      fprintf (stderr, "vpgsql: error creating table '%s': %s\n", table, 
        PQerrorMessage(pgc));
  } else err = 0;
  
  if (pgres) PQclear (pgres);
  return err;
}

int vauth_adddomain( char *domain )
{
#ifndef MANY_DOMAINS
  vset_default_domain( domain );
  return (vauth_create_table (vauth_munch_domain( domain ), TABLE_LAYOUT, 1));
#else
  /* if creation fails, don't show an error */
  vauth_create_table (PGSQL_DEFAULT_TABLE, TABLE_LAYOUT, 0);
  return (0);
#endif
}

int vauth_adduser(char *user, char *domain, char *pass, char *gecos, 
		  char *dir, int apop )
{
  char *domstr;
  char dom_dir[156];
  uid_t uid; 
  gid_t gid;
  char dirbuf[200];
  char quota[30];
  char Crypted[100];
  int err;
  PGresult *pgres;
    
  if ( (err=vauth_open(1)) != 0 ) return(err);
  vset_default_domain( domain );

  strncpy( quota, "NOQUOTA", 30 );

#ifndef MANY_DOMAINS
  domstr = vauth_munch_domain( domain );
#else
  domstr = PGSQL_DEFAULT_TABLE;
#endif
  if ( domain == NULL || domain[0] == 0 ) {
    domstr = PGSQL_LARGE_USERS_TABLE;
  }

  *dirbuf = '\0';

  if ( strlen(domain) <= 0 ) {
    if ( strlen(dir) > 0 ) {
      snprintf(dirbuf, sizeof(dirbuf), 
	       "%s/users/%s/%s", VPOPMAILDIR, dir, user);
    } else {
      snprintf(dirbuf, sizeof(dirbuf), "%s/users/%s", VPOPMAILDIR, user);
    }
  } else {
    vget_assign(domain, dom_dir, 156, &uid, &gid );
    if ( strlen(dir) > 0 ) {
      snprintf(dirbuf,sizeof(dirbuf), "%s/%s/%s", dom_dir, dir, user);
    } else {
      snprintf(dirbuf,sizeof(dirbuf), "%s/%s", dom_dir, user);
    }
  }

  if ( pass[0] != 0 ) {
    mkpasswd3(pass,Crypted, 100);
  } else {
    Crypted[0] = 0;
  }

  qnprintf( SqlBufUpdate, sizeof(SqlBufUpdate), INSERT, 
	    domstr, user, 
#ifdef MANY_DOMAINS
	    domain,
#endif
	    Crypted, apop, gecos, dirbuf, quota
#ifdef CLEAR_PASS
	    ,pass
#endif
	    );
  if(! ( pgres=PQexec(pgc,SqlBufUpdate) )||
     PQresultStatus(pgres)!=PGRES_COMMAND_OK )  {
    fprintf(stderr, "vauth_adduser: %s\npgsql: %s\n", 
	    SqlBufUpdate, PQerrorMessage(pgc));
  }
  if( pgres )  PQclear(pgres);
  return(0);

}
struct vqpasswd *vauth_getpw(char *user, char *domain)
{
  char in_domain[156];
  char *domstr;
  static struct vqpasswd vpw;
  int err;
  PGresult *pgres;

  verrori = 0;
  if ( (err=vauth_open(0)) != 0 ) {
    verrori = err;
    return(NULL);
  }
  lowerit(user);
  lowerit(domain);

  snprintf (in_domain, sizeof(in_domain), "%s", domain);

  vset_default_domain( in_domain );

#ifndef MANY_DOMAINS
  domstr = vauth_munch_domain( in_domain );
#else
  domstr = PGSQL_DEFAULT_TABLE; 
#endif

  if ( domstr == NULL || domstr[0] == 0 ) {
    domstr = PGSQL_LARGE_USERS_TABLE;
  }

  qnprintf(SqlBufRead, SQL_BUF_SIZE, USER_SELECT, domstr, user
#ifdef MANY_DOMAINS
	   ,in_domain
#endif	
	   );
  pgres=PQexec(pgc, SqlBufRead);
  if ( ! pgres || PQresultStatus(pgres)!=PGRES_TUPLES_OK) {
    if( pgres ) PQclear(pgres);	
#ifdef DEBUG
    fprintf(stderr, 
	    "vauth_getpw: failed select: %s : %s\n", 
	    SqlBufRead, PQerrorMessage(pgc));
#endif
    return NULL;
  }
  if ( PQntuples(pgres) <= 0 ) { /* rows count */
    PQclear(pgres);
    return NULL;
  }

  memset(IUser, 0, sizeof(IUser));
  memset(IPass, 0, sizeof(IPass));
  memset(IGecos, 0, sizeof(IGecos));
  memset(IDir, 0, sizeof(IDir));
  memset(IShell, 0, sizeof(IShell));
  memset(IClearPass, 0, sizeof(IClearPass));

  vpw.pw_name   = IUser;
  vpw.pw_passwd = IPass;
  vpw.pw_gecos  = IGecos;
  vpw.pw_dir    = IDir;
  vpw.pw_shell  = IShell;
  vpw.pw_clear_passwd  = IClearPass;

  strncpy(vpw.pw_name,PQgetvalue( pgres, 0, 0 ),SMALL_BUFF);
  strncpy(vpw.pw_passwd,PQgetvalue( pgres, 0, 1 ),SMALL_BUFF);
  vpw.pw_uid    = atoi(PQgetvalue( pgres, 0, 2 ));
  vpw.pw_gid    = atoi(PQgetvalue( pgres, 0, 3 ));
  strncpy(vpw.pw_gecos,PQgetvalue( pgres, 0, 4 ),SMALL_BUFF);
  strncpy(vpw.pw_dir,PQgetvalue( pgres, 0, 5 ),SMALL_BUFF);
  strncpy(vpw.pw_shell, PQgetvalue( pgres, 0, 6 ),SMALL_BUFF);
#ifdef CLEAR_PASS
  if ( PQgetvalue( pgres, 0, 7 ) != 0 )
    strncpy(vpw.pw_clear_passwd, PQgetvalue( pgres, 0, 7 ),SMALL_BUFF);
#endif

  vlimits_setflags (&vpw, in_domain);

  return(&vpw);
}

int vauth_deldomain( char *domain )
{
  PGresult *pgres;
  char *tmpstr;
  int err;
    
  if ( (err=vauth_open(1)) != 0 ) return(err);
  vset_default_domain( domain );

#ifndef MANY_DOMAINS
  tmpstr = vauth_munch_domain( domain );
  snprintf( SqlBufUpdate, SQL_BUF_SIZE, "drop table %s", tmpstr);
#else
  tmpstr = PGSQL_DEFAULT_TABLE;
  qnprintf(SqlBufUpdate,SQL_BUF_SIZE,
	   "delete from %s where pw_domain = '%s'",
	   tmpstr, domain );
#endif 
  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK){
    fprintf(stderr,"vauth_deldomain: pgsql query: %s",
	    PQerrorMessage(pgc));
    if(pgres) PQclear(pgres);
    return(-1);
  } 
  if(pgres) PQclear(pgres);

#ifdef VALIAS 
    valias_delete_domain( domain);
#endif

#ifdef ENABLE_AUTH_LOGGING
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
        "delete from lastauth where domain = '%s'", domain );
    pgres=PQexec(pgc, SqlBufUpdate);
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK) {
      return(-1);
    } 	
    if(pgres) PQclear(pgres);
#endif

#ifdef ENABLE_SQL_LOGGING
#ifdef ENABLE_SQL_REMOVE_DELETED
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
       "delete from vlog where domain = '%s'", domain );
    pgres=PQexec(pgc, SqlBufUpdate);
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK) {
      return(-1);
    }
#endif
#endif
    return(0);
}

int vauth_deluser( char *user, char *domain )
{
  PGresult *pgres;
  char *tmpstr;
  int err = 0;
    
  if ( (err=vauth_open(1)) != 0 ) return(err);
  vset_default_domain( domain );

#ifndef MANY_DOMAINS
  if ( domain == NULL || domain[0] == 0 ) {
    tmpstr = PGSQL_LARGE_USERS_TABLE;
  } else {
    tmpstr = vauth_munch_domain( domain );
  }
#else
  tmpstr = PGSQL_DEFAULT_TABLE;
#endif

  qnprintf( SqlBufUpdate, SQL_BUF_SIZE, DELETE_USER, tmpstr, user
#ifdef MANY_DOMAINS
	    , domain
#endif
	    );

  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    err = -1;
  } 
  if( pgres ) PQclear(pgres);

#ifdef ENABLE_AUTH_LOGGING
  qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	    "delete from lastauth where user = '%s' and domain = '%s'", 
	    user, domain );
  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    err = -1;
  }
  if( pgres ) PQclear(pgres);
#endif

#ifdef ENABLE_SQL_LOGGING
#ifdef ENABLE_SQL_REMOVE_DELETED
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
        "delete from vlog where domain = '%s' and user='%s'", 
       domain, user );
    pgres=PQexec(pgc, SqlBufUpdate);
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK) {
      err = -1;
    }
#endif
#endif

  return(err);
}

int vauth_setquota( char *username, char *domain, char *quota)
{
  PGresult *pgres;
  char *tmpstr;
  int err;

  if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR
  if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif
  if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(quota) > MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);
    
  if ( (err=vauth_open(1)) != 0 ) return(err);
  vset_default_domain( domain );

#ifndef MANY_DOMAINS
  tmpstr = vauth_munch_domain( domain );
#else
  tmpstr = PGSQL_DEFAULT_TABLE; 
#endif

  qnprintf( SqlBufUpdate, SQL_BUF_SIZE, SETQUOTA, tmpstr, quota, username
#ifdef MANY_DOMAINS
	    , domain
#endif		
	    );

  pgres = PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, 
	    "vauth_setquota: query failed: %s\n", PQerrorMessage(pgc));
    if( pgres ) PQclear(pgres);
    return(-1);
  } 
  if( pgres ) PQclear(pgres);
  return(0);
}

struct vqpasswd *vauth_getall(char *domain, int first, int sortit)
{
  static PGresult *pgres=NULL; 
  /* ntuples - number of tuples ctuple - current tuple */
  static unsigned ntuples=0, ctuple=0;      

  char *domstr = NULL;
  static struct vqpasswd vpw;
  int err;

  vset_default_domain( domain );

#ifdef MANY_DOMAINS
  domstr = PGSQL_DEFAULT_TABLE; 
#else
  domstr = vauth_munch_domain( domain );
#endif

  if ( first == 1 ) {
    if ( (err=vauth_open(0)) != 0 ) return(NULL);
    qnprintf(SqlBufRead,  SQL_BUF_SIZE, GETALL, domstr
#ifdef MANY_DOMAINS
	     ,domain
#endif
	     );
    if ( sortit == 1 ) {
      strncat( SqlBufRead, " order by pw_name", SQL_BUF_SIZE-strlen(SqlBufRead)-1);
    }
    if ( pgres ) { /* reset state if we had previous result */
      PQclear(pgres);    // clear previous result	
      pgres=NULL;
      ntuples=ctuple=0;	
    }	
    pgres = PQexec(pgc, SqlBufRead);
    if( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      fprintf(stderr, "vauth_getall:query failed[5]: %s\n", PQerrorMessage(pgc));
      if( pgres ) { 
        PQclear(pgres);
        pgres=NULL;
      }
      return (NULL);
    }
    ntuples = PQntuples( pgres );
  }

  if ( ctuple == ntuples ) {
    PQclear(pgres);
    pgres=NULL;
    ctuple=ntuples=0;
    return NULL;
  }
  memset(IUser, 0, sizeof(IUser));
  memset(IPass, 0, sizeof(IPass));
  memset(IGecos, 0, sizeof(IGecos));
  memset(IDir, 0, sizeof(IDir));
  memset(IShell, 0, sizeof(IShell));
  memset(IClearPass, 0, sizeof(IClearPass));
  
  vpw.pw_name   = IUser;
  vpw.pw_passwd = IPass;
  vpw.pw_gecos  = IGecos;
  vpw.pw_dir    = IDir;
  vpw.pw_shell  = IShell;
  vpw.pw_clear_passwd  = IClearPass;
    
  strncpy(vpw.pw_name, PQgetvalue( pgres, ctuple, 0 ),SMALL_BUFF );
  strncpy(vpw.pw_passwd, PQgetvalue( pgres, ctuple, 1 ),SMALL_BUFF );

  vpw.pw_uid    = atoi(PQgetvalue( pgres, ctuple, 2 ));
  vpw.pw_gid    = atoi(PQgetvalue( pgres, ctuple, 3 ));

  strncpy(vpw.pw_gecos, PQgetvalue( pgres, ctuple, 4 ),SMALL_BUFF);
  strncpy(vpw.pw_dir, PQgetvalue( pgres, ctuple, 5 ),SMALL_BUFF);
  strncpy(vpw.pw_shell, PQgetvalue( pgres, ctuple, 6 ),SMALL_BUFF);

#ifdef CLEAR_PASS
    if (PQgetvalue( pgres, ctuple, 7)!= 0 ) {
      strncpy(vpw.pw_clear_passwd, PQgetvalue( pgres, ctuple, 7 ),SMALL_BUFF);
    }
#endif
    ctuple++;
    vlimits_setflags(&vpw,domain);
    return(&vpw);
}

void vauth_end_getall()
{
  /* not applicable in pgsql? */
}

char *vauth_munch_domain( char *domain )
{
  int i;
  static char tmpbuf[512];

  if ( domain == NULL || domain[0] == 0 ) return(domain);

  for(i=0;domain[i]!=0 && i < (sizeof(tmpbuf) - 1);++i){
    tmpbuf[i] = tolower(domain[i]);
    if ( domain[i] == '.' || domain[i] == '-' ) {
      tmpbuf[i] = SQL_DOT_CHAR;
    }
  }
  tmpbuf[i] = 0; 
  return(tmpbuf);
}

int vauth_setpw( struct vqpasswd *inpw, char *domain )
{
  PGresult *pgres;
  char *tmpstr;
  uid_t myuid;
  uid_t uid;
  gid_t gid;
  int err;

#ifdef USE_ONCHANGE
 char user_domain[MAX_BUFF];
#endif 

  err = vcheck_vqpw(inpw, domain);
  if ( err != 0 ) return(err);

  vget_assign(domain,NULL,0,&uid,&gid);
  myuid = geteuid();
  if ( myuid != 0 && myuid != uid ) {
    return(VA_BAD_UID);
  }

  if ( (err=vauth_open(1)) != 0 ) return(err);
  
#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", inpw->pw_name, domain);  
  on_change("mod_user", user_domain, "-", 0, 0);
#endif
  
  vset_default_domain( domain );

#ifndef MANY_DOMAINS
  tmpstr = vauth_munch_domain( domain );
#else
  tmpstr = PGSQL_DEFAULT_TABLE; 
#endif

  qnprintf( SqlBufUpdate,SQL_BUF_SIZE,SETPW,
            tmpstr, 
            inpw->pw_passwd,
            inpw->pw_uid,
            inpw->pw_gid, 
            inpw->pw_gecos,
            inpw->pw_dir, 
            inpw->pw_shell, 
#ifdef CLEAR_PASS
            inpw->pw_clear_passwd,
#endif
            inpw->pw_name
#ifdef MANY_DOMAINS
            ,domain
#endif
            );
  pgres=PQexec(pgc, SqlBufUpdate);
  if ( !pgres || PQresultStatus(pgres)!= PGRES_COMMAND_OK ) {
    fprintf(stderr, "vauth_setpw: pgsql query[6]: %s\n", 
	    PQerrorMessage(pgc));
    if( pgres )  PQclear(pgres);
    return(-1);
  } 
  if( pgres ) PQclear(pgres);
#ifdef SQWEBMAIL_PASS
    vsqwebmail_pass( inpw->pw_dir, inpw->pw_passwd, uid, gid);
#endif

#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", inpw->pw_name, domain);  
  on_change("mod_user", user_domain, "-", 1, 1);
#endif

    return(0);
}

#ifdef POP_AUTH_OPEN_RELAY
int vopen_smtp_relay()
{
  PGresult *pgres;
  char *ipaddr;
  time_t mytime;
  int err;

  mytime = time(NULL);
  ipaddr = get_remote_ip();
  if ( ipaddr == NULL ) {
    return 0;
  }

  if ( (err=vauth_open(1)) != 0 ) return 0;

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, 
    "UPDATE relay SET ip_addr='%s', timestamp=%d WHERE ip_addr='%s'",
    ipaddr, (int)mytime, ipaddr);

  pgres=PQexec(pgc, SqlBufUpdate);
  if (PQresultStatus(pgres) == PGRES_COMMAND_OK && atoi(PQcmdTuples(pgres)) == 0) {
    if( pgres ) PQclear(pgres);

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
      "INSERT INTO relay (ip_addr, timestamp) VALUES ('%s', %lu)",
      ipaddr, time(NULL)); 

    pgres=PQexec(pgc, SqlBufUpdate);
    }

/* UPDATE returned 0 rows and/or INSERT failed.  Try creating the table */
  if(!pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK) {
    if( pgres ) PQclear(pgres);

    vcreate_relay_table();

/* and try INSERTing now... */
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
      "INSERT INTO relay (ip_addr, timestamp) VALUES ('%s', %lu)",
      ipaddr, time(NULL)); 

    pgres=PQexec(pgc, SqlBufUpdate);
    }

  if(pgres && PQresultStatus(pgres) == PGRES_COMMAND_OK ) {
    /* need to return non-zero value if value inserted */
    if( pgres ) PQclear(pgres);
    return 1;
  }

  if( pgres ) PQclear(pgres);
  return 0;
}

void vupdate_rules(int fdm)
{
  PGresult *pgres;
  const char re[]=":allow,RELAYCLIENT=\"\",RBLSMTPD=\"\"\n";
  register unsigned i=0, n, len=strlen(re)+1;
  char *buf=NULL;

  if (vauth_open(0) != 0) return;

  snprintf(SqlBufRead, SQL_BUF_SIZE, "SELECT ip_addr FROM relay");
  if ( !(pgres=PQexec(pgc, SqlBufRead)) || PQresultStatus(pgres)!=PGRES_TUPLES_OK) {
    vcreate_relay_table();
    if(pgres) PQclear(pgres);
    if ( !(pgres=PQexec(pgc, SqlBufRead)) || PQresultStatus(pgres)!=PGRES_TUPLES_OK ) {
      fprintf(stderr, "vupdate_rules: query : %s\n", PQerrorMessage(pgc));
      if (pgres) PQclear (pgres);
      return;
    }
  }
  
  n=PQntuples(pgres);
  for( ; i < n ; i++ ) {
    buf=realloc(buf, len+PQgetlength(pgres, i, 0) );
    if( buf==NULL || errno==ENOMEM ) {
      PQclear(pgres);
      free(buf);
      fprintf(stderr, "vupdate_rules: no mem\n");
      return;
    }

    sprintf( buf, "%s%s", PQgetvalue(pgres, i, 0), re );
    if( write( fdm, buf, strlen(buf) ) != strlen(buf) ) {
      fprintf(stderr, "vupdate_rules: short write: %s",
	      strerror(errno));
      break;
    }
  }
  if(pgres) PQclear(pgres);
  free(buf);
  return;
}

void vclear_open_smtp(time_t clear_minutes, time_t mytime)
{
  PGresult *pgres;
  time_t delete_time;
  int err;
    
  if ( (err=vauth_open(1)) != 0 ) return;
  delete_time = mytime - clear_minutes;

  snprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	    "DELETE FROM relay WHERE timestamp <= %d", 
	    (int)delete_time);
  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK) {
    vcreate_relay_table();
  }
  return;
}

void vcreate_relay_table()
{
  vauth_create_table ("relay", RELAY_TABLE_LAYOUT, 1);
  return;
}
#endif

int vmkpasswd( char *domain )
{
    return(0);
}

void vclose()
{
  /* disconnection from the database */
  if ( is_open == 1 ) {
    is_open = 0;
    PQfinish(pgc);
  }
}

#ifdef IP_ALIAS_DOMAINS
void vcreate_ip_map_table()
{
  vauth_create_table ("ip_alias_map", IP_ALIAS_TABLE_LAYOUT, 1);
  return;
}

int vget_ip_map( char *ip, char *domain, int domain_size)
{
  PGresult *pgres;
  char *ptr;
  unsigned ntuples;
  int ret = -1;

  if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
  if ( domain == NULL ) return(-2);
  if ( vauth_open(0) != 0 ) return(-3);

  qnprintf(SqlBufRead, SQL_BUF_SIZE,
	   "select domain from ip_alias_map where ip_addr = '%s'",
	   ip);
  pgres=PQexec(pgc, SqlBufRead);
  if( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
    fprintf( stderr, "vget_ip_map: pgsql query: %s\n", PQerrorMessage(pgc));
      if( pgres ) PQclear(pgres);
      return -1;
    }

  ntuples = PQntuples(pgres);
  if(!ntuples)
    *domain='\0';
  else {
    ret = 0;
    ptr = PQgetvalue(pgres, ntuples-1, 0);
    strncpy(domain, ptr, strlen(ptr) );
  }

  PQclear(pgres);
  return (ret);
}

int vadd_ip_map( char *ip, char *domain) 
{
  PGresult *pgres;
  int err = 0;
  
  if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
  if ( domain == NULL || strlen(domain) <= 0 ) return(-1);

  if ( (err=vauth_open(1)) != 0 ) return(err);

  if( ( err=pg_begin() )!= 0 ) {     /* begin transaction */
    return(err);
  }
  qnprintf(SqlBufUpdate,SQL_BUF_SIZE,  
	   "delete from ip_alias_map where ip_addr='%s' and domain='%s'",
	   ip, domain);

  /* step 1: delete previous entry */
  pgres=PQexec(pgc, SqlBufUpdate);
  if( pgres ) PQclear(pgres); /* don't check pgres status 
				 table may not exist */

  /* step 2: insert new data */
  qnprintf(SqlBufUpdate,SQL_BUF_SIZE,  
	   "insert into ip_alias_map (ip_addr,domain) values ('%s','%s')",
	   ip, domain);
  pgres=PQexec(pgc, SqlBufUpdate);
  if ( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK ) {
    if( pgres ) PQclear(pgres);
    vcreate_ip_map_table();
    qnprintf(SqlBufUpdate,SQL_BUF_SIZE,  
	   "insert into ip_alias_map (ip_addr,domain) values ('%s','%s')",
	     ip, domain);
    pgres=PQexec( pgc, SqlBufUpdate);
    if ( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK ) {
      fprintf( stderr, "vadd_ip_map: insert: %s\n", PQerrorMessage(pgc));
      if( pgres ) PQclear(pgres);
      return -1;
    }
  }
  if( pgres ) PQclear(pgres);
  return ( pg_end() ); /* end transaction */
}

int vdel_ip_map( char *ip, char *domain) 
{
  PGresult *pgres;
  int err=0;

  if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
  if ( domain == NULL || strlen(domain) <= 0 ) return(-1);
  if ( (err=vauth_open(1)) != 0 ) return(err);

  qnprintf( SqlBufUpdate,SQL_BUF_SIZE,  
	    "delete from ip_alias_map where ip_addr='%s' and domain='%s'",
            ip, domain);

  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "vdel_ip_map: delete failed: %s\n", 
	    PQerrorMessage(pgc));
    if(pgres) PQclear(pgres);
    /* #warning why are we returning 0 when we couldn't delete?*/
    return(0);
  }
  if(pgres) PQclear(pgres);
  return(0);
}	
int vshow_ip_map( int first, char *ip, char *domain )
{
  static PGresult *pgres=NULL;
  static unsigned ntuples=0, ctuple=0;
  int err= 0;

  if ( ip == NULL ) return(-1);
  if ( domain == NULL ) return(-1);
  if ( ( err=vauth_open(0) ) != 0 ) return(err);

  if ( first == 1 ) {
    snprintf(SqlBufRead,SQL_BUF_SIZE, 
	     "select ip_addr, domain from ip_alias_map"); 
    if (pgres) { 
      PQclear(pgres);
      ntuples=ctuple=0;
    }	
    if ( ! (pgres=PQexec(pgc, SqlBufRead))
         || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      if(pgres) PQclear(pgres);
      snprintf(SqlBufRead,SQL_BUF_SIZE, 
	       "select ip_addr, domain from ip_alias_map"); 
      vcreate_ip_map_table();
      if ( ! (pgres=PQexec(pgc, SqlBufRead))
	   || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
	return(0);
      }
    }
    ntuples=PQntuples(pgres);
  } 

  if ( ctuple == ntuples ) {
    PQclear(pgres);
    ntuples=ctuple=0;
    return (0);
  }

  strncpy( ip, PQgetvalue( pgres, ctuple, 0), 18);
  strncpy( domain, PQgetvalue( pgres, ctuple, 1), 156);
  strncpy( ip, PQgetvalue( pgres, ctuple, 0), 18);
  strncpy( domain, PQgetvalue( pgres, ctuple, 1), 156);

  ctuple++;
  return 1;
}
#endif

int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{
  PGresult *pgres;
  int found = 0;

  if ( vauth_open(0) != 0 ) return(-1);

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, 
	   "select %s from dir_control where domain = '%s'", 
	   DIR_CONTROL_SELECT, domain );

  if (!(pgres=PQexec(pgc, SqlBufUpdate)) || 
      PQresultStatus(pgres)!=PGRES_TUPLES_OK ) {
      if( pgres ) PQclear(pgres);
      vcreate_dir_control(domain);
      qnprintf(SqlBufUpdate, SQL_BUF_SIZE, 
	       "select %s from dir_control where domain = '%s'", 
	       DIR_CONTROL_SELECT, domain );
      if (! (pgres=PQexec(pgc, SqlBufUpdate)) || 
	  PQresultStatus(pgres)!=PGRES_TUPLES_OK ) {
	fprintf(stderr, "vread_dir_control: q: %s\npgsql: %s", 
		SqlBufUpdate, PQerrorMessage(pgc));
	  if (pgres) PQclear (pgres);
	  return (-1);
      }
  }
  if ( PQntuples(pgres) > 0 ) {
    found = 1;
    vdir->cur_users = atol( PQgetvalue( pgres, 0, 0 ) );
    vdir->level_cur = atoi( PQgetvalue( pgres, 0, 1 ) );
    vdir->level_max = atoi( PQgetvalue( pgres, 0, 2 ) );

    vdir->level_start[0] = atoi( PQgetvalue( pgres, 0, 3 ) );
    vdir->level_start[1] = atoi( PQgetvalue( pgres, 0, 4 ) );
    vdir->level_start[2] = atoi( PQgetvalue( pgres, 0, 5 ) );

    vdir->level_end[0] = atoi( PQgetvalue( pgres, 0, 6 ) );
    vdir->level_end[1] = atoi( PQgetvalue( pgres, 0, 7 ) );
    vdir->level_end[2] = atoi( PQgetvalue( pgres, 0, 8 ) );

    vdir->level_mod[0] = atoi( PQgetvalue( pgres, 0, 9 ) );
    vdir->level_mod[1] = atoi( PQgetvalue( pgres, 0, 10 ) );
    vdir->level_mod[2] = atoi( PQgetvalue( pgres, 0, 11 ) );

    vdir->level_index[0] = atoi( PQgetvalue( pgres, 0, 12 ) );
    vdir->level_index[1] = atoi( PQgetvalue( pgres, 0, 13 ) );
    vdir->level_index[2] = atoi( PQgetvalue( pgres, 0, 14 ) );

    strncpy(vdir->the_dir, PQgetvalue( pgres, 0, 15 ), MAX_DIR_NAME);
  }
  PQclear(pgres);
  if ( found == 0 ) {
    int i;
    vdir->cur_users = 0;
    for(i=0;i<MAX_DIR_LEVELS;++i) {
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
  }
  return(0);
}

int vwrite_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{
  PGresult *pgres;

  if ( vauth_open(1) != 0 ) return(-1);

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, 
	   "delete from dir_control where domain='%s'", domain );
  if( pg_begin() ) { /* begin transaction */
      return -1;
  }
  pgres=PQexec(pgc, SqlBufUpdate);
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "vwrite_dir_control: delete failed: %s", 
	    PQerrorMessage(pgc));
	if (pgres) PQclear (pgres);
    return -1;
  }
  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
	   "insert into dir_control ( \
domain, cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir ) values ( \
'%s', %lu, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
'%s')\n",
	   domain, vdir->cur_users, vdir->level_cur, vdir->level_max,
	   vdir->level_start[0], vdir->level_start[1], vdir->level_start[2],
	   vdir->level_end[0], vdir->level_end[1], vdir->level_end[2],
	   vdir->level_mod[0], vdir->level_mod[1], vdir->level_mod[2],
	   vdir->level_index[0], vdir->level_index[1], vdir->level_index[2],
	   vdir->the_dir);

  pgres=PQexec(pgc, SqlBufUpdate);
  if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    PQclear(pgres);
    vcreate_dir_control(domain);
    if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr, "vwrite_dir_control: %s\n", PQerrorMessage(pgc));
      if (pgres) PQclear (pgres);
      return(-1);
    }
  }
  PQclear(pgres);
  return pg_end(); /* end transcation */

}

void vcreate_dir_control(char *domain)
{
  PGresult *pgres;
  vauth_create_table ("dir_control", DIR_CONTROL_TABLE_LAYOUT, 1);

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, "insert into dir_control ( \
domain, cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir ) values ( \
\'%s\', 0, \
0, %d, \
0, 0, 0, \
%d, %d, %d, \
0, 2, 4, \
0, 0, 0, \
\'\')\n",
    domain, MAX_DIR_LEVELS, MAX_DIR_LIST-1, MAX_DIR_LIST-1, MAX_DIR_LIST-1);

  pgres = PQexec( pgc, SqlBufUpdate );
  if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    fprintf(stderr, "vcreate_dir_control: insert failed: %s\n", 
	    PQerrorMessage(pgc));
	  if (pgres) PQclear (pgres);
      return;
  }

  PQclear(pgres);
}

int vdel_dir_control(char *domain)
{
  PGresult *pgres;
  int err;

  if ( (err=vauth_open(1)) != 0 ) return(err);

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, 
	   "delete from dir_control where domain = '%s'", 
	   domain); 
  pgres=PQexec(pgc, SqlBufUpdate);

  if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    PQclear(pgres);
    vcreate_dir_control(domain);
    qnprintf(SqlBufUpdate, SQL_BUF_SIZE, 
	     "delete from dir_control where domain = '%s'", 
	     domain); 
    if ( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr, "vdel_dir_control: delete failed[e]: %s\n", 
	      PQerrorMessage(pgc));
      err=-1;
    }
  }
  if( pgres ) PQclear(pgres);
  return err;
}

#ifdef ENABLE_AUTH_LOGGING
int vset_lastauth(char *user, char *domain, char *remoteip )
{
  PGresult *pgres;
  int err=0;

  if ( (err=vauth_open(1)) != 0 ) return(err);

  qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
    "UPDATE lastauth SET remote_ip='%s', timestamp=%lu " \
    "WHERE userid='%s' AND domain='%s'", remoteip, time(NULL), user, domain); 

#ifdef DEBUG
fprintf(stderr,"UPDATE command to run is \n\n%s\n\n", SqlBufUpdate);
#endif

  pgres=PQexec(pgc, SqlBufUpdate);

  if (pgres && PQresultStatus(pgres) == PGRES_COMMAND_OK && atoi(PQcmdTuples(pgres)) == 0) {

#ifdef DEBUG
fprintf(stderr,"UPDATE returned OK but had 0 rows\n");
#endif

    if( pgres ) PQclear(pgres);

    qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
      "INSERT INTO lastauth (userid, domain, remote_ip, timestamp) " \
      "VALUES ('%s', '%s', '%s', %lu)", user, domain, remoteip, time(NULL)); 

#ifdef DEBUG
fprintf(stderr,"INSERT command to run is \n\n%s\n\n", SqlBufUpdate);
#endif
    pgres=PQexec(pgc, SqlBufUpdate);
    }

/* UPDATE returned 0 rows and/or INSERT failed.  Try creating the table */
  if(!pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK) {
#ifdef DEBUG
fprintf(stderr,"UPDATE and/or INSERT failed.  error was %s\n", PQerrorMessage(pgc));
#endif
    if( pgres ) PQclear(pgres);

#ifdef DEBUG
fprintf(stderr, "update returned 0 and/or insert failed in vset_lastauth()\n");
#endif
    vcreate_lastauth_table();

/* and try INSERTing now... */
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
      "INSERT INTO lastauth (userid, domain, remote_ip, timestamp) " \
      "VALUES ('%s', '%s', '%s', %lu)", user, domain, remoteip, time(NULL)); 

    pgres=PQexec(pgc, SqlBufUpdate);
    }

  if ( !pgres || PQresultStatus(pgres) != PGRES_COMMAND_OK ) {
    fprintf( stderr, "vset_lastauth[f]: %s\n: %s\n", SqlBufUpdate,PQerrorMessage(pgc));
    if( pgres ) PQclear(pgres);
    return (-1);
  }

  if( pgres ) PQclear(pgres);
  return(0);
}
time_t vget_lastauth(struct vqpasswd *pw, char *domain)
{
  PGresult *pgres;
  int err, ntuples;
  time_t mytime;

  if ( (err=vauth_open(0)) != 0 ) return(err);

  qnprintf( SqlBufRead,  SQL_BUF_SIZE, "SELECT timestamp FROM lastauth WHERE userid='%s' AND domain='%s'", pw->pw_name, domain);

  pgres=PQexec(pgc, SqlBufRead);

  if ( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
    if( pgres ) PQclear(pgres);
    vcreate_lastauth_table();
    qnprintf( SqlBufRead,  SQL_BUF_SIZE, "SELECT timestamp FROM lastauth WHERE userid='%s' AND domain='%s'", pw->pw_name, domain);
    pgres=PQexec(pgc, SqlBufRead);
    if ( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      fprintf(stderr,"vpgsql: sql error[g]: %s\n", PQerrorMessage(pgc));
      return(0);
    }
  }

  ntuples = PQntuples(pgres);
  mytime = 0;
  if( ntuples ) { /* got something */
    mytime = atol( PQgetvalue(pgres, ntuples-1, 0));
  }
  if( pgres ) PQclear(pgres);
  return(mytime);
}

char *vget_lastauthip(struct vqpasswd *pw, char *domain)
{
  PGresult *pgres;
  static char tmpbuf[100];
  int ntuples=0;

  if ( vauth_open(0) != 0 ) return(NULL);

  qnprintf( SqlBufRead,  SQL_BUF_SIZE, "select remote_ip from lastauth where userid='%s' and domain='%s'",  pw->pw_name, domain);

  pgres=PQexec(pgc, SqlBufRead);
  if ( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
    if( pgres ) PQclear(pgres);
    vcreate_lastauth_table();
    qnprintf( SqlBufRead,  SQL_BUF_SIZE, "select remote_ip from lastauth where userid='%s' and domain='%s'", pw->pw_name, domain);

    pgres=PQexec(pgc, SqlBufRead);
    if ( !pgres || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      fprintf( stderr,"vpgsql: sql error[h]: %s\n", PQerrorMessage(pgc));
      return(NULL);
    }
  }
  ntuples = PQntuples(pgres);
  if( ntuples ) { /* got something */
    strncpy(tmpbuf, PQgetvalue(pgres, ntuples-1, 0),100 );
  }
  if( pgres ) PQclear(pgres);
  return(tmpbuf);
}

void vcreate_lastauth_table()
{
  vauth_create_table ("lastauth", LASTAUTH_TABLE_LAYOUT, 1);
  return;
}
#endif /* ENABLE_AUTH_LOGGING */

#ifdef VALIAS
struct linklist *valias_current = NULL;

char *valias_select( char *alias, char *domain )
{
  PGresult *pgvalias;
  int err, verrori;
  unsigned ntuples, ctuple;
  struct linklist *temp_entry = NULL;

  /* remove old entries as necessary */
  while (valias_current != NULL)
    valias_current = linklist_del (valias_current);

  if ( (err=vauth_open(0)) != 0 ) {
    verrori = err;
    return(NULL);
  }

  qnprintf( SqlBufRead, SQL_BUF_SIZE, 
	    "select valias_line from valias where alias='%s' and domain='%s'",
	    alias, domain );
  if ( ! (pgvalias=PQexec(pgc, SqlBufRead)) 
       || PQresultStatus(pgvalias) != PGRES_TUPLES_OK ) {
    if(pgvalias) PQclear(pgvalias);
    vcreate_valias_table();
    if ( ! (pgvalias=PQexec(pgc, SqlBufRead)) 
	 || PQresultStatus(pgvalias) != PGRES_TUPLES_OK ) {
      fprintf(stderr,"vpgsql: sql error[j]: %s\n", 
	      PQerrorMessage(pgc));
	  if (pgvalias) PQclear(pgvalias);
      return(NULL);
    }
  }

  ntuples = PQntuples (pgvalias);
  for (ctuple = 0; ctuple < ntuples; ctuple++) {
    temp_entry = linklist_add (temp_entry, PQgetvalue (pgvalias, ctuple, 0), "");
    if (valias_current == NULL) valias_current = temp_entry;
  }
  PQclear (pgvalias);
  pgvalias = NULL;

  if (valias_current == NULL) return NULL; /* no results */
  else return(valias_current->data);
}

char *valias_select_next()
{
  if (valias_current == NULL) return NULL;

  valias_current = linklist_del (valias_current);

  if (valias_current == NULL) return NULL; 
  else return valias_current->data; 
}

int valias_insert( char *alias, char *domain, char *alias_line)
{
  PGresult *pgres;
  int err;
  
#ifdef USE_ONCHANGE
 char user_domain[MAX_BUFF];
#endif   

  if ( (err=vauth_open(1)) != 0 ) return(err);
  
#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_add", domain, alias_line, 0, 0);
#endif

  while(*alias_line==' ') ++alias_line;

  qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
    "insert into valias(alias,domain,valias_line) values ('%s','%s','%s')",
	    alias, domain, alias_line );

  pgres=PQexec( pgc, SqlBufUpdate );
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
    "insert into valias(alias,domain,valias_line) values ('%s','%s','%s')",
	    alias, domain, alias_line );
    pgres=PQexec( pgc, SqlBufUpdate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr,"vpgsql: sql error[k]: %s\n", PQerrorMessage(pgc));
      if (pgres) PQclear (pgres);
      return(-1);
    }
    if(pgres) PQclear(pgres);

#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_add", domain, alias_line, 1, 1);
#endif

    return(0);
  }
  return(-1);
}

int valias_delete( char *alias, char *domain)
{
  PGresult *pgres;
  int err;

#ifdef USE_ONCHANGE
 char user_domain[MAX_BUFF];
#endif 

  if ( (err=vauth_open(1)) != 0 ) return(err);

#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_delete", domain, alias_line, 1, 0);
#endif

  qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	    "delete from valias where alias='%s' and domain='%s'", 
	    alias, domain );
  pgres=PQexec( pgc, SqlBufUpdate );
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	      "delete from valias where alias='%s' and domain='%s'", 
	      alias, domain );
    pgres=PQexec( pgc, SqlBufUpdate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr,"vpgsql: sql error: %s\n", PQerrorMessage(pgc));
      if (pgres) PQclear (pgres);
      return(-1);
    }
  }
  if(pgres) PQclear(pgres);
  
#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_delete", domain, alias_line, 0, 1);
#endif 
  
  return(0);
}

int valias_remove( char *alias, char *domain, char *alias_line)
{
  PGresult *pgres;
  int err;
  
#ifdef USE_ONCHANGE
 char user_domain[MAX_BUFF];
#endif   

  if ( (err=vauth_open(1)) != 0 ) return(err);

#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_remove", user_domain, alias_line, 1, 0);
#endif

  qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	    "delete from valias where alias='%s' and valias_line='%s' and domain='%s'", 
	    alias, alias_line, domain );
  pgres=PQexec( pgc, SqlBufUpdate );
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    pgres=PQexec( pgc, SqlBufUpdate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr,"vpgsql: sql error: %s\n", PQerrorMessage(pgc));
      if (pgres) PQclear (pgres);
      return(-1);
    }
  }
  if(pgres) PQclear(pgres);

#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_remove", user_domain, alias_line, 0, 1);
#endif 
  
  return(0);
}

int valias_delete_domain( char *domain)
{
  PGresult *pgres;
  int err;
  
#ifdef USE_ONCHANGE
 char user_domain[MAX_BUFF];
#endif   

  if ( (err=vauth_open(1)) != 0 ) return(err);

#ifdef USE_ONCHANGE
  on_change("valias_delete_domain", domain, "-", 1, 0);
#endif

  qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	    "delete from valias where domain='%s'", domain );

  pgres=PQexec( pgc, SqlBufUpdate );
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    qnprintf( SqlBufUpdate, SQL_BUF_SIZE, 
	      "delete from valias where domain='%s'", domain );
    pgres=PQexec( pgc, SqlBufUpdate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr,"vpgsql: sql error: %s\n", PQerrorMessage(pgc));
      if (pgres) PQclear (pgres);
      return(-1);
    }
  }
  if(pgres) PQclear(pgres);

#ifdef USE_ONCHANGE
  on_change("valias_delete_domain", domain, "-", 0, 1);
#endif
  
  return(0);
}

void vcreate_valias_table()
{
  PGresult *pgres;
  char SqlBufCreate[SQL_BUF_SIZE];

  vauth_create_table ("valias", VALIAS_TABLE_LAYOUT, 1);
    snprintf( SqlBufCreate, SQL_BUF_SIZE,
	"create index valias_idx on valias ( %s )", VALIAS_INDEX_LAYOUT );

    pgres=PQexec( pgc, SqlBufCreate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      fprintf(stderr,"vpgsql:sql error[n.i]:%s\n", PQerrorMessage(pgc));
      if( pgres ) PQclear(pgres);
      return;
    }
    if( pgres ) PQclear(pgres);
    return;
}

char *valias_select_all( char *alias, char *domain )
{
  PGresult *pgres;
  int err;
  unsigned ntuples, ctuple;
  struct linklist *temp_entry = NULL;

  /* remove old entries as necessary */
  while (valias_current != NULL)
    valias_current = linklist_del (valias_current);

  if ( (err=vauth_open(0)) != 0 ) return(NULL);

  qnprintf( SqlBufRead, SQL_BUF_SIZE, 
	    "select alias, valias_line from valias where domain = '%s' order by alias", 
	    domain );
  if ( ! (pgres=PQexec(pgc, SqlBufRead))
       || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    if ( ! (pgres=PQexec(pgc, SqlBufRead))
         || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      fprintf(stderr,"vpgsql: sql error[o]: %s\n",
              PQerrorMessage(pgc));
      if (pgres) PQclear (pgres);
      return(NULL);
    }
  }

  ntuples = PQntuples (pgres);
  for (ctuple = 0; ctuple < ntuples; ctuple++) {
    temp_entry = linklist_add (temp_entry, PQgetvalue (pgres, ctuple, 1), PQgetvalue (pgres, ctuple, 0));
    if (valias_current == NULL) valias_current = temp_entry;
  }
  PQclear (pgres);
  pgres = NULL; 

  if (valias_current == NULL) return NULL; /* no results */
  else {
    strcpy (alias, valias_current->d2);
    return(valias_current->data);
  }
}

char *valias_select_all_next(char *alias)
{
  if (valias_current == NULL) return NULL;
  valias_current = linklist_del (valias_current);
     
  if (valias_current == NULL) return NULL; 
  else {
    strcpy (alias, valias_current->d2);
    return valias_current->data; 
  }
}

/************************************************************************
 *
 *  valias_select_names
 */

char *valias_select_names( char *domain )
{
  PGresult *pgres;
  int err;
  unsigned ntuples, ctuple;
 struct linklist *temp_entry = NULL;


    /* remove old entries as necessary */
    while (valias_current != NULL)
        valias_current = linklist_del (valias_current);

    if ( (err=vauth_open(0)) != 0 ) return(NULL);

    qnprintf( SqlBufRead, SQL_BUF_SIZE,
        "select distinct alias from valias where domain = '%s' order by alias", domain );

  if ( ! (pgres=PQexec(pgc, SqlBufRead))
       || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
    if(pgres) PQclear(pgres);
    vcreate_valias_table();
    if ( ! (pgres=PQexec(pgc, SqlBufRead))
         || PQresultStatus(pgres) != PGRES_TUPLES_OK ) {
      fprintf(stderr,"vpgsql: sql error[o]: %s\n",
              PQerrorMessage(pgc));
      if (pgres) PQclear (pgres);
      return(NULL);
    }
  }

  ntuples = PQntuples (pgres);
  for (ctuple = 0; ctuple < ntuples; ctuple++) {
    temp_entry = linklist_add (temp_entry, PQgetvalue (pgres, ctuple, 0), "");
    if (valias_current == NULL) valias_current = temp_entry;
  }
  PQclear (pgres);
  pgres = NULL;

    if (valias_current == NULL) return NULL; /* no results */
    else return(valias_current->data);
}

/************************************************************************
 *
 *  valias_select_names_next
 */

char *valias_select_names_next()
{
    if (valias_current == NULL) return NULL;
    valias_current = linklist_del (valias_current);

    if (valias_current == NULL) return NULL; /* no results */
    else return(valias_current->data);
}


/************************************************************************
 *
 *  valias_select_names_end
 */

void valias_select_names_end() {

//  not needed by pgsql

}

#endif

#ifdef ENABLE_SQL_LOGGING
int logsql(	int verror, char *TheUser, char *TheDomain, char *ThePass, 
		char *TheName, char *IpAddr, char *LogLine) 
{
  PGresult *pgres;
  int err;
  time_t mytime;

  mytime = time(NULL);
  if ( (err=vauth_open(1)) != 0 ) return(err);
  /*

  qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
	    "INSERT INTO vlog set userid='%s', passwd='%s', \
        domain='%s', logon='%s', remoteip='%s', message='%s', \
        error=%i, timestamp=%d", TheUser, ThePass, TheDomain,
        TheName, IpAddr, LogLine, verror, (int)mytime);
  */

  qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
  "INSERT INTO vlog (userid,passwd,domain,logon,remoteip,message,error,timestamp) values('%s','%s','%s','%s','%s','%s',%i,%d)", 
	    TheUser, ThePass, TheDomain, TheName, 
	    IpAddr, LogLine, verror, (int)mytime);

  pgres=PQexec( pgc, SqlBufUpdate );
  if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
    if( pgres ) PQclear(pgres);
    vcreate_vlog_table();
  qnprintf( SqlBufUpdate, SQL_BUF_SIZE,
  "INSERT INTO vlog (userid,passwd,domain,logon,remoteip,message,error,timestamp) values('%s','%s','%s','%s','%s','%s',%i,%d)", 
	    TheUser, ThePass, TheDomain, TheName, 
	    IpAddr, LogLine, verror, (int)mytime);

    pgres=PQexec( pgc, SqlBufUpdate );
    if( !pgres || PQresultStatus(pgres)!=PGRES_COMMAND_OK ) {
      if( pgres ) PQclear(pgres);
      fprintf(stderr,"error inserting into lastauth table\n");
    }
  }
  if( pgres ) PQclear(pgres);
  return(0);
}

void vcreate_vlog_table()
{
  vauth_create_table ("vlog", VLOG_TABLE_LAYOUT, 1);
  return;
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

