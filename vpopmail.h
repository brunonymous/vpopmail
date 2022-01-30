/*
 * $Id: vpopmail.h 1015 2011-02-03 16:33:39Z volz0r $
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
#ifndef VPOPMAIL_VPOPMAIL_H
#define VPOPMAIL_VPOPMAIL_H

#include <stdio.h>
#include <sys/types.h>		// for uid_t
#include "storage.h"

/*  Enable expanded debug information.  Consider these for ./configure options  */
//  Show entry and parms when hitting vpopmail library functions
//#define SHOW_TRACE
//  Show database queries
//#define SHOW_QUERY
//  Dump returnd data
//#define DUMP_DATA

#define DEFAULT_DOMAIN default_domain()

/* max buffer sizes */
#define MAX_BUFF 300

/* max field sizes */
#define MAX_PW_NAME          32
#define MAX_PW_DOMAIN        96
#define MAX_PW_PASS         128
#define MAX_PW_GECOS         48
#define MAX_PW_CLEAR_PASSWD 128
#define MAX_PW_DIR          160
#define MAX_PW_QUOTA         20
#define MAX_ALIAS_LINE      160

#define ATCHARS "@%/"
#define BOUNCE_ALL "bounce-no-mailbox"
#define DELETE_ALL "delete"

/* modes for vpopmail dirs, files and qmail files */
#define VPOPMAIL_UMASK          0077
#define VPOPMAIL_TCPRULES_UMASK 0022
#define VPOPMAIL_DIR_MODE       0750
#define VPOPMAIL_QMAIL_MODE S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH

#define USE_POP      0x00
#define USE_APOP     0x01

/* error return codes */
#define VA_SUCCESS                        0
#define VA_ILLEGAL_USERNAME              -1
#define VA_USERNAME_EXISTS               -2
#define VA_BAD_DIR                       -3
#define VA_BAD_U_DIR                     -4
#define VA_BAD_D_DIR                     -5
#define VA_BAD_V_DIR                     -6
#define VA_EXIST_U_DIR                   -7
#define VA_BAD_U_DIR2                    -8
#define VA_SUBDIR_CREATION               -9
#define VA_USER_DOES_NOT_EXIST          -10
#define VA_DOMAIN_DOES_NOT_EXIST        -11
#define VA_INVALID_DOMAIN_NAME          -12
#define VA_DOMAIN_ALREADY_EXISTS        -13
#define VA_COULD_NOT_MAKE_DOMAIN_DIR    -14
#define VA_COULD_NOT_OPEN_QMAIL_DEFAULT -15
#define VA_CAN_NOT_MAKE_DOMAINS_DIR     -16
#define VA_COULD_NOT_UPDATE_FILE        -17
#define VA_CRYPT_FAILED                 -18
#define VA_COULD_NOT_OPEN_DOT_QMAIL     -19
#define VA_BAD_CHAR                     -20
#define VA_SQWEBMAIL_PASS_FAIL          -21
#define VA_BAD_UID                      -22
#define VA_NO_AUTH_CONNECTION           -23
#define VA_MEMORY_ALLOC_ERR             -24
#define VA_USER_NAME_TOO_LONG           -25
#define VA_DOMAIN_NAME_TOO_LONG         -26
#define VA_PASSWD_TOO_LONG              -27
#define VA_GECOS_TOO_LONG               -28
#define VA_QUOTA_TOO_LONG               -29
#define VA_DIR_TOO_LONG                 -30
#define VA_CLEAR_PASSWD_TOO_LONG        -31
#define VA_ALIAS_LINE_TOO_LONG          -32
#define VA_NULL_POINTER                 -33
#define VA_INVALID_EMAIL_CHAR           -34
#define VA_PARSE_ERROR                  -35
#define VA_PARSE_ERROR01                -45
#define VA_PARSE_ERROR02                -46
#define VA_PARSE_ERROR03                -47
#define VA_PARSE_ERROR04                -48
#define VA_PARSE_ERROR05                -49
#define VA_PARSE_ERROR06                -50
#define VA_PARSE_ERROR07                -51
#define VA_PARSE_ERROR08                -52
#define VA_PARSE_ERROR09                -53
#define VA_PARSE_ERROR10                -54
#define VA_CANNOT_READ_LIMITS           -36
#define VA_CANNOT_READ_ASSIGN           -37
#define VA_CANNOT_OPEN_DATABASE         -38
#define VA_INVALID_IP_ADDRESS           -39
#define VA_QUERY_FAILED                 -40
#define VA_STORE_RESULT_FAILED          -41
#define VA_INVALID_OPEN_MODE            -42
#define VA_CANNOT_CREATE_DATABASE       -43
#define VA_CANNOT_CREATE_TABLE          -44
#define VA_CANNOT_DELETE_CATCHALL       -55


/* gid flags */
#define NO_PASSWD_CHNG 0x01
#define NO_POP         0x02
#define NO_WEBMAIL     0x04
#define NO_IMAP        0x08
#define BOUNCE_MAIL    0x10
#define NO_RELAY       0x20
#define NO_DIALUP      0x40
#define V_USER0       0x080
#define V_USER1       0x100
#define V_USER2       0x200
#define V_USER3       0x400
#define NO_SMTP       0x800
#define QA_ADMIN     0x1000
#define V_OVERRIDE   0x2000
#define NO_SPAMASSASSIN 0x4000
#define DELETE_SPAM  0x8000
#define SA_ADMIN     0x10000
#define SA_EXPERT    0x20000
#define NO_MAILDROP  0x40000

/*  Constants for vlistlib  */
#define MAX_SORT_BLOCKS 1000
#define SORT_TABLE_ENTRIES 1000
#define MAX_OPTIONS 26
#define MAX_FILE_NAME 512
#define MAX_NAME 160
#define EZMLMDIR "/usr/local/bin/ezmlm"

#define POSTING_ANYONE 0
#define POSTING_SPOB 1
#define POSTING_SPOM 2
#define POSTING_MPOB 3
#define POSTING_MPOM 4

#define REPLYTO_SENDER 1
#define REPLYTO_LIST 2
#define REPLYTO_ADDRESS 3

/*   List of strings */
typedef struct string_list {
    int size;
    int count;
    char **values;
} string_list;

void string_list_init(string_list *a, int first);
int string_list_add(string_list *a, char *value);
void string_list_free(string_list *a);

/*   Domain entry  */
typedef struct domain_entry {
        char    *domain;
        char    *realdomain;
        int             uid;
        int             gid;
        char    *path;
} domain_entry;


/*   Structure for mailing list data  */
typedef struct listInfoType {
   domain_entry *entry;
   char Name[MAX_NAME];
   int Posting;
   int Access;
   int Archive;
   int DomainOnly;
   int Prefix;
   int ReplyTo;
   int Digest;
   int Edit;
   int SubConf;
   int Indexed;
   int UnsubConf;
   int Kill;
   int RemoteSub;
   int RemoteText;
   int Public;
   int Requests;
   int Remote;
   int SubMod;
   int Trailer;
   int Warn;
   int Extra;
   int SQLSupport;
   int SQLPort;
   char OwnerEmail[MAX_NAME];
   char SQLHost[MAX_NAME];
   char SQLUser[MAX_NAME];
   char SQLPass[MAX_NAME];
   char SQLBase[MAX_NAME];
   char SQLTable[MAX_NAME];
   char Dot[MAX_NAME];
   char Dir[MAX_NAME];
   char PrefixText[MAX_NAME];
   char Domain[MAX_NAME];
   char ReplyTo_Addr[MAX_NAME];
} listInfoType;

extern int OptimizeAddDomain;
extern int NoMakeIndex;
extern int verrori;

/* functions */

/* Alias Management */
//  these may be in their own .h file...

/* Domain Management */
int vadddomain( char *domain, char *dir, uid_t uid, gid_t gid);
int vaddaliasdomain( char *alias_domain, char *real_domain);
int vdeldomain( char *);
domain_entry *get_domain_entries( const char *match_real );


/*  User Management  */
int vadduser( char *, char *, char *, char *, int);
void vgetpasswd( char *, char *, size_t);
int vpasswd( char *, char *, char *, int);
int vdeluser( char *, char *);
int vsetuserquota( char *, char *, char * );
char *vget_assign(char *domain, char *dir, int dir_len, uid_t *uid, gid_t *gid);
void remove_maildirsize(char *dir);
void update_maildirsize(char *domain, char *dir, char *quota);


/* Mailing List Management */
//  Subs = Subscribers.  I really don't want to write that out every time...
int    listSubsDescription( listInfoType *LI, int mode, int size, char *description );
int    listSubsCount(       listInfoType *LI, int mode );
char **listSubsList(        listInfoType *LI, int mode, int page, int perPage );
int    listSubsAdd(         listInfoType *LI, int mode, char *email ); 
int    listSubsDel(         listInfoType *LI, int mode, char *email ); 

int    listCount(      listInfoType *LI );
char **listList(       listInfoType *LI, int page, int perPage );
int    listGetOptions( listInfoType *LI, char *options, int maxOptions );
int    listMake(       listInfoType *LI );
int    listDelete(     listInfoType *LI );
int    listInit(       listInfoType *LI, char *address, int isDomainOnly, int isCreating );
int    listClose(      listInfoType *LI );
void   listGetError( char *buff, const int size, const int status );

/*  Low level string support  */
int parse_email( char *, char *, char *, int);
char *vrandom_pass (char *buffer, int len);
int is_username_valid( char *user );
int is_domain_valid( char *domain );
char *maildir_to_email(const char *maildir);


/*  Operational Overhead  */
int vexit(int err);
int vexiterror( FILE *f, char *comment);


/*  Utility Functions  */
/*  Low Level File System Management  */
int vdelfiles( char *);
int r_chown( char *, uid_t, gid_t);


/*  Misc Functions  */
int vopen_smtp_relay();	
char *get_remote_ip();


/*  Not yet categorized  */
char randltr(void);
int mkpasswd3( char *, char *, int);
int add_domain_assign( char *alias_domain, char *real_domain, 
                       char *dir, uid_t uid, gid_t gid);
//int del_control( char *);
int del_control( char **aliases, int aliascount);
int del_domain_assign( char **aliasies, int aliascount, 
                       char *real_domain,
                       char *dir, uid_t uid, gid_t gid);
int remove_lines( char *filename, char **aliases, int aliascount);
int signal_process( char *, int );
int update_newu();
int add_user_assign( char *, char *);
int del_user_assign( char *);
void lowerit( char *);
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
int update_file(char *, char *, int);
int count_rcpthosts();
int compile_morercpthosts();
char *make_user_dir(char *username, char *domain, uid_t uid, gid_t gid);
int r_mkdir(char *, uid_t uid, gid_t gid);
struct vqpasswd *vgetent(FILE *);
char *default_domain();
void vset_default_domain( char *);
void vupdate_rules(int);
void vclear_open_smtp(time_t, time_t);
char *verror(int);
int vadddotqmail(char *alias, char *domain,... ); 
int vdeldotqmail( char *alias, char *domain);
int vget_real_domain(char *domain, int len );
struct vqpasswd *vauth_user(char *user, char *domain, char *password, char *apop);
int vmake_maildir(char *domain, char *dir);
int vsqwebmail_pass( char *dir, char *crypted, uid_t uid, gid_t gid );
int open_smtp_relay();
unsigned  long tcprules_open();
int vfd_copy(int,int);
int vfd_move(int,int);
int update_rules();
char *vversion(char *);
int vcheck_vqpw(struct vqpasswd *inpw, char *domain);
char *vgen_pass(int len);
int vvalidchar( char inchar );
char *format_maildirquota(const char *q);
char *date_header();
int qnprintf (char *buffer, size_t size, const char *format, ...);
int readuserquota(const char* dir, storage_t *sizep, storage_t *cntp);
#ifndef HAVE_WARN
#define warn(...) fprintf(stderr, __VA_ARGS__)
#endif
/* Even though this definition defines data as 4096 bytes, we only allocate just
 * enough memory to hold the data.
 */
struct linklist {
	struct linklist *next;
	char *d2;
	char data[4096];
};
struct linklist * linklist_add (struct linklist *list, const char *d1, const char *d2);
struct linklist * linklist_del (struct linklist *list);

#ifdef APOP
char *dec2hex(unsigned char *);
#endif


#endif

void vsqlerror( FILE *f, char *comment );

//  Error handling
extern char sqlerr[MAX_BUFF];
extern char *last_query;

#ifdef ONCHANGE_SCRIPT
/* onchange function */
extern char onchange_buf[MAX_BUFF];
extern int allow_onchange;
int call_onchange();
#endif

#ifdef USERS_BIG_DIR
char *backfill(char *, char *, char *, int);
#endif
