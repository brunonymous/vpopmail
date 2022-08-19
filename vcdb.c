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
/******************************************************************************
**
** Change a domain's password file to a CDB database
**
** Chris Johnson, July 1998
**
******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/time.h>
#include <time.h>
#include <utime.h>
#include <sys/types.h>

#include "config.h"

#ifdef TINYCDB
#include <cdb.h>
#else
#include <cdbmake.h>
#endif

#include "vpopmail.h"
#include "vauth.h"
#include "vcdb.h"
#include "file_lock.h"
#include "vlimits.h"

#define TOKENS " \n"

#ifdef TINYCDB
typedef uint32_t uint32;
#endif

char *dc_filename(char *domain, uid_t uid, gid_t gid);
void vcdb_strip_char( char *instr );

char sqlerr[MAX_BUFF] = "";
char *last_query = NULL;

extern int cdb_seek();

static char vpasswd_file[MAX_BUFF];
static char vpasswd_bak_file[MAX_BUFF];
static char vpasswd_cdb_file[MAX_BUFF];
static char vpasswd_cdb_tmp_file[MAX_BUFF];
static char vpasswd_lock_file[MAX_BUFF];
static char vpasswd_dir[MAX_BUFF];
static char TmpBuf1[MAX_BUFF];

#ifdef TINYCDB
int make_vpasswd_cdb(char *domain)
{
    struct cdb_make cdbm;
    char pwline[MAX_BUFF_CDB];
    char Dir[156];
    char *key;
    char *data;
    char *ptr;
    long unsigned keylen,datalen;
    FILE *pwfile;
    int tmpfile;
    uid_t uid;
    gid_t gid;
    char *tmpstr;
    mode_t oldmask; 
        
    /* If we don't optimize the index this time, just return */
    if ( NoMakeIndex == 1 ) return(0);
    
    if ((pwfile = fopen(vpasswd_file,"r")) == NULL) {
        return(-1);
    }

    /* temporarily set umask (no group/other access) and open temp file */
    oldmask = umask(VPOPMAIL_UMASK);
    tmpfile = open(vpasswd_cdb_tmp_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    umask(oldmask);

    if (tmpfile == -1) {
        fprintf(stderr,"Error: could not create/open temporary file\n");
        return(-1);
    }
    
    if (cdb_make_start(&cdbm, tmpfile) != 0) {
        fprintf(stderr,"Error: could not initialise cdb\n");
        return(-1);
    }
    
    /* creation */
    fgets(pwline,MAX_BUFF_CDB,pwfile);
    while (!feof(pwfile)) {
        key = pwline; ptr = pwline;
        while (*ptr != ':') { ptr++; }
        *ptr = 0; data = ptr; data++;
        while (*ptr != '\n') { ptr++; }
        *ptr = 0;
        keylen = strlen(key); datalen = strlen(data);
#ifdef VPOPMAIL_DEBUG
        fprintf (stderr,"Got entry: keylen = %lu, key = %s\n           datalen = %lu, data = %s\n",keylen,key,datalen,data);
#endif

        if (cdb_make_add(&cdbm, key, keylen, data, datalen) != 0) {
            fprintf(stderr,"Error: could not add cdb entry\n");
            return(-1);
        }
        
        fgets(pwline,MAX_BUFF_CDB,pwfile);
    }

    fclose(pwfile);
 
    if (cdb_make_finish(&cdbm) != 0) {
        fprintf(stderr,"Error: could not write cdb file\n");
        return(-1);
    }

    if (close(tmpfile) == -1) {
        fprintf(stderr,"Error 24: error with close()\n");
        return(-1);
    }
   
    if (rename(vpasswd_cdb_tmp_file,vpasswd_cdb_file)) {
        fprintf(stderr, 
            "Error 25: could not rename cdb.tmp to vpasswd.cdb\n");
        return(-1);
    }
        
    tmpstr = vget_assign(domain, Dir, 156, &uid, &gid );
    
    if (chown(vpasswd_cdb_file, uid, gid) == -1) fprintf(stderr, "error!\n");
    if (chown(vpasswd_lock_file, uid, gid) == -1) fprintf(stderr, "error!\n");
    if (chown(vpasswd_file, uid, gid) == -1) fprintf(stderr, "error!\n");

    return 0;
}
#else
int make_vpasswd_cdb(char *domain)
{
 char pwline[MAX_BUFF_CDB];
 char packbuf[8];
 char *key;
 char *data;
 char *ptr;
 int i,j,h;
 int len;
 long unsigned keylen,datalen;
 uint32 pos,op;
 struct cdbmake cdbm;
 FILE *pwfile, *tmfile;
 char Dir[156];
 uid_t uid;
 gid_t gid;
 char *tmpstr;
 mode_t oldmask;

    /* If we don't optimize the index this time, just return */
    if ( NoMakeIndex == 1 ) return(0);

    if ((pwfile = fopen(vpasswd_file,"r")) == NULL) {
        return(-1);
    }

    cdbmake_init(&cdbm);

    /* temporarily set umask (no group/other access) and open temp file */
    oldmask = umask(VPOPMAIL_UMASK);
    tmfile = fopen(vpasswd_cdb_tmp_file,"w");
    umask(oldmask);

    if (tmfile == NULL) {
        fprintf(stderr,"Error: could not create/open temporary file\n");
        return(-1);
    }

    for (i=0; i < (int)sizeof(cdbm.final); i++) {
        if (putc(' ',tmfile) == EOF) {
                fprintf(stderr,"Error:error writing temp file\n");
            return(-1);
        }
    }
    pos = sizeof(cdbm.final);

    /* creation **/
    fgets(pwline,MAX_BUFF_CDB,pwfile);
    while (!feof(pwfile)) {
        key = pwline; ptr = pwline;
        while (*ptr != ':') { ptr++; }
        *ptr = 0; data = ptr; data++;
        while (*ptr != '\n') { ptr++; }
        *ptr = 0;
        keylen = strlen(key); datalen = strlen(data);
#ifdef VPOPMAIL_DEBUG
        fprintf (stderr,"Got entry: keylen = %lu, key = %s\n           datalen = %lu, data = %s\n",keylen,key,datalen,data);
#endif
        cdbmake_pack(packbuf, (uint32)keylen);
        cdbmake_pack(packbuf + 4, (uint32)datalen);
        if (fwrite(packbuf,1,8,tmfile) < 8) {
            fprintf(stderr,"Error: error writing temp file\n");
            return(-1);
        }

        h = CDBMAKE_HASHSTART;
        for (i=0; i < (int)keylen; i++) {
            h = cdbmake_hashadd(h,key[i]);
            if (putc(key[i],tmfile) == EOF) {
                fprintf (stderr,"Error: error temp file\n");
                return(-1);
            }
        }
        for (i=0; i < (int)datalen; i++) {
            if (putc(data[i],tmfile) == EOF) {
                fprintf (stderr,"Error: write error temp file");
                return(-1);
            }
        }
        if (!cdbmake_add(&cdbm,h,pos,malloc)) {
            fprintf(stderr, "Error: out of memory\n");
            return(-1);
        }

        op = pos;
        pos += (uint32)8;
        pos += (uint32)keylen;
        pos += (uint32)datalen;
        if (pos < op) {
            fprintf(stderr,"Error: too much data\n");
            return(-1);
        }
        if (!cdbmake_split(&cdbm,malloc)) {
            fprintf(stderr,"Error: out of memory\n");
            return(-1);
        }
        fgets(pwline,MAX_BUFF_CDB,pwfile);
        free(cdbm.split);
    }
    fclose(pwfile);

    if (!cdbmake_split(&cdbm,malloc)) {
        fprintf(stderr, "Error: out of memory\n");
        return(-1);
    }

    for (i=0; i < 256; i++) {
        len = cdbmake_throw(&cdbm,pos,i);
        for (j=0; j < len; j++) {
            cdbmake_pack(packbuf,cdbm.hash[j].h);
            cdbmake_pack(packbuf + 4, cdbm.hash[j].p);
            if (fwrite(packbuf,1,8,tmfile) < 8) {
                fprintf(stderr,"Error 1: error temp file\n");
                return(-1);
            }
            op = pos;
            pos += (uint32)8;
            if (pos < op) {
                fprintf (stderr, "Error 12: too much data\n");
                return(-1);
            }
        }
    }
    if (fflush(tmfile) == EOF) {
        fprintf (stderr,"Error 20: write error temp file\n");
        return(-1);
    }
    rewind(tmfile);
    if (fwrite(cdbm.final,1,sizeof(cdbm.final),tmfile)<sizeof(cdbm.final)){
        fprintf(stderr,"Error 21: write error temp file\n");
        return(-1);
    }
    if (fflush(tmfile) == EOF) {
        fprintf(stderr,"Error 22: write error temp file\n");
        return(-1);
    }
    
    if (close(fileno(tmfile)) == -1) {
        fprintf(stderr,"Error 24: error with close()\n");
        return(-1);
    }
    if (rename(vpasswd_cdb_tmp_file,vpasswd_cdb_file)) {
        fprintf(stderr, 
            "Error 25: could not rename cdb.tmp to vpasswd.cdb\n");
        return(-1);
    }
    free(cdbm.head);
    free(cdbm.split);

    tmpstr = vget_assign(domain, Dir, 156, &uid, &gid );
    chown(vpasswd_cdb_file, uid, gid);
    chown(vpasswd_lock_file, uid, gid);
    chown(vpasswd_file, uid, gid);

    return 0;
}
#endif

struct vqpasswd *vauth_getpw(char *user, char *domain)
{
 char in_domain[156];
 static struct vqpasswd pwent;
 static char line[2048];
 char *ptr = NULL, *uid = NULL, *gid = NULL;
 uid_t myuid;
 uid_t tuid;
 gid_t tgid;
 uint32 dlen;
 int pwf;
#ifdef FILE_LOCKING
 int lock_fd;
#endif

    verrori = 0;
    lowerit(user);
    lowerit(domain);

    if (vget_assign(domain,NULL,0,&tuid,&tgid) == NULL) {
        /* domain does not exist */
        return(NULL);
    }

    myuid = geteuid();
    if ( myuid != 0 && myuid != tuid ) {
	return(NULL);
    }

    strncpy( in_domain, domain, sizeof(in_domain));
    in_domain[sizeof(in_domain)-1] = '\0';  /* ensure NULL termination */
  
    if (set_vpasswd_files( in_domain ) == -1) {
        return (NULL);
    }    

    if ((pwf = open(vpasswd_cdb_file,O_RDONLY)) < 0 ) {
#ifdef FILE_LOCKING
		if ( (lock_fd=open(vpasswd_lock_file, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR)) < 0) {
			return(NULL);
		}
		get_write_lock( lock_fd );
#endif
        make_vpasswd_cdb(domain);
#ifdef FILE_LOCKING
		unlock_lock(lock_fd, 0, SEEK_SET, 0);
		close(lock_fd);
#endif
        if ((pwf = open(vpasswd_cdb_file,O_RDONLY)) < 0 ) {
            return(NULL);
        }
    }

    strncpy(line,user,sizeof(line)); 
    strncat(line,":",sizeof(line)-strlen(line)-1);
    ptr = line;
    while (*ptr != ':') { ptr++; }
    ptr++;
    switch (cdb_seek(pwf,user,strlen(user),&dlen)) {
        case -1:
        case 0:
            close(pwf);
            return NULL;
    }
#ifdef TINYCDB
    if (cdb_bread(pwf, ptr, dlen) != 0) {
        close(pwf); 
        return NULL;
    }
#else    
    if (read(pwf, ptr,dlen) != (int)dlen) {
        close(pwf);
        return NULL;
    }
#endif
    close(pwf);
    line[(dlen+strlen(user)+1)] = 0;

    pwent.pw_name   = "";
    pwent.pw_passwd = "";
    pwent.pw_gecos  = "";
    pwent.pw_dir    = "";
    pwent.pw_shell  = "";
    pwent.pw_clear_passwd  = "";

    ptr = line;
    pwent.pw_name    = line;
    while (*ptr!=0&&*ptr != ':') { ptr++; }
    if ( *ptr!=0 ){ *ptr = 0; ptr++; pwent.pw_passwd = ptr; }
    while (*ptr!=0&&*ptr != ':') { ptr++; }
    if ( *ptr!=0 ){ *ptr = 0; ptr++; uid = ptr; }
    while (*ptr!=0&&*ptr != ':') { ptr++; }
    if ( *ptr!=0 ){ *ptr = 0; ptr++; gid = ptr; }
    while (*ptr!=0&&*ptr != ':') { ptr++; }
    if ( *ptr!=0 ){ *ptr = 0; ptr++; pwent.pw_gecos = ptr; }
    while (*ptr!=0&&*ptr != ':') { ptr++; }
    if ( *ptr!=0 ){ *ptr = 0; ptr++; pwent.pw_dir = ptr; }
    while (*ptr!=0&&*ptr != ':') { ptr++; }
    if ( *ptr!=0 ){ *ptr = 0; ptr++; pwent.pw_shell = ptr; }
    while (*ptr!=0&&*ptr != ':') { ptr++; }
    if ( *ptr!=0 ){ *ptr = 0; ptr++; pwent.pw_clear_passwd = ptr; }

    if (!*uid) { pwent.pw_uid = 0; } else { pwent.pw_uid = atoi(uid); }
    if (!*gid) { pwent.pw_gid = 0; } else { pwent.pw_gid = atoi(gid); }

    vlimits_setflags (&pwent, in_domain);

#ifdef VPOPMAIL_DEBUG
    if( dump_data ) {
    fprintf (stderr,"vgetpw: db: results: pw_name   = %s\n",pwent.pw_name);
    fprintf (stderr,"                     pw_passwd = %s\n",pwent.pw_passwd);
    fprintf (stderr,"                     pw_uid    = %d\n",pwent.pw_uid);
    fprintf (stderr,"                     pw_gid    = %d\n",pwent.pw_gid);
    fprintf (stderr,"                     pw_flags  = %d\n",pwent.pw_flags);
    fprintf (stderr,"                     pw_gecos  = %s\n",pwent.pw_gecos);
    fprintf (stderr,"                     pw_dir    = %s\n",pwent.pw_dir);
    fprintf (stderr,"                     pw_shell  = %s\n",pwent.pw_shell);
    }
#endif

    return(&pwent);
}


struct vqpasswd *vauth_getall(char *domain, int first, int sortit)
{
 static FILE *fsv = NULL;
 struct vqpasswd *tmpwd;

    if (set_vpasswd_files( domain ) == -1) {
        return (NULL);
    }
    
    if ( first == 1 ) {
        if ( fsv != NULL ) fclose(fsv);
        if (set_vpasswd_files( domain ) == -1) {
            return (NULL);
        }
        if ((fsv = fopen(vpasswd_file, "r")) == NULL) return(NULL);
    } else if ( fsv == NULL ) {
		return(NULL);
	}
    tmpwd = vgetent(fsv);
    if ( tmpwd == NULL ) {
		fclose(fsv);
		fsv = NULL;
	}
    if(tmpwd) vlimits_setflags(tmpwd,domain) ;
    return(tmpwd);
}

void vauth_end_getall()
{
}

int set_vpasswd_files( char *domain )
{
 char *tmpstr;
 uid_t uid;
 gid_t gid;
 int r;
 char Dir[156];

    vset_default_domain( domain );
    tmpstr = vget_assign(domain, Dir, 156, &uid, &gid );
    memset(vpasswd_dir, 0, MAX_BUFF);
    memset(vpasswd_file, 0, MAX_BUFF);
    memset(vpasswd_cdb_file, 0, MAX_BUFF);
    memset(vpasswd_cdb_tmp_file, 0, MAX_BUFF);
    memset(vpasswd_lock_file, 0, MAX_BUFF);

    if ( domain == NULL || domain[0] == 0 ) {
        snprintf(vpasswd_dir, MAX_BUFF, "%s/users", VPOPMAILDIR);
    } else {
        snprintf(vpasswd_dir, MAX_BUFF, "%s", Dir); 
    }
    r = snprintf(vpasswd_file, MAX_BUFF, "%s/%s", vpasswd_dir,VPASSWD_FILE);
    if (r == -1) {
        return -1;
    }
    r = snprintf(vpasswd_bak_file, MAX_BUFF, "%s/%s.%d", 
        vpasswd_dir,VPASSWD_BAK_FILE, getpid());
    if (r == -1) {
        return -1;
    }
    r = snprintf(vpasswd_cdb_file, MAX_BUFF, 
        "%s/%s", vpasswd_dir,VPASSWD_CDB_FILE);
    if (r == -1) {
        return -1;
    }
    r = snprintf(vpasswd_cdb_tmp_file, MAX_BUFF, 
        "%s/%s",vpasswd_dir,VPASSWD_CDB_TMP_FILE);
    if (r == -1) {
        return -1;
    }
    r = snprintf(vpasswd_lock_file, MAX_BUFF, 
        "%s/%s", vpasswd_dir,VPASSWD_LOCK_FILE);
    if (r == -1) {
        return -1;
    }
        
    return 0;
}

int vauth_adduser(char *user, char *domain, char *pass, char *gecos, char *dir, int apop )
{
 static char tmpbuf1[MAX_BUFF_CDB];
 static char tmpbuf2[MAX_BUFF_CDB];
 char *tmpstr;
 int added = 0;
 FILE *fs1;
 FILE *fs2;
#ifdef FILE_LOCKING
 int fd3;
#endif

    /* do not trod on the vpasswd file */
    if ( strcmp( "vpasswd", user ) == 0 ) {
      return( VA_ILLEGAL_USERNAME );
    }

    if (set_vpasswd_files( domain ) == -1) {
        return (-1);
    }

    /* if the gecos field is null, set it to user name */
    if ( gecos==0 || gecos[0]==0) gecos=user;
    vcdb_strip_char( gecos );

#ifdef FILE_LOCKING
    fd3 = open(vpasswd_lock_file, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR);
    if ( get_write_lock(fd3) < 0 ) return(-2);
#endif

    fs1 = fopen(vpasswd_bak_file, "w+");
    if ( (fs2 = fopen(vpasswd_file, "r+")) == NULL ) {
    	fs2 = fopen(vpasswd_file, "w+");
	}	
        
    if ( fs1 == NULL || fs2 == NULL ) {
		if ( fs1 != NULL ) fclose(fs1);
		if ( fs2 != NULL ) fclose(fs2);
#ifdef FILE_LOCKING
		unlock_lock(fd3, 0, SEEK_SET, 0);
		close(fd3);
#endif
        return(-1);
    }

    while (fgets(tmpbuf1,MAX_BUFF_CDB,fs2)!=NULL){    
        strncpy(tmpbuf2, tmpbuf1, MAX_BUFF_CDB);
        tmpstr = strtok(tmpbuf2,":");
        if ( added == 0 && strcmp(user, tmpstr) < 0 ) {
            added = 1;
            vauth_adduser_line( fs1, user, pass, domain,gecos,dir, apop);
        }
        fputs(tmpbuf1, fs1);
    }
    if ( added == 0 ) {
        vauth_adduser_line( fs1, user, pass, domain,gecos,dir,apop);
    }
    fclose(fs1);
    fclose(fs2);
    
    rename(vpasswd_bak_file, vpasswd_file);
      
    make_vpasswd_cdb(domain);
    
#ifdef FILE_LOCKING
	unlock_lock(fd3, 0, SEEK_SET, 0);
	close(fd3);
#endif

    return(0);
}

int vauth_adddomain( char *domain )
{
    return(0);
}

int vauth_deldomain( char *domain )
{
    return(0);
}

int vauth_deluser( char *user, char *domain )
{
 static char tmpbuf1[MAX_BUFF_CDB];
 static char tmpbuf2[MAX_BUFF_CDB];
 char *tmpstr;
 FILE *fs1;
 FILE *fs2;
#ifdef FILE_LOCKING
 int fd3;
#endif

    if (set_vpasswd_files( domain ) == -1) {
        return (-1);
    }

#ifdef FILE_LOCKING
	fd3 = open(vpasswd_lock_file, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR);
	if ( get_write_lock(fd3) < 0 ) return(-2);
#endif

    fs1 = fopen(vpasswd_bak_file, "w+");
    if ( (fs2 = fopen(vpasswd_file, "r+")) == NULL ) {
    	fs2 = fopen(vpasswd_file, "w+");
	}

    if ( fs1 == NULL || fs2 == NULL ) {
		if ( fs1 != NULL ) fclose(fs1);
		if ( fs2 != NULL ) fclose(fs2);
#ifdef FILE_LOCKING
		unlock_lock(fd3, 0, SEEK_SET, 0);
		close(fd3);
#endif
        return(-1);
    }

    while (fgets(tmpbuf1,MAX_BUFF_CDB,fs2)!=NULL){
        strncpy(tmpbuf2, tmpbuf1, MAX_BUFF_CDB);
        tmpstr = strtok(tmpbuf2,":");
        
        if ( strcmp(user, tmpstr) != 0) {
            fputs(tmpbuf1, fs1);
        } 
    }
    fclose(fs1);
    fclose(fs2);

    rename(vpasswd_bak_file, vpasswd_file);
    make_vpasswd_cdb(domain);

#ifdef FILE_LOCKING
	unlock_lock(fd3, 0, SEEK_SET, 0);
	close(fd3);
#endif

    return(0);
}

/* Utility function to set the users quota
 *
 * Calls underlying vauth_getpw and vauth_setpw
 * to actually change the users information
 */
int vauth_setquota( char *username, char *domain, char *quota)
{
 struct vqpasswd *vpw;

    if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR
    if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif
    if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
    if ( strlen(quota) > MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);

    vpw = vauth_getpw( username, domain );
    if ( vpw==NULL ) return(VA_USER_DOES_NOT_EXIST);
    vpw->pw_shell = quota;
    return(vauth_setpw(vpw,domain));

}

int vauth_setpw( struct vqpasswd *inpw, char *domain ) 
{
 static char tmpbuf1[MAX_BUFF_CDB];
 static char tmpbuf2[MAX_BUFF_CDB];
 
#ifdef USE_ONCHANGE
 char user_domain[MAX_BUFF];
#endif 
 
 char *tmpstr;
 FILE *fs1;
 FILE *fs2;
#ifdef FILE_LOCKING
 int fd3;
#endif
 uid_t myuid;
 uid_t uid;
 gid_t gid;
 int ret;
 
#ifdef USE_ONCHANGE
  snprintf( user_domain, MAX_BUFF, "%s@%s", inpw->pw_name, domain);
  on_change("mod_user", user_domain, "-", 0, 0);
#endif

    ret = vcheck_vqpw(inpw, domain);
    if ( ret != 0 ) return(ret);

	/* get the owner of the domain */
	vget_assign(domain,NULL,0,&uid,&gid);

	/* get the current effective user */
    myuid = geteuid();

	/* 
	 * if it is not the owner, vpopmail or root
	 * then reject this operation
	 */
    if ( myuid != 0 && myuid != uid ) {
		return(VA_BAD_UID);
    }

    if (set_vpasswd_files( domain ) == -1) {
        return (-1);
    }
    
#ifdef FILE_LOCKING
	fd3 = open(vpasswd_lock_file, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR);
	if ( get_write_lock(fd3) < 0 ) return(-2);
#endif

    fs1 = fopen(vpasswd_bak_file, "w+");
    if ( (fs2 = fopen(vpasswd_file, "r+")) == NULL ) {
    	fs2 = fopen(vpasswd_file, "w+");
	}

    if ( fs1 == NULL || fs2 == NULL ) {
		if ( fs1 != NULL ) fclose(fs1);
		if ( fs2 != NULL ) fclose(fs2);

#ifdef FILE_LOCKING
		unlock_lock(fd3, 0, SEEK_SET, 0);
		close(fd3);
#endif
        return(-1);
    }
    vcdb_strip_char( inpw->pw_gecos );
#ifndef CLEAR_PASS
    vcdb_strip_char( inpw->pw_clear_passwd );
#endif

    while (fgets(tmpbuf1,MAX_BUFF_CDB,fs2)!=NULL){
        strncpy(tmpbuf2, tmpbuf1, MAX_BUFF_CDB);
        tmpstr = strtok(tmpbuf2,":\n");
        
        if ( strcmp(inpw->pw_name, tmpstr) != 0) {
            fputs(tmpbuf1, fs1);
        } else {
#ifndef CLEAR_PASS
            fprintf(fs1, "%s:%s:%d:%d:%s:%s:%s\n",
                inpw->pw_name,
                inpw->pw_passwd,
                inpw->pw_uid,
                inpw->pw_gid,
                inpw->pw_gecos,
                inpw->pw_dir,
                inpw->pw_shell);
#else
            fprintf(fs1, "%s:%s:%d:%d:%s:%s:%s:%s\n",
                inpw->pw_name,
                inpw->pw_passwd,
                inpw->pw_uid,
                inpw->pw_gid,
                inpw->pw_gecos,
                inpw->pw_dir,
                inpw->pw_shell, inpw->pw_clear_passwd);
#endif
        }
    }
    fclose(fs1);
    fclose(fs2);

    rename(vpasswd_bak_file, vpasswd_file);
    make_vpasswd_cdb(domain);

#ifdef FILE_LOCKING
	unlock_lock(fd3, 0, SEEK_SET, 0);
	close(fd3);
#endif

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

int vauth_adduser_line( FILE *fs1, 
    char *user, 
    char *pass, 
    char *domain, 
    char *gecos, 
    char *dir, int apop )
{
 char Dir[156];
 uid_t uid;
 gid_t gid;
 char crypted[100];
 
	if ( vget_assign(domain, Dir, 156, &uid, &gid ) == NULL ) {
		strcpy(Dir, VPOPMAILDIR);
        }
 
        if ( pass[0] != 0 ) {
            mkpasswd3(pass,crypted, 100);
        } else {
            crypted[0] = 0;
        }
                                         
        fprintf(fs1,"%s:", user );
        
        if ( apop == USE_POP ) fprintf(fs1, "%s:1:", crypted);
        else fprintf(fs1, "%s:2:", crypted);

        fprintf(fs1, "0:%s:%s", gecos, Dir);
        
        if ( strlen(domain) <= 0 ) {
            if ( strlen(dir) > 0 ) {
                fprintf(fs1, "/users/%s/%s:", dir, user);
            } else {
                fprintf(fs1, "/users/%s:", user);
            }
        } else {
            if ( strlen(dir) > 0 ) {
                fprintf(fs1,"/%s/%s:", dir,user);
            } else {
                fprintf(fs1, "/%s:", user);
            }
        }

        fprintf(fs1, "NOQUOTA");

#ifndef CLEAR_PASS
        fprintf(fs1, "\n");
#else
        fprintf(fs1, ":%s\n", pass);
#endif

        return(0);
}


int vmkpasswd( char *domain )
{
#ifdef FILE_LOCKING
 int fd3;
#endif
 char Dir[156];
 uid_t uid;
 gid_t gid;
 char *tmpstr;

    getcwd(TmpBuf1, MAX_BUFF);
	tmpstr = vget_assign(domain, Dir, 156, &uid, &gid );

    if ( chdir(Dir) != 0 ) return(VA_BAD_DIR);

    lowerit(domain);
    
    if (set_vpasswd_files( domain ) == -1) {
        return (-1);
    }
    
#ifdef FILE_LOCKING
	fd3 = open(vpasswd_lock_file, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR);
	if ( get_write_lock(fd3) < 0 ) return(-2);
#endif

    make_vpasswd_cdb(domain);
#ifdef FILE_LOCKING
	unlock_lock(fd3, 0, SEEK_SET, 0);
	close(fd3);
#endif

    return(0);
}

/*   Verify the connection to the authentication database   */

int vauth_open( int will_update ) {

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

    return( 0 );
}

void vclose()
{

}

#ifdef IP_ALIAS_DOMAINS
int vget_ip_map( char *ip, char *domain, int domain_size)
{
 FILE *fs;
 char tmpbuf[156];
 char *tmpstr;

	if ( ip == NULL || strlen(ip) <= 0 ) return(-1);

	/* open the ip_alias_map file */
	snprintf(tmpbuf, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
	if ( (fs = fopen(tmpbuf,"r")) == NULL ) return(-1);

	while( fgets(tmpbuf, 156, fs) != NULL ) {
		tmpstr = strtok(tmpbuf, IP_ALIAS_TOKENS);
		if ( tmpstr == NULL ) continue;
		if ( strcmp(ip, tmpstr) != 0 ) continue;

		tmpstr = strtok(NULL, IP_ALIAS_TOKENS);
		if ( tmpstr == NULL ) continue;
		strncpy(domain, tmpstr, domain_size);
		fclose(fs);
		return(0);

	}
	fclose(fs);
	return(-1);
}

/* 
 * Add an ip to domain mapping
 * It will remove any duplicate entry before adding it
 *
 */
int vadd_ip_map( char *ip, char *domain)
{
 FILE *fs;
 char tmpbuf[156];

	if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
	if ( domain == NULL || strlen(domain) <= 0 ) return(-10);

	vdel_ip_map( ip, domain );

	snprintf(tmpbuf, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
	if ( (fs = fopen(tmpbuf,"a+")) == NULL ) return(-1);
	fprintf( fs, "%s %s\n", ip, domain);
	fclose(fs);

	return(0);
}

int vdel_ip_map( char *ip, char *domain) 
{
 FILE *fs;
 FILE *fs1;
 char file1[156];
 char file2[156];
 char tmpbuf[156];
 char tmpbuf1[156];
 char *ip_f;
 char *domain_f;

	if ( ip == NULL || strlen(ip) <= 0 ) return(-1);
	if ( domain == NULL || strlen(domain) <= 0 ) return(-1);

	snprintf(file1, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
	if ( (fs = fopen(file1,"r")) == NULL ) return(-1);

	snprintf(file2, 156,
            "%s/%s.%d", VPOPMAILDIR, IP_ALIAS_MAP_FILE, getpid());
	if ( (fs1 = fopen(file2,"w")) == NULL ) {
		fclose(fs);
		return(-1);
	}

	while( fgets(tmpbuf, 156, fs) != NULL ) {
		strncpy(tmpbuf1,tmpbuf, 156);

		ip_f = strtok(tmpbuf, IP_ALIAS_TOKENS);
		if ( ip_f == NULL ) continue;

		domain_f = strtok(NULL, IP_ALIAS_TOKENS);
		if ( domain_f == NULL ) continue;

		if ( strcmp(ip, ip_f) == 0 && strcmp(domain,domain_f) == 0)
			continue;

		fprintf(fs1, tmpbuf1);

	}
	fclose(fs);
	fclose(fs1);

	if ( rename( file2, file1) < 0 ) return(-1);

	return(0);
}

int vshow_ip_map( int first, char *ip, char *domain)
{
 static FILE *fs = NULL;
 char tmpbuf[156];
 char *tmpstr;

	if ( ip == NULL ) return(-1);
	if ( domain == NULL ) return(-1);

	if ( first == 1 ) {
		if ( fs != NULL ) {
			fclose(fs);
			fs = NULL;
		}
		snprintf(tmpbuf, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
		if ( (fs = fopen(tmpbuf,"r")) == NULL ) return(-1);
	}
	if ( fs == NULL ) return(-1);

	while (1) {
		if (fgets(tmpbuf, 156, fs) == NULL ) {
			fclose(fs);
			fs = NULL;
			return(0);
		}

		tmpstr = strtok(tmpbuf, IP_ALIAS_TOKENS);
		if ( tmpstr == NULL ) continue;
		strcpy( ip, tmpstr);

		tmpstr = strtok(NULL, IP_ALIAS_TOKENS);
		if ( tmpstr == NULL ) continue;
		strcpy( domain, tmpstr);

		return(1);
	}
	return(-1);

}
#endif

int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{ 
 FILE *fs;
 char dir_control_file[MAX_DIR_NAME];
 int i;

    strncpy(dir_control_file,dc_filename(domain, uid, gid),MAX_DIR_NAME);


    if ( (fs = fopen(dir_control_file, "r")) == NULL ) {
        vdir->cur_users = 0;
        for(i=0;i<MAX_DIR_LEVELS;++i){
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
        return(-1);
    } 

    fgets(dir_control_file, MAX_DIR_NAME, fs ); 
    vdir->cur_users = atol(dir_control_file);

    fgets(dir_control_file, MAX_DIR_NAME, fs ); 
    vdir->level_cur = atoi(dir_control_file);

    fgets(dir_control_file, MAX_DIR_NAME, fs ); 
    vdir->level_max = atoi(dir_control_file);

    fgets(dir_control_file, MAX_DIR_NAME, fs ); 
    vdir->level_start[0] = atoi(dir_control_file);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_start[1] = atoi(&dir_control_file[i]);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_start[2] = atoi(&dir_control_file[i]);

    fgets(dir_control_file, MAX_DIR_NAME, fs ); 
    vdir->level_end[0] = atoi(dir_control_file);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_end[1] = atoi(&dir_control_file[i]);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_end[2] = atoi(&dir_control_file[i]);

    fgets(dir_control_file, MAX_DIR_NAME, fs ); 
    vdir->level_mod[0] = atoi(dir_control_file);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_mod[1] = atoi(&dir_control_file[i]);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_mod[2] = atoi(&dir_control_file[i]);

    fgets(dir_control_file, MAX_DIR_NAME, fs ); 
    vdir->level_index[0] = atoi(dir_control_file);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_index[1] = atoi(&dir_control_file[i]);
    for(i=0;dir_control_file[i]!=' ';++i); ++i;
    vdir->level_index[2] = atoi(&dir_control_file[i]);

    fgets(dir_control_file, MAX_DIR_NAME, fs ); 
    for(i=0;dir_control_file[i]!=0;++i) {
        if (dir_control_file[i] == '\n') {
            dir_control_file[i] = 0;
        }
    }

    fgets(dir_control_file, MAX_DIR_NAME, fs ); 
    for(i=0;dir_control_file[i]!=0;++i) {
        if (dir_control_file[i] == '\n') {
            dir_control_file[i] = 0;
        }
    }
    strncpy(vdir->the_dir, dir_control_file, MAX_DIR_NAME);

    fclose(fs);

    return(0);
}

int vwrite_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid)
{ 
 FILE *fs;
 int r;
 char dir_control_file[MAX_DIR_NAME];
 char dir_control_tmp_file[MAX_DIR_NAME];

    strncpy(dir_control_file,dc_filename(domain, uid, gid),MAX_DIR_NAME);
    r = snprintf(dir_control_tmp_file, MAX_DIR_NAME, 
        "%s.%d", dir_control_file, getpid());
    if (r == -1) {
        return(-1);
    }

    if ( (fs = fopen(dir_control_tmp_file, "w+")) == NULL ) {
        return(-1);
    } 

    fprintf(fs, "%lu\n", vdir->cur_users);
    fprintf(fs, "%d\n", vdir->level_cur);
    fprintf(fs, "%d\n", vdir->level_max);
    fprintf(fs, "%d %d %d\n", 
        vdir->level_start[0],
        vdir->level_start[1],
        vdir->level_start[2]);
    fprintf(fs, "%d %d %d\n", 
        vdir->level_end[0],
        vdir->level_end[1],
        vdir->level_end[2]);
    fprintf(fs, "%d %d %d\n", 
        vdir->level_mod[0],
        vdir->level_mod[1],
        vdir->level_mod[2]);
    fprintf(fs, "%d %d %d\n", 
        vdir->level_index[0],
        vdir->level_index[1],
        vdir->level_index[2]);
    fprintf(fs, "%s\n", vdir->the_dir); 

    fclose(fs);

    rename( dir_control_tmp_file, dir_control_file); 

    chown(dir_control_file,uid, gid);

    return(0);
}

int vdel_dir_control(char *domain)
{
 char dir_control_file[MAX_DIR_NAME];

    vget_assign(domain, dir_control_file, 156, NULL,NULL);
    strncat(dir_control_file,"/.dir-control", MAX_DIR_NAME-strlen(dir_control_file)-1);
    return(unlink(dir_control_file));
}

#ifdef ENABLE_AUTH_LOGGING
int vset_lastauth(char *user, char *domain, char *remoteip )
{
 char *tmpbuf;
 FILE *fs;
 struct vqpasswd *vpw;
 uid_t uid;
 gid_t gid;

    if( (vpw = vauth_getpw( user, domain )) == NULL) return(0);

	tmpbuf = malloc(MAX_BUFF);
	snprintf(tmpbuf, MAX_BUFF, "%s/lastauth", vpw->pw_dir);
	if ( (fs = fopen(tmpbuf,"w+")) == NULL ) {
	  free(tmpbuf);
	  return(-1);
	}
	fprintf(fs, "%s", remoteip);
	fclose(fs);

        vget_assign(domain,NULL,0,&uid,&gid);
        chown(tmpbuf,uid,gid);
	free(tmpbuf);
	return(0);
}

time_t vget_lastauth( struct vqpasswd *pw, char *domain)
{
 char *tmpbuf;
 struct stat mystatbuf;

	tmpbuf = malloc(MAX_BUFF);
	snprintf(tmpbuf, MAX_BUFF, "%s/lastauth", pw->pw_dir);
	if ( stat(tmpbuf,&mystatbuf) == -1 ) {
		free(tmpbuf);
		return(0);
	}
	free(tmpbuf);
	return(mystatbuf.st_mtime);
}

char *vget_lastauthip( struct vqpasswd *pw, char *domain)
{
 static char tmpbuf[MAX_BUFF];
 FILE *fs;

	snprintf(tmpbuf, MAX_BUFF, "%s/lastauth", pw->pw_dir);
        if ( (fs=fopen(tmpbuf,"r"))==NULL) return(NULL);
        fgets(tmpbuf,MAX_BUFF,fs);
        fclose(fs);
        return(tmpbuf);
}
#endif /* ENABLE_AUTH_LOGGING */

char *dc_filename(char *domain, uid_t uid, gid_t gid)
{
 static char dir_control_file[MAX_DIR_NAME];
 struct passwd *pw;

    /* if we are lucky the domain is in the assign file */
    if ( vget_assign(domain,dir_control_file,MAX_DIR_NAME,NULL,NULL)!=NULL ) { 
	strncat(dir_control_file, "/.dir-control", MAX_DIR_NAME-strlen(dir_control_file)-1);

    /* it isn't in the assign file so we have to get it from /etc/passwd */
    } else {
      
        /* save some time if this is the vpopmail user */
        if ( uid == VPOPMAILUID ) {
            strncpy(dir_control_file, VPOPMAILDIR, MAX_DIR_NAME);

        /* for other users, look them up in /etc/passwd */
        } else if ( (pw=getpwuid(uid))!=NULL ) {
            strncpy(dir_control_file, pw->pw_dir, MAX_DIR_NAME);

        /* all else fails return a blank string */
        } else {
            return("");
        }

        /* stick on the rest of the path */
        strncat(dir_control_file, "/" DOMAINS_DIR "/.dir-control", MAX_DIR_NAME-strlen(dir_control_file)-1); 
    }
    return(dir_control_file);
}

void vcdb_strip_char( char *instr )
{
 char *nextstr;

    nextstr = instr;
    while (*instr != 0 ) {
       if ( *instr == ':' ) ++instr;
       if ( nextstr != instr ) *nextstr = *instr;
       ++nextstr;
       ++instr;
    }

}

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
