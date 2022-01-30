/*
 * $Id: vpopmail.c 1026 2011-02-08 21:35:17Z volz0r $
 * Copyright (C) 2000-2009 Inter7 Internet Technologies, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>
#include <pwd.h>
#include "config.h"
#ifdef HAVE_ERR_H
#include <err.h>
#endif
#include "md5.h"
#include "vpopmail.h"
#include "file_lock.h"
#include "vauth.h"
#include "vlimits.h"
#include "maildirquota.h"
#include "storage.h"

#ifndef MD5_PASSWORDS
#define MAX_PW_CLEAR_PASSWD 8
#endif

#ifdef VPOPMAIL_DEBUG
int show_trace=0;
int show_query=0;
int dump_data=0;
#endif

#ifdef POP_AUTH_OPEN_RELAY
/* keep a output pipe to tcp.smtp file */
int tcprules_fdm;
static char relay_tempfile[MAX_BUFF];
#endif

int verrori = 0;

extern int cdb_seek();

/* Global Flags */
int NoMakeIndex = 0;
int OptimizeAddDomain = 0;

#define PS_TOKENS " \t"
#define CDB_TOKENS ":\n\r"

#ifdef IP_ALIAS_DOMAINS
int host_in_locals(char *domain);
#endif

static char gen_chars[] = "abcdefghijklmnopqrstuvwxyz" \
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                          "0123456789.@!#%*";

static char ok_env_chars[] = "abcdefghijklmnopqrstuvwxyz" \
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                            "1234567890_-.@";

 typedef struct defsortrec {
   char *key;
   char *value;
 } sortrec;

/************************************************************************/

void string_list_init(string_list *a, int initial) {
  a->count = 0;
  a->size = ((initial + 3) / 4) * 4;
  if (a->size <= 0) a->size = 4;
  a->values = calloc(a->size, sizeof(char **));
  if (a->values == NULL) a->size = 0;
}

int string_list_add(string_list *a, char *value) {
  if (a->count >= (a->size - 2)) {
    char **new;

    a->size += 8;
    new = realloc(a->values, a->size * sizeof(char **));
    if (new != NULL) {
      a->values = new;
      return a->size;
    }
    return 0;
  }

  if ((a->values[a->count] = strdup(value)) == NULL)
    return 0;
  a->count++;
  return 1;
}

void string_list_free(string_list *a) {
 int i;

  if (a->values == NULL) return;
  for (i = 0; i < a->count; i++)
    free(a->values[i]);
  free(a->values);
}


/************************************************************************/

/* 
 * Add a domain to the email system
 *
 * input: domain name
 *        dir to put the files
 *        uid and gid to assign to the files
 */
int vadddomain( char *domain, char *dir, uid_t uid, gid_t gid )
{
 FILE *fs;
 int i;
 char *domain_hash;
 char DomainSubDir[MAX_BUFF];
 char dir_control_for_uid[MAX_BUFF];
 char tmpbuf[MAX_BUFF];
 char Dir[MAX_BUFF];
 int call_dir;
 string_list aliases;
 
#ifdef ONCHANGE_SCRIPT
  /*  Don't execute any implied onchange in called functions  */
  allow_onchange = 0;
#endif

  /* we only do lower case */
  lowerit(domain);

  /* reject domain names that are too short to be valid */
  if ( strlen( domain) <3) return (VA_INVALID_DOMAIN_NAME);

  /* reject domain names that exceed our max permitted/storable size */
  if ( strlen( domain ) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);

  /* check invalid email domain characters */
  for(i=0;domain[i]!=0;++i) {
    if (i == 0 && domain[i] == '-' ) return(VA_INVALID_DOMAIN_NAME);
    if (isalnum((int)domain[i])==0 && domain[i]!='-' && domain[i]!='.') {
      return(VA_INVALID_DOMAIN_NAME);
    }
  }
  if ( domain[i-1] == '-' ) return(VA_INVALID_DOMAIN_NAME);

  /* after the name is okay, check if it already exists */
  if ( vget_assign(domain, NULL, 0, NULL, NULL ) != NULL ) {
    return(VA_DOMAIN_ALREADY_EXISTS);
  }
 
  /* set our file creation mask for machines where the
   * sysadmin has tightened default permissions
   */
  umask(VPOPMAIL_UMASK);

  /* store the calling directory */
  call_dir = open(".", O_RDONLY);


  /* go to the directory where our Domains dir is to be stored 
   * check for error and return error on error
   */
  if ( chdir(dir) != 0 ) return(VA_BAD_V_DIR);

  /* go into the Domains subdir */
  if ( chdir(DOMAINS_DIR) != 0 ) {

    /* if it's not there, no problem, just try to create it */
    if ( mkdir(DOMAINS_DIR, VPOPMAIL_DIR_MODE) != 0 ) {
      fchdir(call_dir); close(call_dir);
      return(VA_CAN_NOT_MAKE_DOMAINS_DIR);
    }

    /*  set the permisions on our new Domains dir */
    chown(DOMAINS_DIR,uid,gid);

    /* now try moving into the Domains subdir again */
    if ( chdir(DOMAINS_DIR) != 0 ) {
      fchdir(call_dir); close(call_dir);
      return(VA_BAD_D_DIR);
    }
  }

  /* since domains can be added under any /etc/passwd
   * user, we have to create dir_control information
   * for each user/domain combination
   */
  snprintf(dir_control_for_uid, sizeof(dir_control_for_uid),
   "dom_%lu", (long unsigned)uid);

  /* work out a subdir name for the domain 
   * Depending on how many domains we have, it may need to be hashed
   */
  open_big_dir(dir_control_for_uid, uid, gid);       
  domain_hash = next_big_dir(uid, gid);
  close_big_dir(dir_control_for_uid, uid, gid);      

  if ( strlen(domain_hash) > 0 ) {
    snprintf(DomainSubDir, sizeof(DomainSubDir), "%s/%s", domain_hash, domain);
  } else {
    snprintf(DomainSubDir,sizeof(DomainSubDir), "%s", domain);
  }

  /* Check to make sure length of the dir isnt going to exceed
   * the maximum storable size
   * We dont want to start creating dirs and putting entries in
   * the assign file etc if the path is going to be too long
   */
  if (strlen(dir)+strlen(DOMAINS_DIR)+strlen(DomainSubDir) > MAX_PW_DIR) {
    /* back out of changes made so far */
    dec_dir_control(dir_control_for_uid, uid, gid);
    fchdir(call_dir); close(call_dir);
    return(VA_DIR_TOO_LONG);
  }

  /* Make the subdir for the domain */
  if ( r_mkdir(DomainSubDir, uid, gid ) != 0 ) {
    /* back out of changes made so far */
    dec_dir_control(dir_control_for_uid, uid, gid);
    fchdir(call_dir); close(call_dir);
    return(VA_COULD_NOT_MAKE_DOMAIN_DIR);
  }
  
  if ( chdir(DomainSubDir) != 0 ) {
    /* back out of changes made so far */
    vdelfiles(DomainSubDir);
    dec_dir_control(dir_control_for_uid, uid, gid);
    fchdir(call_dir); close(call_dir);
    return(VA_BAD_D_DIR);
  }

  /* create the .qmail-default file */
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/%s/%s/.qmail-default", dir, DOMAINS_DIR, 
    DomainSubDir);
  if ( (fs = fopen(tmpbuf, "w+"))==NULL) {
    /* back out of changes made so far */
    chdir(dir); chdir(DOMAINS_DIR);
    if (vdelfiles(DomainSubDir) != 0) {
      fprintf(stderr, "Failed to delete directory tree :%s\n", DomainSubDir);
    }
    dec_dir_control(dir_control_for_uid, uid, gid);
    fchdir(call_dir); close(call_dir);
    return(VA_COULD_NOT_OPEN_QMAIL_DEFAULT);
  } else {
    fprintf(fs, "| %s/bin/vdelivermail '' bounce-no-mailbox\n", VPOPMAILDIR);
    fclose(fs);
  }

  /* create an entry in the assign file for our new domain */
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/%s/%s", dir, DOMAINS_DIR, DomainSubDir);
  if (add_domain_assign( domain, domain, tmpbuf, uid, gid ) != 0) {
    /* back out of changes made so far */
    chdir(dir); chdir(DOMAINS_DIR);
    if (vdelfiles(DomainSubDir) != 0) {
      fprintf(stderr, "Failed to delete directory tree: %s\n", DomainSubDir);
    }
    dec_dir_control(dir_control_for_uid, uid, gid);
    fchdir(call_dir); close(call_dir);
    fprintf (stderr, "Error. Failed to add domain to assign file\n");
    return (VA_COULD_NOT_UPDATE_FILE);
  }

  /* recursively change ownership to new file system entries */
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/%s/%s", dir, DOMAINS_DIR, DomainSubDir);
  r_chown(tmpbuf, uid, gid);

  /* ask the authentication module to add the domain entry */
  /* until now we checked if domain already exists in cdb and
   * setup all dirs, but vauth_adddomain may __fail__ so we need to check
   */

  if (vauth_adddomain( domain ) != VA_SUCCESS ) {

    /* ok we have run into problems here. adding domain to auth backend failed
     * so now we need to reverse the steps we have already performed above 
     */

    fprintf(stderr, "Error. Failed while attempting to add domain to auth backend\n");

    chdir(dir); chdir(DOMAINS_DIR);    
    if (vdelfiles(DomainSubDir) != 0) {
      fprintf(stderr, "Failed to delete directory tree: %s\n", DomainSubDir);
    }

    dec_dir_control(dir_control_for_uid, uid, gid);

    vget_assign(domain, Dir, sizeof(Dir), &uid, &gid );

    string_list_init(&aliases, 1);
    string_list_add(&aliases, domain);

    if ( del_domain_assign(aliases.values, 1, domain, Dir, uid, gid) != 0) {
      fprintf(stderr, "Failed while attempting to remove domain from assign file\n");
    }

    if (del_control(aliases.values,1) !=0) {
      fprintf(stderr, "Failed while attempting to delete domain from the qmail control files\n");
    }

#ifdef USERS_BIG_DIR
    if (vdel_dir_control(domain) != 0) {
      fprintf (stderr, "Warning: Failed to delete dir_control for %s\n", domain);
    }
#endif

    /* send a HUP signal to qmail-send process to reread control files */
    signal_process("qmail-send", SIGHUP);

    fchdir(call_dir); close(call_dir);
    string_list_free(&aliases);
    return (VA_NO_AUTH_CONNECTION);
  }	
 
  /* ask qmail to re-read it's new control files */
  if ( OptimizeAddDomain == 0 ) {
    signal_process("qmail-send", SIGHUP);
  }


#ifdef ONCHANGE_SCRIPT
  allow_onchange = 1;
  /* tell other programs that data has changed */
  snprintf ( onchange_buf, MAX_BUFF, "%s", domain );
  call_onchange ( "add_domain" );
  allow_onchange = 0;
#endif

  /* return back to the callers directory and return success */
  fchdir(call_dir); close(call_dir);

  return(VA_SUCCESS);
}

/************************************************************************/

/* Delete a domain from the entire mail system
 *
 * If we have problems at any of the following steps, it has been 
 * decided that the best course of action is to continue rather than
 * abort. The idea behind this is to allow the removal of a partially
 * installed domain. We will emit warnings should any of the expected
 * cleanup steps fail.
 */
int vdeldomain( char *domain )
{
 struct stat statbuf;
 char Dir[MAX_BUFF];
 char domain_to_del[MAX_BUFF];
 char dircontrol[MAX_BUFF];
 uid_t uid;
 gid_t gid;
 string_list aliases;
 domain_entry *entry;
 int i = 0;
 int call_dir;

  /* we always convert domains to lower case */
  lowerit(domain);

  /* Check the length of the domain to del
   * If it exceeds the max storable size, 
   * then the user has made some sort of error in 
   * asking to del that domain, because such a domain
   * wouldnt be able to exist in the 1st place
   */
  if (strlen(domain) > MAX_PW_DOMAIN) return (VA_DOMAIN_NAME_TOO_LONG);

  /* now we want to check a couple for things :
   * a) if the domain to del exists in the system
   * b) if the domain to del is an aliased domain or not
   */

  /* Take a backup of the domain we want to del,
   * because when we call vget_assign, if the domain
   * is an alias, then the domain parameter will be
   * rewritten on return as the name of the real domain
   */
  snprintf(domain_to_del, sizeof(domain_to_del), "%s", domain);

  /* check if the domain exists. If so extract the dir, uid, gid */
  if (vget_assign(domain, Dir, sizeof(Dir), &uid, &gid ) == NULL) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  if ( strcmp(domain_to_del, domain) != 0 ) {
     /*  This is just an alias, so add it to the list of aliases
      *  that are about to be deleted.  It will be the only one
      *  but I will use the same code as multi domains anyway.
      */
     string_list_init(&aliases, 1);
     string_list_add(&aliases, domain_to_del);

#ifdef ONCHANGE_SCRIPT
     /* tell other programs that data has changed */
     snprintf ( onchange_buf, MAX_BUFF, "%s alias of %s", domain_to_del, domain );
     call_onchange ( "del_domain" );
#endif

  } else {
    /* this is an NOT aliased domain....
   * (aliased domains dont have any filestructure of their own)
   */

    /* check if the domain's dir exists */
    if ( stat(Dir, &statbuf) != 0 ) {
      fprintf(stderr, "Warning: Could not access (%s)\n",Dir);
    }

    /*
     * Michael Bowe 23rd August 2003
     *
     * at this point, we need to write some code to check if any alias domains
     * point to this (real) domain. If we find such aliases, then I guess we
     * have a couple of options :
     * 1. Abort with an error, saying cant delete domain until all
     *    aliases are removed 1st (list them)
     * 2. Zap all the aliases in additon to this domain
     *
     * Rick Widmer 28 April 3004
     *
     * OK.  Option 2 won.  If this domain has aliases they will all
     * be deleted.  If you want to warn people about this it should
     * be done by the program calling vdeldomain() before you call it.
     * You shuould be able to find example code in vdeldomain.c.
     *
     */

     entry = get_domain_entries( domain );

     if (entry==NULL) {   //  something went wrong
       if( verrori ) {    //  could not open file
         fprintf(stderr,"%s\n", verror(verrori));

       } else {           //  domain does not exist
         fprintf(stderr,"%s\n", verror(VA_DOMAIN_DOES_NOT_EXIST));
       }
     }

     string_list_init(&aliases, 10);

     while( entry ) {
       string_list_add(&aliases, entry->domain);
       entry = get_domain_entries(NULL);
     }

//   Dump the alias list
//     for(i=0;i<aliases.count;i++) {
//       fprintf(stderr,"alias %s\n", aliases[i]);
//     }


#ifdef ONCHANGE_SCRIPT
     /* tell other programs that data has changed */
     snprintf ( onchange_buf, MAX_BUFF, "%s", domain );
     call_onchange ( "del_domain" );
#endif

    /* call the auth module to delete the domain from the storage */
    /* Note !! We must del domain from auth module __before__ we delete it from
     * fs, because deletion from auth module may fail !!!!
     */

    /* del a domain from the auth backend which includes :
     * - drop the domain's table, or del all users from users table
     * - delete domain's entries from lastauth table
     * - delete domain's limit's entries
     */
    if (vauth_deldomain(domain) != VA_SUCCESS ) {
      fprintf (stderr, "Warning: Failed while attempting to delete domain from auth backend\n");
    }

    /* vdel_limits does the following :
     * If we have mysql_limits enabled,
     *  it will delete the domain's entries from the limits table
     * Or if we arent using mysql_limits,
     *  it will delete the .qmail-admin file from the domain's dir
     *
     * Note there are inconsistencies in the auth backends.  Some
     * will run vdel_limits() in vauth_deldomain(), others don't.
     * For now, we always run it to be safe.  Ultimately, the auth
     * backends should to be updated to do this.
     */  
    vdel_limits(domain);

#ifdef USERS_BIG_DIR
    /* delete the dir control info for this domain */
    if (vdel_dir_control(domain) != 0) {
      fprintf (stderr, "Warning: Failed to delete dir_control for %s\n", domain);
    }
#endif

    /* Now remove domain from filesystem */
    /* if it's a symbolic link just remove the link */
    if ( readlink(Dir, (char *) &call_dir, sizeof(call_dir)) != -1) {
      if ( unlink(Dir) !=0) {
        fprintf (stderr, "Warning: Failed to remove symlink for %s\n", domain);
      }
    } else {
      /* Not a symlink.. so we have to del some files structure now */
      /* zap the domain's directory tree */
      call_dir = open(".", O_RDONLY);

      if ( vdelfiles(Dir) != 0 ) {
        fprintf(stderr, "Warning: Failed to delete directory tree: %s\n", domain);
      }
      
      fchdir(call_dir); close(call_dir);
    }

    /* decrement the master domain control info */
    snprintf(dircontrol, sizeof(dircontrol), "dom_%lu", (long unsigned)uid);
    dec_dir_control(dircontrol, uid, gid);
  }

  /* The following things need to happen for real and aliased domains */

  /* delete the email domain from the qmail control files :
   * rcpthosts, morercpthosts, virtualdomains
   */
  if (del_control(aliases.values,aliases.count) != 0) {
    fprintf (stderr, "Warning: Failed to delete domain from qmail's control files\n");
  }

  /* delete the assign file line */
  if (del_domain_assign(aliases.values, aliases.count, domain, Dir, uid, gid) != 0) {
    fprintf (stderr, "Warning: Failed to delete domain from the assign file\n");
  }

  /* send a HUP signal to qmail-send process to reread control files */
  signal_process("qmail-send", SIGHUP);

  /*  clean up memory used by the alias list  */
  string_list_free(&aliases);

  return(VA_SUCCESS);

}

/************************************************************************/

/* get_domain_entries
 *
 * Parses the qmail users/assign file and returns a domain_entry pointer.
 * If first parameter is not NULL, re-open users/assign file and start scanning.
 *   If first parameter is "", return all entries.  Otherwise, only return
 *   entries where "real" domain matches the first parameter.
 * If first parameter is NULL, returns the next line in already open file.
 *
 * Example 1.  Scan through all entries.
 *   domain_entry *e;
 *   e = get_domain_entries ("");
 *   while (e) {
 *     printf ("Alias: %s  Real domain: %s  uid: %d  gid: %d  path: %s\n",
 *       e->domain, e->realdomain, e->uid, e->gid, e->path);
 *     e = get_domain_entries (NULL);
 *   }
 *
 * Example 2.  Find all entries (primary and aliases) for domain.com.
 *   domain_entry *e;
 *   e = get_domain_entries ("domain.com");
 *   while (e) {
 *     printf ("Alias: %s  Real domain: %s  uid: %d  gid: %d  path: %s\n",
 *       e->domain, e->realdomain, e->uid, e->gid, e->path);
 *     e = get_domain_entries (NULL);
 *   }
 *
 *
 */

domain_entry *get_domain_entries (const char *match_real)
{
        static FILE *fs = NULL;
        static char     match_buffer[MAX_PW_DOMAIN];
        static domain_entry entry;
        static char linebuf[MAX_BUFF];
        char *p;

        if (match_real != NULL) {
                if (fs != NULL) fclose (fs);
                snprintf (linebuf, sizeof (linebuf), "%s/users/assign", QMAILDIR);
                fs = fopen (linebuf, "r");

                snprintf (match_buffer, sizeof (match_buffer), "%s", match_real);
                vget_assign(match_buffer,NULL,0,NULL,NULL);
        }

        if (fs == NULL) {
           verrori = VA_CANNOT_READ_ASSIGN;
           return NULL;
        }

        while (fgets (linebuf, sizeof (linebuf), fs) != NULL) {
                /* ignore non-domain entries */
                if (*linebuf != '+') continue;

                entry.domain = strtok (linebuf + 1, ":");
                if (entry.domain == NULL) continue;

                /* ignore entries without '.' in them */
                if (strchr (entry.domain, '.') == NULL) continue;

                entry.realdomain = strtok (NULL, ":");
                if (entry.realdomain == NULL) continue;

                /* remove trailing '-' from entry.domain */
		if (entry.realdomain <= entry.domain + 2 ||
		    *(entry.realdomain-2) != '-') continue;
                *(entry.realdomain-2) = '\0';

                if ((p = strtok (NULL, ":")) == NULL) continue;
                entry.uid = atoi (p);

                if ((p = strtok (NULL, ":")) == NULL) continue;
                entry.gid = atoi (p);

                entry.path = strtok (NULL, ":");
                if (entry.path == NULL) continue;

                if (!*match_buffer || (strcmp (match_buffer, entry.realdomain) == 0))
                        return &entry;
        }

        /* reached end of file, so we're done */
        fclose (fs);
        fs=NULL;
        return NULL;
}

/************************************************************************/

/*
 * Add a virtual domain user
 */
int vadduser( char *username, char *domain, char *password, char *gecos, 
              int apop )
{
 char Dir[MAX_BUFF];
 char *user_hash;
 int call_dir;
 uid_t uid = VPOPMAILUID;
 gid_t gid = VPOPMAILGID;
 struct vlimits limits;
 char quota[50];

#ifdef ONCHANGE_SCRIPT
 int temp_onchange;
    temp_onchange = allow_onchange;
    allow_onchange = 0;
#endif

  /* check gecos for : characters - bad */
  if ( strchr(gecos,':')!=0) return(VA_BAD_CHAR);

  if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR
  if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif
  if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(domain) < 3) return(VA_INVALID_DOMAIN_NAME);

  if ( strlen(password) > MAX_PW_CLEAR_PASSWD ) return(VA_PASSWD_TOO_LONG);
  if ( strlen(gecos) > MAX_PW_GECOS )    return(VA_GECOS_TOO_LONG);

  umask(VPOPMAIL_UMASK);
  lowerit(username);
  lowerit(domain);

  if ( is_username_valid(username) != 0 ) return(VA_ILLEGAL_USERNAME);
  if ( is_domain_valid(domain) != 0 ) return(VA_INVALID_DOMAIN_NAME);

  if ( vauth_getpw( username, domain ) != NULL ) return(VA_USERNAME_EXISTS);

  /* lookup the home dir, uid and gid for the domain */
  if ( vget_assign(domain, Dir, sizeof(Dir), &uid, &gid)==NULL) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  /* make sure we can load domain limits for default quota */
  if (vget_limits(domain, &limits) != 0) {
    return(VA_CANNOT_READ_LIMITS);
  }

  /* record the dir where the vadduser command was run from */
  call_dir = open(".", O_RDONLY);

  /* go to the domain's home dir (ie test it exists) */
  /* would a stat be a better option here? */
  if ( chdir(Dir) != 0 ) {
    close(call_dir);
    return(VA_BAD_D_DIR);
  }

  /* create dir for the the user */ 
  if ( (user_hash=make_user_dir(username, domain, uid, gid)) == NULL ) {
    fchdir(call_dir); close(call_dir);
    if (verrori != 0 ) return(verrori);
    else return(VA_BAD_U_DIR);
  }
        
  /* add the user to the auth backend */
  /* NOTE: We really need to update this method to include the quota. */
  if (vauth_adduser(username, domain, password, gecos, user_hash, apop )!=0) {
    fprintf(stderr, "Failed while attempting to add user to auth backend\n");
    /* back out of changes made so far */
    chdir(Dir); if (strlen(user_hash)>0) { chdir(user_hash);} vdelfiles(username);
    fchdir(call_dir); close(call_dir);
    return(VA_NO_AUTH_CONNECTION);
  }

  if (limits.defaultquota > 0) {
    if (limits.defaultmaxmsgcount > 0)
      snprintf (quota, sizeof(quota), "%lluS,%lluC", limits.defaultquota,
        limits.defaultmaxmsgcount);
    else
      snprintf (quota, sizeof(quota), "%lluS", limits.defaultquota);
  } else {
    if (limits.defaultmaxmsgcount > 0)
      snprintf (quota, sizeof(quota), "%lluC", limits.defaultmaxmsgcount);
    else
      strcpy (quota, "NOQUOTA");
  }

  if (vsetuserquota (username, domain, quota) == VA_USER_DOES_NOT_EXIST) {
    /* server with replication, need to wait and try again */
    sleep(5);
    vsetuserquota (username, domain, quota);
  }

#ifdef SQWEBMAIL_PASS
  {
   /* create the sqwebmail-pass file in the user's maildir
    * This file contains a copy of the user's crypted password
    */
    struct vqpasswd *mypw;
    mypw = vauth_getpw( username, domain);
    if ( mypw != NULL ) { 
      vsqwebmail_pass( mypw->pw_dir, mypw->pw_passwd, uid, gid);
    }
  }
#endif

#ifdef ENABLE_AUTH_LOGGING
  if (vset_lastauth(username,domain,NULL_REMOTE_IP) !=0) {
    /* should we back out of all the work we have done so far? */
    fchdir(call_dir); close(call_dir);
    fprintf (stderr, "Failed to create create lastauth entry\n");
    return (VA_NO_AUTH_CONNECTION);
  }
#endif

  /* jump back into the dir from which the vadduser was run */
  fchdir(call_dir); close(call_dir);

#ifdef ONCHANGE_SCRIPT
  allow_onchange = temp_onchange;
  /* tell other programs that data has changed */
  snprintf ( onchange_buf, MAX_BUFF, "%s@%s", username, domain );
  call_onchange ( "add_user" );
  allow_onchange = 1;
#endif

  return(VA_SUCCESS);
}

/************************************************************************/

char randltr(void)
{
  static const char saltchar[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  return saltchar[(rand() % 64)];
}

/************************************************************************/

/*
 * encrypt a password 
 * Input
 * clearpass = pointer to clear text password
 * ssize     = size of the crypted pointer buffer
 * 
 * Output
 *  copies the encrypted password into the crypted 
 *      character pointer
 * 
 * Return code:
 *   VA_CRYPT_FAILED = encryption failed
 *   VA_SUCCESS = 0  = encryption success
 * 
 */
int mkpasswd3( char *clearpass, char *crypted, int ssize )
{
 char *tmpstr;
 char salt[12];
 static int seeded = 0;

 if (!seeded) {
   seeded = 1;
   srand (time(NULL)^(getpid()<<15));
 }

#ifdef MD5_PASSWORDS
  salt[0] = '$';
  salt[1] = '1';
  salt[2] = '$';
  salt[3] = randltr();
  salt[4] = randltr();
  salt[5] = randltr();
  salt[6] = randltr();
  salt[7] = randltr();
  salt[8] = randltr();
  salt[9] = randltr();
  salt[10] = randltr();
  salt[11] = 0;
#else
  salt[0] = randltr();
  salt[1] = randltr();
  salt[2] = 0;
#endif

  tmpstr = crypt(clearpass,salt);
  if ( tmpstr == NULL ) return(VA_CRYPT_FAILED);

#ifdef MD5_PASSWORDS
  /* Make sure this host's crypt supports MD5 passwords.  If not,
   * fall back on old-style crypt
   */
  if (tmpstr[2] != '$') {
    salt[0] = randltr();
    salt[1] = randltr();
    salt[2] = 0;
    tmpstr = crypt(clearpass,salt);
    if ( tmpstr == NULL ) return(VA_CRYPT_FAILED);
  }
#endif

  strncpy(crypted,tmpstr, ssize);
  return(VA_SUCCESS);
}

/************************************************************************/

/* 
 * prompt the command line and get a password twice, that matches 
 */

void vgetpasswd(char *user, char *pass, size_t len)
{
 char pass2[128];
 char prompt[128];

  snprintf( prompt, sizeof(prompt), "Please enter password for %s: ", user);

  while( 1 ) {
    snprintf(pass, len, "%s", getpass(prompt));
    snprintf(pass2, sizeof(pass2), "%s", getpass("enter password again: "));

    if ( strcmp( pass, pass2 ) != 0 ) {
      printf("Passwords do not match, try again\n");
    } else {
	return;
    }
  }
}

/************************************************************************/

/* 
 * vdelfiles : delete a directory tree
 *
 * input: directory to start the deletion
 * output: 
 *         0 on success
 *        -1 on failer
 */
int vdelfiles(char *dir)
{
 DIR *mydir;
 struct dirent *mydirent;
 struct stat statbuf;

  /* Modified By David Wartell david@actionwebservices.com to work with 
   * Solaris. Unlike Linux, Solaris will NOT return error when unlink() 
   * is called on a directory.   A correct implementation to support 
   * Linux & Solaris is to test to see if the file is a directory.  
   * If it is not a directory unlink() it. 
   * If unlink() returns an error return error.
   */

  if (lstat(dir, &statbuf) == 0) {

    /* if dir is not a directory unlink it */
    if ( !( S_ISDIR(statbuf.st_mode) ) ) {
      if ( unlink(dir) == 0 ) {
        /* return success we deleted the file */
        return(0);
      } else {
        /* error, return error to calling function, 
         * we couldn't unlink the file 
         */
        return(-1);
      }
    }

  } else {
    /* error, return error to calling function, 
     * we couldn't lstat the file 
     */
    return(-1);
  }

  /* go to the directory, and check for error */ 
  if (chdir(dir) == -1) {
    /* error, return error to calling function */
    return(-1);
  }

  /* open the directory and check for an error */
  if ( (mydir = opendir(".")) == NULL ) {
    /* error, return error */
    fprintf(stderr, "Failed to opendir()");
    return(-1);
  }

  while((mydirent=readdir(mydir))!=NULL){

    /* skip the current directory and the parent directory entries */
    if ( strncmp(mydirent->d_name,".", 2) !=0 &&
         strncmp(mydirent->d_name,"..", 3)!=0 ) {

      /* stat the file to check it's type, I/O expensive */
      stat( mydirent->d_name, &statbuf);

      /* Is the entry a directory? */
      if ( S_ISDIR(statbuf.st_mode) ) {

        /* delete the sub tree, -1 means an error */
        if ( vdelfiles ( mydirent->d_name) == -1 ) {

          /* on error, close the directory stream */
          closedir(mydir);

          /* and return error */
          return(-1);
        }

      /* the entry is not a directory, unlink it to delete */
      } else {

        /* unlink the file and check for error */
        if (unlink(mydirent->d_name) == -1) {

          /* print error message and return and error */
          fprintf (stderr, "Failed to delete directory %s", mydirent->d_name);
          return(-1);
        }
      }
    }
  }
  
  /* close the directory stream, we don't need it anymore */
  closedir(mydir);

  /* go back to the parent directory and check for error */
  if (chdir("..") == -1) {

    /* print error message and return an error */
    fprintf(stderr, "Failed to cd to parent");
    return(-1);
  }

  /* delete the directory, I/O expensive */
  rmdir(dir);

  /* return success */
  return(0);
}

/************************************************************************/

/* 
 * Add a domain to all the control files 
 * And signal qmail
 * domain is the domain name
 * dir is the full path to the domain directory
 * uid and gid are the uid/gid to store in the assign file
 */
int add_domain_assign( char *alias_domain, char *real_domain,
                       char *dir, uid_t uid, gid_t gid )
{
 FILE *fs1 = NULL;
 struct stat mystat;
 char tmpstr1[MAX_BUFF];
 char tmpstr2[MAX_BUFF];
 string_list aliases;

  string_list_init(&aliases, 1);
  string_list_add(&aliases,alias_domain);

  snprintf(tmpstr1, sizeof(tmpstr1), "%s/users/assign", QMAILDIR);

  /* stat assign file, if it's not there create one */
  if ( stat(tmpstr1,&mystat) != 0 ) {
    /* put a . on one line by itself */
    if ( (fs1 = fopen(tmpstr1, "w+"))==NULL ) {
      fprintf(stderr, "could not open assign file\n");
      return(-1);
    }
    fputs(".\n", fs1);
    fclose(fs1);
  }

  snprintf(tmpstr2, sizeof(tmpstr2), "+%s-:%s:%lu:%lu:%s:-::",
    alias_domain, real_domain, (long unsigned)uid, (long unsigned)gid, dir);

  /* update the file and add the above line and remove duplicates */
  if (update_file(tmpstr1, tmpstr2, 1) !=0 ) {
   fprintf (stderr, "Failed while attempting to update_file() the assign file\n");
   return (-1);
  }

  /* set the mode in case we are running with a strange mask */
  chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

  /* compile the assign file */
  /* as of the 5.4 builds, we always need an updated assign file since
   * we call vget_assign to add the postmaster account.  The correct
   * solution is to cache the information somewhere so vget_assign
   * can pull from cache instead of having to read the assign file.
   */
  /* if ( OptimizeAddDomain == 0 ) */ update_newu();

  /* If we have more than 50 domains in rcpthosts
   * make a morercpthosts and compile it
   */
  if ( count_rcpthosts() >= 50 ) {
    snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/morercpthosts", QMAILDIR);
    if (update_file(tmpstr1, alias_domain, 2) !=0) {
      fprintf (stderr, "Failed while attempting to update_file() the morercpthosts file\n");
      return (-1);
    }
    snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/morercpthosts", QMAILDIR);
    chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

    if ( OptimizeAddDomain == 0 ) compile_morercpthosts();

  /* or just add to rcpthosts */
  } else {
    snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/rcpthosts", QMAILDIR);
    if (update_file(tmpstr1, alias_domain, 2) != 0) {
      fprintf (stderr, "Failed while attempting to update_file() the rcpthosts file\n");
      return (-1);
    }
    snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/rcpthosts", QMAILDIR);
    chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 
  }
    
  /* Add to virtualdomains file and remove duplicates  and set mode */
  snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/virtualdomains", QMAILDIR );
  snprintf(tmpstr2, sizeof(tmpstr2), "%s:%s", alias_domain, alias_domain );
  if (update_file(tmpstr1, tmpstr2, 3) !=0 ) {
    fprintf (stderr, "Failed while attempting to update_file() the virtualdomains file\n");
    return (-1);
  };
  chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

  /* make sure it's not in locals and set mode */
  snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/locals", QMAILDIR);
  if (remove_lines( tmpstr1, aliases.values, aliases.count) < 0) {
    fprintf (stderr, "Failure while attempting to remove_lines() the locals file\n");
    return(-1);
  }
  chmod(tmpstr1, VPOPMAIL_QMAIL_MODE ); 

  string_list_free(&aliases);

  return(0);
}

/************************************************************************/

/*
 * delete a domain from the control files
 * the control files consist of :
 * - /var/qmail/control/rcpthosts
 * - /var/qmail/control/virtualdomains
 */
int del_control(char **aliases, int aliascount ) 
{
 char tmpbuf1[MAX_BUFF];
 char tmpbuf2[MAX_BUFF];
 struct stat statbuf;
 string_list virthosts;

 int problem_occurred = 0, i=0;

  /* delete entry from control/rcpthosts (if it is found) */
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s/control/rcpthosts", QMAILDIR);
  switch ( remove_lines(tmpbuf1, aliases, aliascount) ) {

    case -1 :
      /* error ocurred in remove line */
      fprintf (stderr, "Failed while attempting to remove_lines() the rcpthosts file\n");
      problem_occurred = 1;
      break;

    case 0 :
      /* not found in rcpthosts, so try morercpthosts */
      snprintf(tmpbuf1, sizeof(tmpbuf1), "%s/control/morercpthosts", QMAILDIR);
  
      switch (remove_lines(tmpbuf1, aliases, aliascount) ) {

        case -1 :
          fprintf (stderr, "Failed while attempting to remove_lines() the morercpthosts file\n");
          problem_occurred = 1;
          break; 

        case 0 :
         /* not found in morercpthosts */
          break;

        case 1 :
          /* was removed from morercpthosts */
          if ( stat( tmpbuf1, &statbuf) == 0 ) {
            /* Now check to see if morercpthosts its empty */
            if ( statbuf.st_size == 0 ) {
              /* is empty. So delete it */
              unlink(tmpbuf1);
              /* also delete the morercpthosts.cdb */
              strncat(tmpbuf1, ".cdb", sizeof(tmpbuf1)-strlen(tmpbuf1)-1);
              unlink(tmpbuf1);
            } else {
              /* morercpthosts is not empty, so compile it */
              compile_morercpthosts();
              /* make sure correct permissions are set on morercpthosts */
              chmod(tmpbuf1, VPOPMAIL_QMAIL_MODE ); 
            }
          }
          break; 

      } /* switch for morercpthosts */ 
      break;

    case 1 : /* we removed the line successfully */
      /* make sure correct permissions are set on rcpthosts */
      chmod(tmpbuf1, VPOPMAIL_QMAIL_MODE );
      break; 
  } /* switch for rcpthosts */

  /* delete entry from control/virtualdomains (if it exists) */
  string_list_init(&virthosts, 10);
  
  for(i=0;i<aliascount;i++) {
    snprintf(tmpbuf1, sizeof(tmpbuf1), "%s:%s", aliases[i], aliases[i]);
    string_list_add(&virthosts, tmpbuf1);
  }

  snprintf(tmpbuf2, sizeof(tmpbuf2), "%s/control/virtualdomains", QMAILDIR);
  if (remove_lines( tmpbuf2, virthosts.values, virthosts.count) < 0 ) {
    fprintf(stderr, "Failed while attempting to remove_lines() the virtualdomains file\n"); 
    problem_occurred = 1; 
  }

  string_list_free(&virthosts);

  /* make sure correct permissions are set on virtualdomains */
  chmod(tmpbuf2, VPOPMAIL_QMAIL_MODE ); 
  
  if (problem_occurred == 1) {
    return (-1);
  } else { 
    return(0);
  }
}

/************************************************************************/

/*
 * delete a domain from the users/assign file
 * input : lots;)
 *
 * output : 0 = success no aliases
 *          less than error = failure
 *          greater than 0 = number of aliases deleted
 *
 */
int del_domain_assign( char **aliases, int aliascount, 
                       char *real_domain, 
                       char *dir, gid_t uid, gid_t gid )  
{
 char search_string[MAX_BUFF];
 char assign_file[MAX_BUFF];
 string_list virthosts;
 int i;

  string_list_init(&virthosts, 10);

  /* format the removal string */ 
  for(i=0;i<aliascount;i++) {
  snprintf(search_string, sizeof(search_string), "+%s-:%s:%lu:%lu:%s:-::",
      aliases[i], real_domain, (long unsigned)uid, (long unsigned)gid, dir);
    string_list_add(&virthosts, search_string);
  }

  /* format the assign file name */
  snprintf(assign_file, sizeof(assign_file), "%s/users/assign", QMAILDIR);

  /* remove the formatted string from the file */
  if (remove_lines( assign_file, virthosts.values, virthosts.count ) < 0) {
    fprintf(stderr, "Failed while attempting to remove_lines() the assign file\n");
    string_list_free(&virthosts);
    return (-1);
  }

  string_list_free(&virthosts);

  /* force the permission on the file */
  chmod(assign_file, VPOPMAIL_QMAIL_MODE ); 

  /* compile assign file */
  update_newu();

  vget_assign(NULL, NULL, 0, NULL, NULL);  //  clear cache
  return(0);
}

/************************************************************************/

/*
 * Generic remove a line from a file utility
 * input: template to search for
 *        file to search inside
 *
 * output: -1 on failure
 *          0 on success, no match found
 *          1 on success, match was found
 */
int remove_lines( char *filename, char **aliases, int aliascount )
{
 FILE *fs = NULL;
 FILE *fs1 = NULL;
#ifdef FILE_LOCKING
 int fd3 = 0;
#endif
 char tmpbuf1[MAX_BUFF];
 char tmpbuf2[MAX_BUFF];
 int i, count=0, removed=0, doit=0;

//  fprintf( stderr, "\n***************************************\n" 
//                      "remove lines - file: %s\n", filename );
//  for(i=0;i<aliascount;i++) {
//    fprintf( stderr,  "               line: %s\n", aliases[i] );
//  }


#ifdef FILE_LOCKING
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.lock", filename);
  if ( (fd3 = open(tmpbuf1, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR)) < 0 ) {
    fprintf(stderr, "could not open lock file %s\n", tmpbuf1);
    return(VA_COULD_NOT_UPDATE_FILE);
  }

  if ( get_write_lock(fd3) < 0 ) return(-1);
#endif

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.%lu", filename, (long unsigned)getpid());
  fs1 = fopen(tmpbuf1, "w+");
  if ( fs1 == NULL ) {
#ifdef FILE_LOCKING
    unlock_lock(fd3, 0, SEEK_SET, 0);
    close(fd3);
#endif
    return(VA_COULD_NOT_UPDATE_FILE);
  }

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s", filename);
  if ( (fs = fopen(tmpbuf1, "r")) == NULL ) {
    if (errno != ENOENT)
	return VA_COULD_NOT_UPDATE_FILE;
    if ( (fs = fopen(tmpbuf1, "w+")) == NULL ) {
      fclose(fs1);
#ifdef FILE_LOCKING
      close(fd3);
      unlock_lock(fd3, 0, SEEK_SET, 0);
#endif
      return(VA_COULD_NOT_UPDATE_FILE);
    }
  }

  while( fgets(tmpbuf1,sizeof(tmpbuf1),fs) != NULL ) {
    count++;

    //  Trim \n off end of line.
    for(i=0;tmpbuf1[i]!=0;++i) {
      if (tmpbuf1[i]=='\n') {
        tmpbuf1[i]=0;
	break;
      }
    }

//    fprintf( stderr, "   Entry: %s\n", tmpbuf1 );

    doit=1;
    for(i=0;i<aliascount;i++) {
      if( 0 == strcmp(tmpbuf1,aliases[i])) {
        doit=0;
//        fprintf( stderr, "      ***  DELETE  ***\n");
	break;
        }
      }    
    if( doit ) {
      fprintf(fs1, "%s\n", tmpbuf1);
    } else {
      removed++;
    }
  }

  fclose(fs);
  fclose(fs1);

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s", filename);
  snprintf(tmpbuf2, sizeof(tmpbuf2), "%s.%lu", filename, (long unsigned)getpid());

  rename(tmpbuf2, tmpbuf1);

#ifdef FILE_LOCKING
  unlock_lock(fd3, 0, SEEK_SET, 0);
  close(fd3);
#endif

  return(removed);
}

/************************************************************************/

/* 
 * Recursive change ownership utility 
 */
int r_chown(char *path, uid_t owner, gid_t group )
{
 DIR *mydir;
 struct dirent *mydirent;
 struct stat statbuf;

  chown(path,owner,group);
  if (chdir(path) == -1) {
    fprintf(stderr, "r_chown() : Failed to cd to directory %s", path);
    return(-1);
  }
  mydir = opendir(".");
  if ( mydir == NULL ) { 
    fprintf(stderr, "r_chown() : Failed to opendir()");
    return(-1);
  }

  while((mydirent=readdir(mydir))!=NULL){
    if ( strncmp(mydirent->d_name,".", 2)!=0 && 
         strncmp(mydirent->d_name,"..", 3)!=0 ) {
      stat( mydirent->d_name, &statbuf);
      if ( S_ISDIR(statbuf.st_mode) ) {
        r_chown( mydirent->d_name, owner, group);
      } else {
        chown(mydirent->d_name,owner,group);
      }
    }
  }
  closedir(mydir);
  if (chdir("..") == -1) {
    fprintf(stderr, "rchown() : Failed to cd to parent");
    return(-1);
  }
  return(0);
}

/************************************************************************/

/* 
 * Send a signal to a process utility function
 *
 * name    = name of process
 * sig_num = signal number 
 */
int signal_process(char *name, int sig_num)
{
 FILE *ps;
 char *tmpstr;
 int  col;
 pid_t tmppid;
 pid_t mypid;
 int  pid_col=0;
 char pid[10];
 char tmpbuf1[1024];

  mypid = getpid();

  if ( (ps = popen(PS_COMMAND, "r")) == NULL ) {
    perror("popen on ps command");
    return(-1);
  }

  if (fgets(tmpbuf1, sizeof(tmpbuf1), ps)!= NULL ) {
    col=0;
    tmpstr = strtok(tmpbuf1, PS_TOKENS);
    while (tmpstr != NULL ) {
      if (strcmp(tmpstr, "PID") == 0 ) pid_col = col;

      tmpstr = strtok(NULL, PS_TOKENS);
      ++col;
    }
  }

  while (fgets(tmpbuf1, sizeof(tmpbuf1), ps)!= NULL ) {
    if ( strstr( tmpbuf1, name ) != NULL && 
         strstr(tmpbuf1, "supervise") == NULL &&
         strstr(tmpbuf1, "multilog") == NULL &&
         strstr(tmpbuf1, "svscan") == NULL) {
      tmpstr = strtok(tmpbuf1, PS_TOKENS);
      col = 0;
      do {
        if( col == pid_col ) {
          snprintf(pid, sizeof(pid), "%s", tmpstr);
          break;
        } 
        ++col;
        tmpstr = strtok(NULL, PS_TOKENS);
      } while ( tmpstr!=NULL );
      tmppid = atoi(pid);
      if ( tmppid && (tmppid != mypid) ) { 
        kill(tmppid,sig_num);
      }
    }
  }
  pclose(ps);
  return(0);
}

/************************************************************************/

/*
 * Compile the users/assign file using qmail-newu program
 */
int update_newu()
{
 int pid;

  pid=vfork();
  if ( pid==0){
			  umask(022);
    execl(QMAILNEWU,"qmail-newu", NULL);
    exit(127);
  } else {
    waitpid(pid,&pid,0);
  }
  return(0);
}

/************************************************************************/

/*
 * parse out user and domain from an email address utility function
 * 
 * email  = input email address
 * user   = parsed user
 * domain = parsed domain
 * buff_size = the size of the user and domain buffer. 
 *             These need to be the same size or potential buffer overflows
 *             could occur!
 * 
 * return 0 on success
 *       -1 on error
 */
int parse_email(char *email, char *user, char *domain, int buff_size ) 
{
 int i;
 int n;
 int len;
 char *at = NULL;

  lowerit(email);

  len = strlen(ATCHARS);
  for(i=0;i<len; ++i ) if ((at=strchr(email,ATCHARS[i]))) break;

  /* did we find an "AT" char in the email address? */
  if ( at!=NULL ) {
    /* yep we found an AT char */
    /* work out what pos it is in the email address array, store this in n */
    n = at - email + 1;
    if ( n > buff_size ) n = buff_size;
    /* suck out the username */
    snprintf(user, n, "%s", email); 
    /* now suck out the domain name */
    snprintf(domain, buff_size, "%s", ++at);
  } else {
    /* No AT char found, so populate username, leave domain blank */
    snprintf(user, buff_size, "%s", email);
    domain[0] = 0;
  }

  /* check the username for any invalid chars */
  if ( is_username_valid( user ) != 0 ) {
    fprintf(stderr, "user invalid %s\n", user);
    return(-1);
  }

  /* check the domain for any invalid chars */
  if ( is_domain_valid( domain ) != 0 ) {
    fprintf(stderr, "domain invalid %s\n", domain);
    return(-1);
  }

  /* if we havent found a domain, try and set it to the the default domain */
  vset_default_domain(domain);

  return(0);
} 

/************************************************************************/

/*
 * update a users virtual password file entry with a different password
 */
int vpasswd( char *username, char *domain, char *password, int apop )
{
 struct vqpasswd *mypw;
 char Crypted[MAX_BUFF];
#ifdef SQWEBMAIL_PASS
 uid_t uid;
 gid_t gid;
#endif

  if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR  
  if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif
  if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(password) > MAX_PW_CLEAR_PASSWD ) return(VA_PASSWD_TOO_LONG);

  lowerit(username);
  lowerit(domain);

  /* get the password entry for this user */
  mypw = vauth_getpw( username, domain);
  if ( mypw == NULL ) return(-1); 

  /* dont update password, if password updates are disabled */
  if ( mypw->pw_flags & NO_PASSWD_CHNG ) return(-1);

  /* encrypt their supplied password, and save it */
  mkpasswd3(password,Crypted, sizeof(Crypted));
  mypw->pw_passwd = Crypted;

#ifdef CLEAR_PASS
  /* save the clear password too (if clear passwords are enabled) */
  mypw->pw_clear_passwd = password;
#endif

#ifdef SQWEBMAIL_PASS
  /* update the sqwebmail-pass file in the user's maildir (if required) */
  vget_assign(domain, NULL, 0, &uid, &gid );
  vsqwebmail_pass( mypw->pw_dir, Crypted, uid, gid);
#endif
  return (vauth_setpw( mypw, domain));
}

/************************************************************************/

void trim( char *s )  {

//  trim spaces and tabs from beginning
int i=0, j, k;

while(( s[i]==' ')||(s[i]=='\t')) {
   i++;
   }

k = strlen(s) - i - 1; 

if( i>0 ) {
   for( j=0; j<k; j++ )  {
      s[j] = s[j+i];
      }

   s[j] = '\0';
   }

//  trim spaces and tabs from end
i = strlen(s) - 1;
while(( s[i] == ' ' ) || ( s[i] == '\t' )) {
   i--;
   }

if( i < strlen(s) - 1 ) {
   s[i+1] = '\0';
   }
}



/************************************************************************/


int isCatchall( char *user, char *domain, char *dir )   {

 //  This might not be the easiest way to do this...

 char *default_action;
 char *position;
 char *name;
 char email[MAX_BUFF];
 int i, pos;

  //  get the first line of the .qmail-default file
  snprintf( email, MAX_BUFF, "default" );
  default_action = valias_select( email, domain );

  snprintf( email, MAX_BUFF, "%s@%s", user, domain );
//  fprintf( stderr, "email: %s  default action: %s\ndir: %s\n", email, default_action, dir );

  fflush( stderr );

  //  Make sure .qmail_default file contains a reference to vdelivermail
  if( NULL == default_action ) {
//    fprintf( stderr, ".qmail_default file not found.  is this a database?\n" );
    return 0;
    }

  //  Make sure .qmail_default file contains a reference to vdelivermail
  if( ( position = strstr( default_action, "vdelivermail" )) == NULL ) {
//    fprintf( stderr, ".qmail_default file does not include vdelivermail. %s\n", position );
    return 0;
    }

  //  Make sure .qmail_default file continues with ''
  if( ( position = strstr( default_action, "''" )) == NULL  ) {
//    fprintf( stderr, ".qmail_default file missing ''. %s\n", position );
    return 0;
    }

  //  Make sure there is a space after ''
  if( ( position = strstr( position, " " )) == NULL  ) {
//    fprintf( stderr, ".qmail_default does not have space after ''. %s\n", position );
    return 0;
    }

  //  Remove spaces / tabs
  trim( position );

// fprintf( stderr, "Default action for non-existant addresses: |%s|\n", position );

  if( strstr( position, "bounce-no-mailbox" ) != NULL )  {
    //  don't do anything for this default action
//    fprintf( stderr, "Default is Bounce No Mailbox\n" );
    }

  else if( strstr( position, "delete-no-mailbox" ) != NULL ) {
    //  don't do anything for this default action
//    fprintf( stderr, "Default is Delete No Mailbox\n" );
    }

  else if( '/' == position[0] ) {
    //  it is a Maildir
//    fprintf( stderr, "Maildir - %s\n", position );
    if( strstr( position, dir ) != NULL ) {
//      fprintf( stderr, "part of correct domain sub directory\n" );
      position = strrchr( position, '/' );
//      fprintf( stderr, "position: %s\n", position );
      for( i=0; i<strlen( position )-1; i++ ) {
        position[i] = position[i+1];
        }
      position[i] = 0;

//      fprintf( stderr, "position: %s\n", position );

      if( strcmp( user, position ) == 0 ) {
//        fprintf( stderr, "%s is the catchall account by path\n", position );
        return( 1 );
        }
      }
    }

  else if(( pos = strcspn( position, "@" ))) {
    //  it is a forward
    name = strtok( position, "@" );
    position = strtok( NULL, "@" );
//    fprintf( stderr, "Forward - name: %s  domain: %s\n", name, position );
    if( ( strcmp( user, name ) == 0 ) && ( strcmp( position, domain ) == 0 ) ) {
//      fprintf( stderr, "%s is the catchall account by forward", position );
      return( 1 );
      }
    }

  else {
    fprintf( stderr, "unknown .qmail-default contents %s\n", position );
    }

return 0;

}


/************************************************************************/

/*
 * delete a user from a virtual domain password file
 */
int vdeluser( char *user, char *domain )
{
 struct vqpasswd *mypw;
 char Dir[MAX_BUFF];
 uid_t uid;
 gid_t gid;
 int call_dir;

  if ( user == 0 || strlen(user)<=0) return(VA_ILLEGAL_USERNAME);

  /* Michael Bowe 23rd August 2003 
   * should we do a vset_default_domain(domain) here?
   * This function is called by vdeluser.c which will ensure
   * domain is set. But what if this function is called from
   * somewhere else and is passed with a null domain?
   * Should we display en error (which is what will happen when
   * vget_assign runs below.
   *
   * Rick Widmer 4 May 2004
   * No don't use a default domain, if the domain is empty 
   * or bad, complain and exit.  It should not do any I/O, 
   * just return an error state.
   *
   * Also check the catchall account, if delete user is catchall
   * refuse to delete the user.  Error message should suggest
   * changing the catchall settings first.
   *
   */

  umask(VPOPMAIL_UMASK);

  lowerit(user);
  lowerit(domain);

  /* backup the dir where the vdeluser was run from */
  call_dir = open(".", O_RDONLY);

  /* lookup the location of this domain's directory */
  if ( vget_assign(domain, Dir, sizeof(Dir), &uid, &gid ) == NULL ) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  /* change into that directory */
  if ( chdir(Dir) != 0 ) {
    fchdir(call_dir); close(call_dir);
    return(VA_BAD_D_DIR);
  }

  /* see if the user exists in the authentication system */
  if ((mypw = vauth_getpw(user, domain)) == NULL) { 
    return(VA_USER_DOES_NOT_EXIST);
  }

  /* Make sure we are not the email address of the catchall account */
  if ( isCatchall( user, domain, Dir )) {
    return(VA_CANNOT_DELETE_CATCHALL);
    }


#ifdef ONCHANGE_SCRIPT
  /* tell other programs that data has changed */
  snprintf ( onchange_buf, MAX_BUFF, "%s@%s", user, domain );
  call_onchange ( "del_user" );
#endif

  /* del the user from the auth system */
  if (vauth_deluser( user, domain ) !=0 ) {
    fprintf (stderr, "Failed to delete user from auth backend\n");
    fchdir(call_dir); close(call_dir);
    return (-1);
  }

  /* write the information to backfill */
  backfill(user, domain, mypw->pw_dir, 2);
  dec_dir_control(domain, uid, gid);

  /* remove the user's directory from the file system 
   * and check for error
   */
  if ( vdelfiles(mypw->pw_dir) != 0 ) {
    fprintf(stderr, "could not remove %s\n", mypw->pw_dir);
    fchdir(call_dir); close(call_dir);
    return(VA_BAD_DIR);
  }

  /* go back to the callers directory */
  fchdir(call_dir); close(call_dir);
  return(VA_SUCCESS);
}

/************************************************************************/

/*
 * make all characters in a string be lower case
 */
void lowerit(char *instr )
{
 int size;

  if (instr==NULL) return;
  for(size=0;*instr!=0;++instr,++size ) {
    if (isupper((int)*instr)) *instr = tolower(*instr);
    
    /* Michael Bowe 23rd August 2003
     * this looks like a bit of a kludge...
     * how can we improve on it?
     */

    /* add alittle size protection */
    if ( size == 156 ) {
      *instr = 0;
      return;
    }
  } 
}

/************************************************************************/

int extract_domain(char *domain, char *update_line, int file_type )
{
int i,j;
char *parts[10];
char *t, *u;
char tmpbuf[MAX_BUFF];


//  fprintf( stderr, "extract_domain - line: %s\n", update_line );

  i=0;

  //  If users/assign - need to start at first character
  if( 1 == file_type ) {
    j=1;
  } else {
    j=0;
  }

  //  Chop our string off at the first :
  while( j < MAX_BUFF && 
         0 != update_line[j] && 
         ':' != update_line[j] ) {
     domain[i++] = update_line[j++];  
     }

  //  If users/assign - need to delete last character
  if( 1 == file_type ) {
    if (i > 0)
      domain[--i] = 0;
  } else {
    domain[i] = 0;
  }

//  fprintf( stderr, "extract_domain - result: %s\n", domain );


  //  Take the domain name string apart on '.'s.
  i=0;
  strcpy(tmpbuf, domain);

  t = strtok( tmpbuf, "." );
  while( t && i < 10 ) {
    parts[i++] = t;
    t = strtok( NULL, "." );
  }

  //  Get a look at the array before shuffle
//  for(j=0;j<i;j++) {
//    fprintf( stderr, "extract_domain - i: %d part: %s\n", j, parts[j] );
//  }
  if( i > 1 )  {
    //  Juggle the order of stuff in the domain name

    //  Save the last two terms
    t = parts[--i];
    u = parts[--i];

    //  Make room for two elements at the beginning of the name
    for(j=0;j<i;j++) {
      parts[j+2]=parts[j];
    }

    //  Put the parts you saved back in the beginning of the domain name
#ifdef SORTTLD
    parts[0] = t;
    parts[1] = u;
#else
    parts[0] = u;
    parts[1] = t;
#endif

    i=i+2;

    //  Clean out the domain variable
    memset(domain, 0, sizeof(domain));

    //  Get one last look at the array before assembling it
//    for(j=0;j<i;j++) {
//      fprintf( stderr, "extract_domain - modified i: %d part: %s\n", 
//               j, parts[j] );
//    }
  
    //  Copy the first term into the domain name
    strcpy(domain, parts[0] );

    //  Copy the rest of the terms into the domain name
    for(j=1;j<i;j++) {
      strncat( domain, ".", MAX_BUFF );
      strncat( domain, parts[j], MAX_BUFF );
    }
  
  }

//  fprintf( stderr, "extract_domain - final result: %s\n", domain );

return 0;
}


/************************************************************************/

int sort_check(const void *a, const void *b )
//int sort_check(const sortrec *a, const sortrec *b )
{
   
return( strncmp( ((sortrec *)(a))->key, ((sortrec *)(b))->key, MAX_BUFF));
//return( strncmp( a->key, b->key, MAX_BUFF));

}

/************************************************************************/

/*
 *
 * Note:  sortdata needs to be dynamically allocated based on the
 * number of entries specified in file_lines.
 *
 */

int sort_file(char *filename, int file_lines, int file_type )
{
 FILE *fs = NULL;
 FILE *fs1 = NULL;
#ifdef FILE_LOCKING
 int fd3 = 0;
#endif
 char tmpbuf1[MAX_BUFF];
 char tmpbuf2[MAX_BUFF];
 int i, count=0;
 char cur_domain[MAX_BUFF];

 sortrec *sortdata = NULL;

//  fprintf( stderr, "\n***************************************\n" 
//                   "sort_file: %s\n", filename );

#ifdef FILE_LOCKING
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.lock", filename);
  if ( (fd3 = open(tmpbuf1, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR)) < 0 ) {
    fprintf(stderr, "could not open lock file %s\n", tmpbuf1);
    return(VA_COULD_NOT_UPDATE_FILE);
  }

  if ( get_write_lock(fd3) < 0 ) return(-1);
#endif

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.%lu", filename, (long unsigned)getpid());
  fs1 = fopen(tmpbuf1, "w+");
  if ( fs1 == NULL ) {
#ifdef FILE_LOCKING
    unlock_lock(fd3, 0, SEEK_SET, 0);
    close(fd3);
#endif
    return(VA_COULD_NOT_UPDATE_FILE);
  }

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s", filename);
  if ( (fs = fopen(tmpbuf1, "r+")) == NULL ) {
    if ( (fs = fopen(tmpbuf1, "w+")) == NULL ) {
      fclose(fs1);
#ifdef FILE_LOCKING
      unlock_lock(fd3, 0, SEEK_SET, 0);
      close(fd3);
#endif
      return(VA_COULD_NOT_UPDATE_FILE);
    }
  }

  sortdata = malloc(  file_lines * sizeof( sortrec ));
  if (sortdata == NULL) {
    fclose(fs);
    fclose(fs1);
#ifdef FILE_LOCKING
    unlock_lock(fd3, 0, SEEK_SET, 0);
    close(fd3);
#endif
    return(VA_MEMORY_ALLOC_ERR);
  }

  while( fgets(tmpbuf1,sizeof(tmpbuf1),fs) != NULL ) {

    //  Trim \n off end of line.
    for(i=0;tmpbuf1[i]!=0;++i) {
      if (tmpbuf1[i]=='\n') {
        tmpbuf1[i]=0;
	break;
      }
    }

    //  Don't paint the last line of users/assign from the file
    if ( 1 == file_type && strncmp(tmpbuf1, ".", sizeof(tmpbuf1)) == 0 ) {
      continue;
    }

//    fprintf( stderr, "   Entry: %s\n", tmpbuf1 );

    // A new entry; is the allocated memory enough?
    if (count == file_lines) {
      fclose(fs);
      fclose(fs1);
#ifdef FILE_LOCKING
      unlock_lock(fd3, 0, SEEK_SET, 0);
      close(fd3);
#endif
      for (i = 0; i < count; i++) {
	free( sortdata[i].key );
	free( sortdata[i].value );
      }
      free( sortdata );
      return(VA_MEMORY_ALLOC_ERR);
    }

    extract_domain( cur_domain, tmpbuf1, file_type );

    sortdata[count].key = strdup( cur_domain );
    sortdata[count++].value = strdup( tmpbuf1 );
  }

//  fprintf( stderr, "\nSorting...\n\n" );
qsort(sortdata, count, sizeof( sortrec ), sort_check);
//  fprintf( stderr, "\nSort done.\n\n" );

  for(i=0;i<count;i++) {
//    fprintf( stderr, "   Entry: %s\n", sortdata[i].value );
    fprintf(fs1, "%s\n", sortdata[i].value);
  }   

  //  Now we print the period line to users/assign, if needed
  if( 1 == file_type ) {
    fprintf(fs1, ".\n");
  }

  fclose(fs);
  fclose(fs1);

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s", filename);
  snprintf(tmpbuf2, sizeof(tmpbuf2), "%s.%lu", filename, (long unsigned)getpid());

  rename(tmpbuf2, tmpbuf1);

#ifdef FILE_LOCKING
  unlock_lock(fd3, 0, SEEK_SET, 0);
  close(fd3);
#endif

  for (i = 0; i < count; i++) {
    free( sortdata[i].key );
    free( sortdata[i].value );
  }
  free( sortdata );

  return(0);
}

/************************************************************************/

int update_file(char *filename, char *update_line, int file_type )
{
 FILE *fs = NULL;
 FILE *fs1 = NULL;
#ifdef FILE_LOCKING
 int fd3 = 0;
#endif
 char tmpbuf1[MAX_BUFF];
 char tmpbuf2[MAX_BUFF];
 int i, x=0;
 char new_domain[MAX_BUFF];
 char cur_domain[MAX_BUFF];
 char prv_domain[MAX_BUFF];
 int hit=0, count=0, needsort = 0;

//  fprintf( stderr, "\n***************************************\n" 
//                   "update_file - line: %s\n", update_line );

  extract_domain( new_domain, update_line, file_type );
  strcpy(prv_domain, "");

#ifdef FILE_LOCKING
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.lock", filename);
  if ( (fd3 = open(tmpbuf1, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR)) < 0 ) {
    fprintf(stderr, "could not open lock file %s\n", tmpbuf1);
    return(VA_COULD_NOT_UPDATE_FILE);
  }

  if ( get_write_lock(fd3) < 0 ) return(-1);
#endif

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.%lu", filename, (long unsigned)getpid());
  fs1 = fopen(tmpbuf1, "w+");
  if ( fs1 == NULL ) {
#ifdef FILE_LOCKING
    unlock_lock(fd3, 0, SEEK_SET, 0);
    close(fd3);
    return(VA_COULD_NOT_UPDATE_FILE);
#endif
  }

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s", filename);
  if ( (fs = fopen(tmpbuf1, "r+")) == NULL ) {
    if ( (fs = fopen(tmpbuf1, "w+")) == NULL ) {
      fclose(fs1);
#ifdef FILE_LOCKING
      close(fd3);
      unlock_lock(fd3, 0, SEEK_SET, 0);
#endif
      return(VA_COULD_NOT_UPDATE_FILE);
    }
  }

  while( fgets(tmpbuf1,sizeof(tmpbuf1),fs) != NULL ) {
    count++;

    //  Trim \n off end of line.
    for(i=0;tmpbuf1[i]!=0;++i) {
      if (tmpbuf1[i]=='\n') {
        tmpbuf1[i]=0;
	break;
      }
    }

    //  Don't paint the last line of users/assign from the file
    if ( 1 == file_type && strncmp(tmpbuf1, ".", sizeof(tmpbuf1)) == 0 ) {
      continue;
    }

//    fprintf( stderr, "   Entry: %s\n", tmpbuf1 );

    extract_domain( cur_domain, tmpbuf1, file_type );
   
    if( 0 == hit && ( x=strncmp(cur_domain, new_domain, MAX_BUFF)) > 0  ) {
//      fprintf( stderr, "HIT!\n" );
      hit=1;
      fprintf(fs1, "%s\n", update_line);
    }

//    fprintf( stderr, "UpdateUsers - cur_domain: %s new_domain: %s x: %i\n", 
//             cur_domain, new_domain, x );

    if( ( x=strncmp(prv_domain, cur_domain, MAX_BUFF)) > 0  ) {
//      fprintf( stderr, "%s entry is out of order: %s  -- will sort file\n", filename, cur_domain );
      needsort=1;
    }

//    fprintf( stderr, "Chk order - prv: %s cur: %s x: %i\n", 
//             prv_domain, cur_domain, x );

    strcpy(prv_domain, cur_domain);

    fprintf(fs1, "%s\n", tmpbuf1);
  }

  if( 0 == hit ) {
//    fprintf( stderr, "Add at end\n" );
    fprintf(fs1, "%s\n", update_line);
    }

  //  Now we print the period line to users/assign, if needed
  if( 1 == file_type ) {
    fprintf(fs1, ".\n");
  }

  fclose(fs);
  fclose(fs1);

  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s", filename);
  snprintf(tmpbuf2, sizeof(tmpbuf2), "%s.%lu", filename, (long unsigned)getpid());

  rename(tmpbuf2, tmpbuf1);

#ifdef FILE_LOCKING
  unlock_lock(fd3, 0, SEEK_SET, 0);
  close(fd3);
#endif

  count ++;   //  increment count because of the entry we added.
  if( needsort ) {
    fprintf( stderr, "NOTICE: Out of order entries found in %s\n   Sorting...\n\n", filename );
    sort_file(filename, count, file_type);
    }

  return(0);
}

/************************************************************************/

/*
 * Update a users quota
 */
int vsetuserquota( char *username, char *domain, char *quota )
{
 struct vqpasswd *mypw;
 char *formattedquota;
 int ret;

  if ( strlen(username) > MAX_PW_NAME ) return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR  
  if ( strlen(username) == 1 ) return(VA_ILLEGAL_USERNAME);
#endif  
  if ( strlen(domain) > MAX_PW_DOMAIN ) return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(quota) > MAX_PW_QUOTA )    return(VA_QUOTA_TOO_LONG);

  lowerit(username);
  lowerit(domain);

  mypw = vauth_getpw( username, domain );
  if (mypw == NULL) return VA_USER_DOES_NOT_EXIST;

  /* correctly format the quota string,
   * and then store the quota into the auth backend
   */
  formattedquota = format_maildirquota(quota);
  ret = vauth_setquota( username, domain, formattedquota);
  if (ret != VA_SUCCESS ) return(ret);

  update_maildirsize(domain, mypw->pw_dir, formattedquota);
  return(0);
}

/************************************************************************/

/*
 * count the lines in /var/qmail/control/rcpthosts
 */
int count_rcpthosts()
{
 char tmpstr1[MAX_BUFF];
 FILE *fs;
 int count;

  snprintf(tmpstr1, sizeof(tmpstr1), "%s/control/rcpthosts", QMAILDIR);
  fs = fopen(tmpstr1, "r");
  if ( fs == NULL ) return(0);

  count = 0;
  while( fgets(tmpstr1, sizeof(tmpstr1), fs) != NULL ) ++count;

  fclose(fs);
  return(count);

}

/************************************************************************/

/*
 * compile the morercpthosts file using qmail-newmrh program
 */
int compile_morercpthosts()
{
 int pid;

  pid=vfork();
  if ( pid==0){
    execl(QMAILNEWMRH,"qmail-newmrh", NULL);
    exit(127);
  } else {
    waitpid(pid,&pid,0);
  }
  return(0);
}

/************************************************************************/

/*
 * fill out a passwd structure from then next
 * line in a file 
 */ 
struct vqpasswd *vgetent(FILE *pw)
{
    static struct vqpasswd pwent;
    static char line[MAX_BUFF];
    int i=0,j=0;
    char *tmpstr;
    char *tmpstr1;

    if (fgets(line,sizeof(line),pw) == NULL) return NULL;

    for (i=0; line[i] != 0; i++) if (line[i] == ':') j++;
    if (j < 6) return NULL;

    tmpstr = line;
    pwent.pw_name   = line;
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;

    pwent.pw_passwd = tmpstr;
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;
 
    tmpstr1 = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;
    pwent.pw_uid = atoi(tmpstr1); 

    tmpstr1 = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;
    pwent.pw_gid = atoi(tmpstr1); 

    pwent.pw_gecos  = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    *tmpstr = 0; ++tmpstr;

    pwent.pw_dir    = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':') ++tmpstr;
    if (*tmpstr) { *tmpstr = 0; ++tmpstr; }

    pwent.pw_shell  = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!=':' && *tmpstr!='\n') ++tmpstr;
    if (*tmpstr) { *tmpstr = 0; ++tmpstr; }

#ifdef CLEAR_PASS
    pwent.pw_clear_passwd  = tmpstr; 
    while (*tmpstr!=0 && *tmpstr!='\n') ++tmpstr;
    if (*tmpstr) { *tmpstr = 0; ++tmpstr; }
#endif

    return &pwent;
}

/************************************************************************/

/*
 * figure out where to put the user and
 * make the directories if needed
 *
 * if successfull, return a pointer to the user hash
 * on error return NULL
 */
char *make_user_dir(char *username, char *domain, uid_t uid, gid_t gid)
{
 char *user_hash;
 struct vqpasswd *mypw;
 int call_dir;
 char domain_dir[MAX_BUFF];
 const char *dirnames[] = {"Maildir", "Maildir/new", "Maildir/cur", 
	"Maildir/tmp"};
 int i;

  verrori = 0;
  /* record the dir where the command was run from */
  call_dir = open(".", O_RDONLY);

  /* retrieve the dir that stores this domain */
  if (vget_assign(domain, domain_dir, sizeof(domain_dir), NULL, NULL) == NULL) {
    fprintf(stderr, "Error. vget_assign() failed for domain : %s",domain); 
    return(NULL);
  }

  /* go to the dir for our chosen domain */
  chdir(domain_dir); 

  user_hash="";
#ifdef USERS_BIG_DIR
  /* go into a user hash dir if required */
  if (!(user_hash = backfill(username, domain, 0, 1)))
  {
  	open_big_dir(domain, uid, gid);
  	user_hash = next_big_dir(uid, gid);
  	close_big_dir(domain, uid, gid);
  } else
	r_mkdir(user_hash, uid, gid);
  chdir(user_hash);
#endif
  /* check the length of the dir path to make sure it is not too 
     long to save back to the auth backend */
  if ((strlen(domain_dir)+strlen(user_hash)+strlen(username)) > MAX_PW_DIR) {
    fprintf (stderr, "Error. Path exceeds maximum permitted length\n");
    fchdir(call_dir); close(call_dir);
    return (NULL);
  }

  /* create the users dir, including all the Maildir structure */ 
  if ( mkdir(username, VPOPMAIL_DIR_MODE) != 0 ) {
    /* need to add some code to remove the hashed dirs we created above... */
    verrori = VA_EXIST_U_DIR;
    fchdir(call_dir); close(call_dir);
    return(NULL);
  }

  if ( chdir(username) != 0 ) {
    /* back out of changes made above */
    chdir(domain_dir); chdir(user_hash); vdelfiles(username);
    fchdir(call_dir); close(call_dir);
    fprintf(stderr, "make_user_dir: error 2\n");
    return(NULL);
  }

  for (i = 0; i < (int)(sizeof(dirnames)/sizeof(dirnames[0])); i++) {
    if (mkdir(dirnames[i],VPOPMAIL_DIR_MODE) == -1){ 
      fprintf(stderr, "make_user_dir: failed on %s\n", dirnames[i]);
      /* back out of changes made above */
      chdir("..");
      vdelfiles(username);
      fchdir(call_dir); close(call_dir);
      return(NULL);
    }
  }

  /* set permissions on the user's dir */
  r_chown(".", uid, gid);

  /* see if the user already exists in the auth backend */
  mypw = vauth_getpw( username, domain);
  if ( mypw != NULL ) { 

    /* user does exist in the auth backend, so fill in the dir field */
    mypw->pw_dir = malloc(MAX_PW_DIR+1);
    if ( strlen(user_hash) > 0 ) {
      snprintf(mypw->pw_dir, MAX_PW_DIR+1, "%s/%s/%s", domain_dir, user_hash, username);
    } else {
      snprintf(mypw->pw_dir, MAX_PW_DIR+1, "%s/%s", domain_dir, username);
    }
    /* save these values to the auth backend */
    vauth_setpw( mypw, domain );

#ifdef SQWEBMAIL_PASS
    vsqwebmail_pass( mypw->pw_dir, mypw->pw_passwd, uid, gid);
#endif
    free (mypw->pw_dir);
  }

  fchdir(call_dir); close(call_dir);
  return(user_hash);
}

/************************************************************************/

int r_mkdir(char *path, uid_t uid, gid_t gid )
{
 char tmpbuf[MAX_BUFF];
 int err;
 int i;
 struct stat sb;

  if (*path == '\0') return 0;

  for(i=0; ;++i){
    if ( (i > 0) && ((path[i] == '/') || (path[i] == '\0')) ) {
      tmpbuf[i] = 0;
      err = mkdir(tmpbuf,VPOPMAIL_DIR_MODE);
      if (err == 0)
        chown(tmpbuf, uid, gid);
      else if (errno != EEXIST) {
        /* Note that if tmpbuf is a file, we'll catch the error on the
         * next directory creation (ENOTDIR) or when we verify that the
         * directory exists and is a directory at the end of the function.
         */
        warn ("Unable to create directory %s: ", tmpbuf);
        return -1;
      }
      if (path[i] == '\0') break;
    }
    tmpbuf[i] = path[i];
  }
  if (stat (path, &sb) != 0) {
    warn ("Couldn't stat %s: ", path);
    return -1;
  } else if (! S_ISDIR(sb.st_mode)) {
    fprintf (stderr, "Error: %s is not a directory.\n", path);
    return -1;
  }
  return 0;
}

/************************************************************************/

#ifdef APOP
char *dec2hex(unsigned char *digest)
{
  static char ascii[33];
  char *hex="0123456789abcdef";
  int i,j,k;
  memset(ascii,0,sizeof(ascii));
  for (i=0; i < 16; i++) {
    j = digest[i]/16;
    k = digest[i]%16;
    ascii[i*2] = hex[j];
    ascii[(i*2)+1] = hex[k];
  }

  return ascii;
}
#endif

/************************************************************************/

/* Function used by qmailadmin to auth users */

struct vqpasswd *vauth_user(char *user, char *domain, char* password, char *apop)
 {
  struct vqpasswd *mypw;
 
   if ( password == NULL ) return(NULL);
   mypw = vauth_getpw(user, domain);
   if ( mypw == NULL ) return(NULL);
   if ( vauth_crypt(user, domain, password, mypw) != 0 ) return(NULL);
 
   return(mypw);
 }

/************************************************************************/

/*
 * default_domain()
 *   returns a pointer to a string, containing
 *   the default domain (or blank if not set).  Loads from
 *   ~vpopmail/etc/defaultdomain.  Only loads once per program
 *   execution.
 */
char *default_domain()
{
   static int init = 0;
   static char d[MAX_PW_DOMAIN+1];
   char path[MAX_BUFF];
   int dlen;
   FILE *fs;

   if (!init) {
     init++;
     d[0] = '\0';  /* make sure d is empty in case file doesn't exist */
     snprintf (path, sizeof(path), "%s/etc/defaultdomain", VPOPMAILDIR);

     fs = fopen (path, "r");
     if (fs != NULL) {
       fgets (d, sizeof(d), fs);
       fclose (fs);
       dlen = strlen(d) - 1;
       if (d[dlen] == '\n') { d[dlen] = '\0'; }
     }
   }
   return d;
} 

/************************************************************************/

/*
 * If domain is blank, set it to the VPOPMAIL_DOMAIN environment
 * variable, an ip alias domain, or the default domain.
 */
void vset_default_domain( char *domain ) 
{
 char *tmpstr, *cp;
#ifdef IP_ALIAS_DOMAINS
 char host[MAX_BUFF];
#endif

  if (domain != NULL) {
    if (strlen(domain)>0) {
      /* domain isnt blank, so dont try to set it */
      return;
    }
  }

  /* domain is blank, so now try various lookups to set it */

  tmpstr = getenv("VPOPMAIL_DOMAIN");
  if ( tmpstr != NULL) {

    /* As a security precaution, remove all but good chars */
    for (cp = tmpstr; *(cp += strspn(cp, ok_env_chars)); /* */) {*cp='_';}

    /* Michael Bowe 14th August 2003
     * How can we prevent possible buffer overflows here
     * For the moment, stick with a conservative size of MAX_PW_DOMAIN
     * (plus 1 for the NULL)
     */
    snprintf(domain, MAX_PW_DOMAIN+1, "%s", tmpstr);
    return;
  }

#ifdef IP_ALIAS_DOMAINS
  tmpstr = getenv("TCPLOCALIP");

  /* courier-imap uses IPv6 */
  if ( tmpstr != NULL ) {

    /* As a security precaution, remove all but good chars */
    for (cp = tmpstr; *(cp += strspn(cp, ok_env_chars)); ) {*cp='_';}

    /* Michael Bowe 14th August 2003
     * Mmmm Yuk below. What if TCPLOCALIP=":\0"
     * Buffer overflow.
     * Need to perhaps at least check strlen of tmpstr
     */
    if ( tmpstr[0] == ':') {
      tmpstr +=2;
      while(*tmpstr!=':') ++tmpstr;
      ++tmpstr;
    }
  }

  memset(host,0,sizeof(host));
  /* take the ip address that the connection was made to
   * and go and look this up in our vip map
   * and then store the domain into the host var 
   */
  if ( vget_ip_map(tmpstr,host,sizeof(host))==0 && !host_in_locals(host)){
    if ( strlen(host) > 0 ) {
      /* Michael Bowe 14th August 2003
       * How can we prevent possible buffer overflows here
       * For the moment, stick with a conservative size of MAX_PW_DOMAIN
       * (plus 1 for the NULL)
       */
      snprintf(domain, MAX_PW_DOMAIN+1, "%s", host);
    }
    return;
  }
#endif /* IP_ALIAS_DOMAINS */

  /* Michael Bowe 14th August 2003
   * How can we prevent possible buffer overflows here
   * For the moment, stick with a conservative size of MAX_PW_DOMAIN
   * (plus 1 for the NULL)
   */
  snprintf(domain, MAX_PW_DOMAIN+1, "%s", DEFAULT_DOMAIN);
}

/************************************************************************/

#ifdef IP_ALIAS_DOMAINS
/* look to see if the nominated domain is is locals file
 * return 1 if there is a match
 * return 0 if there is no match
 */
int host_in_locals(char *domain)
{
 int i;
 char tmpbuf[MAX_BUFF];
 FILE *fs;

  snprintf(tmpbuf, sizeof(tmpbuf), "%s/control/locals", QMAILDIR);
  if ((fs = fopen(tmpbuf,"r")) == NULL) {
    return(0);
  }

  while( fgets(tmpbuf,sizeof(tmpbuf),fs) != NULL ) {
    /* usually any newlines into nulls */
    for(i=0;tmpbuf[i]!=0;++i) if (tmpbuf[i]=='\n') { tmpbuf[i]=0; break; }
    /* Michael Bowe 14th August 2003
     * What happens if domain isnt null terminated?
     */
    if (( strcmp( domain, tmpbuf)) == 0 ) {
      /* we found a match */
      fclose(fs);
      return(1);
    }

    /* always match with localhost */
    if ( strcmp(domain, "localhost") == 0 && 
       strstr(domain,"localhost") != NULL ) {
      fclose(fs);
      return(1);
    }
  }

  fclose(fs);
  return(0);
}
#endif

/************************************************************************/

/* Convert error flag to text */
char *verror(int va_err )
{
  switch(va_err) {
   case VA_SUCCESS:
    return("Success");
   case VA_ILLEGAL_USERNAME:
    return("Illegal username");
   case VA_USERNAME_EXISTS:
    return("Username exists");
   case VA_BAD_DIR:
    return("Unable to chdir to vpopmail directory");
   case VA_BAD_U_DIR:
    return("Unable to chdir to vpopmail/users directory");
   case VA_BAD_D_DIR:
    return("Unable to chdir to vpopmail/" DOMAINS_DIR " directory");
   case VA_BAD_V_DIR:
    return("Unable to chdir to vpopmail/" DOMAINS_DIR "/domain directory");
   case VA_EXIST_U_DIR:
    return("User's directory already exists");
   case VA_BAD_U_DIR2:
    return("Unable to chdir to user's directory");
   case VA_SUBDIR_CREATION:
    return("Creation of user's subdirectories failed");
   case VA_USER_DOES_NOT_EXIST:
    return("User does not exist");
   case VA_DOMAIN_DOES_NOT_EXIST:
    return("Domain does not exist");
   case VA_INVALID_DOMAIN_NAME:
    return("Invalid domain name");
   case VA_DOMAIN_ALREADY_EXISTS:
    return("Domain already exists");
   case VA_COULD_NOT_MAKE_DOMAIN_DIR:
    return("Could not make domain dir");
   case VA_COULD_NOT_OPEN_QMAIL_DEFAULT:
    return("Could not open qmail default");
   case VA_CAN_NOT_MAKE_DOMAINS_DIR:
    return("Can not make " DOMAINS_DIR " directory");
   case VA_COULD_NOT_UPDATE_FILE:
    return("Could not update file");
   case VA_CRYPT_FAILED:
    return("Crypt failed");
   case VA_COULD_NOT_OPEN_DOT_QMAIL:
    return("Could not open dot qmail file");
   case VA_BAD_CHAR:
    return("bad character");
   case VA_BAD_UID:
    return("running as invalid uid");
   case VA_NO_AUTH_CONNECTION:
    return("no authentication database connection");
   case VA_MEMORY_ALLOC_ERR:
    return("memory allocation error");
   case VA_USER_NAME_TOO_LONG:
    return("user name too long");
   case VA_DOMAIN_NAME_TOO_LONG:
    return("domain name too long");
   case VA_PASSWD_TOO_LONG:
    return("password too long");
   case VA_GECOS_TOO_LONG:
    return("gecos too long");
   case VA_QUOTA_TOO_LONG:
    return("quota too long");
   case VA_DIR_TOO_LONG:
    return("dir too long");
   case VA_CLEAR_PASSWD_TOO_LONG:
    return("clear password too long");
   case VA_ALIAS_LINE_TOO_LONG:
    return("alias line too long");
   case VA_NULL_POINTER:
    return("null pointer");
   case VA_INVALID_EMAIL_CHAR:
    return("invalid email character");
   case VA_PARSE_ERROR:
    return("parsing database configuration file");
   case VA_PARSE_ERROR01:
    return("parsing database configuration file - update server");
   case VA_PARSE_ERROR02:
    return("parsing database configuration file - update port");
   case VA_PARSE_ERROR03:
    return("parsing database configuration file - update user");
   case VA_PARSE_ERROR04:
    return("parsing database configuration file - update password");
   case VA_PARSE_ERROR05:
    return("parsing database configuration file - update database");
   case VA_PARSE_ERROR06:
    return("parsing database configuration file - readonly server");
   case VA_PARSE_ERROR07:
    return("parsing database configuration file - readonly port");
   case VA_PARSE_ERROR08:
    return("parsing database configuration file - readonly user");
   case VA_PARSE_ERROR09:
    return("parsing database configuration file - readonly password");
   case VA_PARSE_ERROR10:
    return("parsing database configuration file - readonly database");
   case VA_CANNOT_READ_LIMITS:
    return("can't read domain limits");
   case VA_CANNOT_READ_ASSIGN:
    return("can't read users/assign file");
   case VA_CANNOT_DELETE_CATCHALL:
    return("can't delete catchall account");
   default:
    return("Unknown error");
  }
}

/************************************************************************/


void vsqlerror( FILE *f, char *comment )
{
    fprintf( f, "Error - %s. %s\n", verror( verrori ), comment );
/*
    if( NULL != sqlerr && strlen(sqlerr) > 0 ) {
        fprintf( f,"%s",sqlerr);
    }

    if( NULL != last_query && strlen( last_query ) > 0 ) {
        fprintf( f,"%s", last_query);
    }
*/
}


/************************************************************************/

int vexiterror( FILE *f, char *comment )
{

    vsqlerror( f, comment );
    vclose();
    exit(verrori);
}

/************************************************************************/

/* Michael Bowe 21st Aug 2003
 * This function doesnt appear to be used by vpopmail or qmailadmin 
 * Consider it for removal perhaps
 */
/* Add an entry to a domain/.qmail-alias file */
int vadddotqmail( char *alias, char *domain,... ) 
{
 struct vqpasswd *mypw = NULL; 
 FILE *fs;
 va_list args;
 char *email;
 char Dir[MAX_BUFF];
 uid_t uid;
 gid_t gid;
 char tmpbuf[MAX_BUFF];

  /* extract the details for the domain (Dir, uid, gid) */
  if ( vget_assign(domain, Dir, sizeof(Dir), &uid, &gid ) == NULL) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  /* open the .qmail-alias file for writing */
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/.qmail-%s", Dir, alias);
  if ((fs=fopen(tmpbuf, "w")) == NULL) return(VA_COULD_NOT_OPEN_DOT_QMAIL);

  va_start(args,domain);
  while ( (email=va_arg(args, char *)) != NULL ) {
    /* are we dealing with an email address? */
    if ( strstr(email, "@") == NULL ) {
      /* not an email address */
      /* get passwd entry for this user */
      mypw = vauth_getpw( email, domain );
      if ( mypw == NULL ) return(VA_USER_DOES_NOT_EXIST);
      /* write out the appropriate maildir entry for this user */
      fprintf(fs, "%s/Maildir/\n", mypw->pw_dir);
    } else {
      /* yes, we have an email address, so write it out */
      fprintf(fs, "%s\n", email);
    }
  }
  fclose(fs);

  /* setup the permission of the .qmail-alias file */
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/.qmail-%s", Dir, alias);
  chown(tmpbuf,uid,gid);

  va_end(args);
  return(VA_SUCCESS);
}

/************************************************************************/

/* Michael Bowe 21st Aug 2003
 * This function doesnt appear to be used by vpopmail or qmailadmin 
 * Consider it for removal perhaps
 */ 
/* delete a domain/qmail-alias file */
int vdeldotqmail( char *alias, char *domain )
{
 char Dir[MAX_BUFF];
 uid_t uid;
 gid_t gid;
 char tmpbuf[MAX_BUFF];

  if ( vget_assign(domain, Dir, sizeof(Dir), &uid, &gid ) == NULL) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  snprintf(tmpbuf, sizeof(tmpbuf), "%s/.qmail-%s", Dir, alias);
  if ( unlink(tmpbuf) < 0 ) return(VA_COULD_NOT_OPEN_DOT_QMAIL);
  return(VA_SUCCESS);
}

/************************************************************************/

/*
 * Given the domain name:
 * 
 *   get dir, uid, gid from the users/cdb file (if they are not passed as NULL)
 *
 *   If domain is an alias domain, then domain gets updated to be the real domain
 *   
 * Function will return the domain directory on success
 * or return NULL if the domain does not exist.
 * 
 * This function caches last lookup in memory to increase speed
 */
char *vget_assign(char *domain, char *dir, int dir_len, uid_t *uid, gid_t *gid)
{
 FILE *fs;
 int dlen;
 int i;
 char *ptr;

 static char *in_domain = NULL;
 static int in_domain_size = 0;
 static char *in_dir = NULL;
 static int in_dir_size = 0;

 static uid_t in_uid = -1;
 static gid_t in_gid = -1;

 char cdb_key[MAX_BUFF]; 
 char cdb_file[MAX_BUFF];
 char *cdb_buf;

  /* cant lookup a null domain! -- but it does clear the cache */
  if ( domain == NULL || *domain == 0) {
    if ( in_domain != NULL ) {
      free(in_domain);
      in_domain = NULL;
    }
    return(NULL);
  }

  /* if domain matches last lookup, use cached values */
  lowerit(domain);
  if ( in_domain_size != 0 && in_domain != NULL 
    && in_dir != NULL && strcmp( in_domain, domain )==0 ) {

    /* return the vars, if the user has asked for them */
    if ( uid!=NULL ) *uid = in_uid;
    if ( gid!=NULL ) *gid = in_gid;
    if ( dir!=NULL ) snprintf(dir, dir_len, "%s", in_dir);

    /* cached lookup complete, exit out now */
    return(in_dir);
  }

  /* this is a new lookup, free memory from last lookup if necc. */
  if ( in_domain != NULL ) {
    free(in_domain);
    in_domain = NULL;
  }
  if ( in_dir != NULL ) {
    free(in_dir);
    in_dir = NULL;
  }

  /* build up a search string so we can search the cdb file */
  snprintf(cdb_key, sizeof(cdb_key), "!%s-", domain);
  
  /* work out the location of the cdb file */
  snprintf(cdb_file, sizeof(cdb_file), "%s/users/cdb", QMAILDIR);

  /* try to open the cdb file */
  if ( (fs = fopen(cdb_file, "r")) == 0 ) {
    return(NULL);
  }

  /* search the cdb file for our requested domain */
  i = cdb_seek(fileno(fs), cdb_key, strlen(cdb_key), &dlen);
  in_uid = -1;
  in_gid = -1;

  if ( i == 1 ) { 
    /* we found a matching record in the cdb file
     * so next create a storage buffer, and then read it in
     */
    cdb_buf = malloc(dlen);
    i = fread(cdb_buf, sizeof(char), dlen, fs);

    /* format of cdb_buf is :
     * realdomain.com\0uid\0gid\0path\0
     */

    /* get the real domain */
    ptr = cdb_buf;                      /* point to start of cdb_buf (ie realdomain) */
    in_domain_size = strlen(ptr)+1;     /* how long is the domain name? cache the length */
    in_domain = malloc(in_domain_size); /* create storage space for domain cache */
    snprintf(in_domain, in_domain_size, "%s", ptr); /* suck out the domain, store into cache */

    /* get the uid */
    while( *ptr != 0 ) ++ptr;           /* advance pointer past the realdomain */
    ++ptr;                              /* skip over the null */
    in_uid = atoi(ptr);                 /* suck out the uid */
    if ( uid!=NULL) *uid = in_uid;      /* if the user requested the uid, give it to them */

    /* get the gid */
    while( *ptr != 0 ) ++ptr;           /* skip over the uid */
    ++ptr;                              /* skip over the null */
    in_gid = atoi(ptr);                 /* suck out the gid */
    if ( gid!=NULL) *gid = in_gid;      /* if the user requested the gid, give it to them */

    /* get the domain directory */
    while( *ptr != 0 ) ++ptr;           /* skip over the gid */
    ++ptr;                              /* skip over the null */
    if ( dir!=NULL ) strncpy( dir, ptr, dir_len); /* if user requested dir, give it */
    in_dir_size = strlen(ptr)+1;        /* how long is dir? cache the length */
    in_dir = malloc(in_dir_size);       /* create storage space for dir cache */
    snprintf(in_dir, in_dir_size, "%s", ptr); /* suck out the dir, and store it in cache */

    free(cdb_buf);

    /* when vget_assign is called with the domain parameter set as an alias domain,
     * it is meant to replace this alias domain with the real domain
     *
     * in_domain contains the real domain, so do this replacement now.
     *
     * Michael Bowe 21st Aug 2003. Need to watch out for buffer overflows here.
     * We dont know what size domain is, so stick with a conservative limit of MAX_PW_DOMAIN
     * (plus 1 for the NULL)
     * Not sure if this is our best option? the pw entry shouldnt contain any dirs larger
     * than this.
     */
    snprintf(domain, MAX_PW_DOMAIN+1, "%s", in_domain); 

  } else {
    free(in_domain);
    in_domain = NULL;
    in_domain_size = 0;
  }
  fclose(fs);
  return(in_dir);
}

/************************************************************************/

/* THE USE OF THIS FUNCTION IS DEPRECIATED.
 *
 * None of the vpopmail code uses this function,
 * but it has been left in the source for the time being,
 * to ensure backwards compatibility with some of the popular
 * patches such as Tonix's chkusr
 *
 * This function is scheduled to be removed at a future date 
 *
 * You can obtain same functionality by calling
 *   vget_assign (domain, NULL, 0, NULL, NULL)
 * 
 */

int vget_real_domain (char *domain, int len)
{
  if (domain == NULL) return (0);
  vget_assign (domain, NULL, 0, NULL, NULL);
  return (0);
}

/************************************************************************/

/* This function is typically used to create a user's maildir
 * on-the-fly should it not exist
 * Basically, a dir for the user has been been allocated/stored
 * in the auth backend, but it does not yet exist in the filesystem
 * so we are going to make the dirs now so that mail can be delivered
 *
 * Main use is to call it from vchkpw.c and vdelivermail.c
 * in this format :
 *  vmake_maildir(TheDomain, vpw->pw_dir)
 */

int vmake_maildir(char *domain, char *dir )
{
 char tmpbuf[MAX_BUFF];
 int call_dir;
 uid_t uid;
 gid_t gid;
 char *tmpstr;
 int i;

  /* record which dir the command was launched from */
  call_dir = open(".", O_RDONLY);

  /* set the mask for file creation */
  umask(VPOPMAIL_UMASK);
 
  /* check if domain exists.
   * if domain exists, store the dir into tmpbuf, and store uid and gid
   */
  if ( vget_assign(domain, tmpbuf, sizeof(tmpbuf), &uid, &gid ) == NULL ) {
    close(call_dir);
    return( VA_DOMAIN_DOES_NOT_EXIST );
  }

  /* so, we should have some variables like this now :
   *   dir:    /home/vpopmail/domains/[x]/somedomain.com/[x]/someuser
   *   tmpbuf: /home/vpopmail/domains/[x]/somedomain.com
   */

  /* walk to where the sub directory starts */
  for(i=0,tmpstr=dir;tmpbuf[i]==*tmpstr&&tmpbuf[i]!=0&&*dir!=0;++i,++tmpstr);

  /* walk past trailing slash */
  while ( *tmpstr == '/'  ) ++tmpstr;

  /* tmpstr should now contain : [x]/someuser */

  /* so 1st cd into the domain dir (which should already exist) */
  if ( chdir(tmpbuf) == -1 ) { fchdir(call_dir); close(call_dir); return( VA_BAD_DIR); }

  /* Next, create the user's dir
   * ie [x]/someuser
   */
  r_mkdir(tmpstr, uid, gid);

  /* we should now be able to cd into the user's dir */
  if ( chdir(dir) != 0 ) { fchdir(call_dir); close(call_dir); return(-1); }

  /* now create the Maildir */
  if (mkdir("Maildir",VPOPMAIL_DIR_MODE) == -1) { fchdir(call_dir); close(call_dir); return(-1); }
  if (chdir("Maildir") == -1) { fchdir(call_dir); close(call_dir); return(-1); }
  if (mkdir("cur",VPOPMAIL_DIR_MODE) == -1) { fchdir(call_dir); close(call_dir); return(-1); }
  if (mkdir("new",VPOPMAIL_DIR_MODE) == -1) { fchdir(call_dir); close(call_dir); return(-1); }
  if (mkdir("tmp",VPOPMAIL_DIR_MODE) == -1) { fchdir(call_dir); close(call_dir); return(-1); }

  /* set permissions on the user's dir */
  chdir(dir);
  r_chown(dir, uid, gid);

  /* change back to the orignal dir */
  fchdir(call_dir); close(call_dir);
  return(0);
}

/************************************************************************/

/* This function allows us to store an crypted password in the user's maildir
 * for use by sqwebmail
 */
int vsqwebmail_pass( char *dir, char *crypted, uid_t uid, gid_t gid )
{
 FILE *fs;
 char tmpbuf1[MAX_BUFF];

  if ( dir == NULL ) return(VA_SUCCESS);
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s/Maildir/sqwebmail-pass", dir);
  if ( (fs = fopen(tmpbuf1, "w")) == NULL ) {
    return(VA_SQWEBMAIL_PASS_FAIL);
  }
  fprintf(fs, "\t%s\n", crypted);
  fclose(fs);
  chown(tmpbuf1,uid,gid);
  return(0);
}

/************************************************************************/

#ifdef POP_AUTH_OPEN_RELAY 
/* This function is used to grab the user's ip address
 * and add it to the ip's that are allowed to relay mail
 * through this server.
 *
 * For mysql backend, the ip is added to the relay table
 * For cdb backend, the ip is added to the ~vpopmail/etc/open-smtp file
 * 
 * Then the update_rules() function is called which 
 * combines the tcp.smtp rules with the relay-table/open-smtp rules
 * to build a new tcp.smtp.cdb file for tcpserver to use
 *
 * This function is called after a successful pop-auth by vchkpw,
 * (assuming that roaming users are enabled)
 */
int open_smtp_relay()
{

#ifdef USE_SQL

int result;

//  NOTE: vopen_smtp_relay returns <0 on error 0 on duplicate 1 added
//  check for failure.

  /* store the user's ip address into the sql relay table */
  if (( result = vopen_smtp_relay()) < 0 ) {   //   database error
      vsqlerror( stderr, "Error. vopen_smtp_relay failed" );
      return (verrori);
  } else if ( result == 1 ) {
    /* generate a new tcp.smtp.cdb file */
    if (update_rules()) {
      vsqlerror( stderr, "Error. vupdate_rules failed" );
      return (verrori);
    }
  }
#else
/* if we arent using SQL backend, then we have to maintain the
 * info via the tcp.smtp file
 */
 FILE *fs_cur_file;
 FILE *fs_tmp_file;
#ifdef FILE_LOCKING
 int fd_lok_file;
#endif /* FILE_LOCKING */
 char *ipaddr;
 char *tmpstr;
 time_t mytime;
 int rebuild_cdb = 1;
 char open_smtp_tmp_filename[MAX_BUFF];
 char tmpbuf1[MAX_BUFF];
 char tmpbuf2[MAX_BUFF];

  mytime = time(NULL);

  ipaddr = get_remote_ip();
  if ( ipaddr == NULL ) {
      return 0;
  }

#ifdef FILE_LOCKING
  /* by default the OPEN_SMTP_LOK_FILE is ~vpopmail/etc/open-smtp.lock */
  if ( (fd_lok_file=open(OPEN_SMTP_LOK_FILE, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR))<0) return(-1);
  get_write_lock(fd_lok_file);
#endif /* FILE_LOCKING */

  /* by default the OPEN_SMTP_CUR_FILE is ~vpopmail/etc/open-smtp */
  if ( (fs_cur_file = fopen(OPEN_SMTP_CUR_FILE, "r+")) == NULL ) {
    /* open for read/write failed, so try creating it from scratch */
    if ( (fs_cur_file = fopen(OPEN_SMTP_CUR_FILE, "w+")) == NULL ) {
#ifdef FILE_LOCKING
      unlock_lock(fd_lok_file, 0, SEEK_SET, 0);
      close(fd_lok_file);
#endif /* FILE_LOCKING */
      /* failed trying to access the open-smtp file */
      return(-1);
    }
  }

  /* by default the OPEN_SMTP_TMP_FILE is ~vpopmail/etc/open-smtp.tmp.pid */
  snprintf(open_smtp_tmp_filename, sizeof(open_smtp_tmp_filename),
           "%s.%lu", OPEN_SMTP_TMP_FILE, (long unsigned)getpid());
  /* create the tmp file */
  fs_tmp_file = fopen(open_smtp_tmp_filename, "w+");

  if ( fs_tmp_file == NULL ) {
#ifdef FILE_LOCKING
    unlock_lock(fd_lok_file, 0, SEEK_SET, 0);
    close(fd_lok_file);
#endif /* FILE_LOCKING */
    /* failed to create the tmp file */
    return(-1);
  }

  /* read in the current open-smtp file */
  while ( fgets(tmpbuf1, sizeof(tmpbuf1), fs_cur_file ) != NULL ) {
    snprintf(tmpbuf2, sizeof(tmpbuf2), "%s", tmpbuf1);
    /* extract the ip address from this line */
    tmpstr = strtok( tmpbuf2, ":");
    /* is this a match for our current ip? */
    if ( strcmp( tmpstr, ipaddr ) != 0 ) {
      /* no match, so copy the line out to our tmp file */
      fputs(tmpbuf1, fs_tmp_file);
    } else {
      /* Found a match. Dont copy this line out to the tmp file.
       * We dont want to echo this same line out, because we are going
       * to write a new version of the line below, with an updated
       * timestamp attached.
       * Also clear the rebuild_cdb flag, because we arent adding
       * any new entries in this case
       */
      rebuild_cdb = 0;
    }
  }
  /* append the current ip address to the tmp file
   * using the format x.x.x.x:ALLOW,RELAYCLIENT="",RBLSMTPD=""<TAB>timestamp
   */
  fprintf( fs_tmp_file, "%s:allow,RELAYCLIENT=\"\",RBLSMTPD=\"\"\t%d\n", 
    ipaddr, (int)mytime);
  fclose(fs_cur_file);
  fclose(fs_tmp_file);

  /* rename the open-smtp.tmp to the be open-smtp */
  rename(open_smtp_tmp_filename, OPEN_SMTP_CUR_FILE);

  /* if we added new entries to the file (or created it for the 1st time)
   * then we need to rebuild our tcp.smtp.cdb based on our newly built
   * open-smtp file.
   */
  if ( rebuild_cdb ) {
    if (update_rules() != 0) {
      fprintf(stderr, "Error. update_rules() failed\n");
      #ifdef FILE_LOCKING
        unlock_lock(fd_lok_file, 0, SEEK_SET, 0);
        close(fd_lok_file);
      #endif /* FILE_LOCKING */
      return (-1);
    }
  }

#ifdef FILE_LOCKING
  unlock_lock(fd_lok_file, 0, SEEK_SET, 0);
  close(fd_lok_file);
#endif /* FILE_LOCKING */
#endif /* USE_SQL */
  return(0);
}
#endif /* POP_AUTH_OPEN_RELAY */

/************************************************************************/

#ifdef POP_AUTH_OPEN_RELAY 
/* This function is called by update_rules()
 *
 * It will create a tcprules task sitting and waiting for a new ruleset to be
 * piped into it. It will then compile these rules into a new 
 * tcp.smtp.cdb file
 */
long unsigned tcprules_open()
{
 int pim[2];
 long unsigned pid;
 char bin0[MAX_BUFF];
 char bin1[MAX_BUFF];
 char bin2[MAX_BUFF];
 char *binqqargs[4];

  /* create a filename for use as a tmp file */
  snprintf(relay_tempfile, sizeof(relay_tempfile), "%s.tmp.%ld", TCP_FILE, (long unsigned)getpid());

  /* create a pair of filedescriptors for our pipe */
  if (pipe(pim) == -1)  { return(-1);}

  switch( pid=vfork()){
   case -1:
    /* vfork error. close pipes and exit */
    close(pim[0]); close(pim[1]);
    return(-1);
   case 0:
    close(pim[1]);
    if (vfd_move(0,pim[0]) == -1) _exit(120);

    /* build the command line to update the tcp rules file 
     * It will be of this format :
     * TCPRULES_PROG TCP_FILE.cdb TCP_FILE.cbd.tmp.pid
     * eg /usr/local/bin/tcprules /home/vpopmail/etc/tcp.smtp.cdb  /home/vpopmail/etc/tcp.smtp.tmp.pid
     */ 
    snprintf( bin0, sizeof(bin0), "%s", TCPRULES_PROG);
    snprintf( bin1, sizeof(bin1), "%s.cdb", TCP_FILE);
    snprintf( bin2, sizeof(bin2), "%s", relay_tempfile);

    /* put these strings into an argv style array */
    binqqargs[0] = bin0;
    binqqargs[1] = bin1;
    binqqargs[2] = bin2;
    binqqargs[3] = 0;

    /* run this command now (it will sit waiting for input to be piped in */
    execv(*binqqargs,binqqargs);
  }

  /* tcprules_fdm is a filehandle to this process, which we can pipe rules into */
  tcprules_fdm = pim[1]; close(pim[0]);

  return(pid);
}
#endif /* POP_AUTH_OPEN_RELAY */

/************************************************************************/

int vfd_copy(int to, int from)
{
  if (to == from) return 0;
  if (fcntl(from,F_GETFL,0) == -1) return -1;

  close(to);

  if (fcntl(from,F_DUPFD,to) == -1) return -1;

  return 0;
}

/************************************************************************/

int vfd_move(int to, int from)
{
  if (to == from) return 0;
  if (vfd_copy(to,from) == -1) return -1;
  close(from);
  return 0;
}

/************************************************************************/

#ifdef POP_AUTH_OPEN_RELAY 
/* update_rules() is run whenever 
 * - a new ip added (via open_smtp_relay())
 * or
 * - an old ip removed (via clearopensmtp)
 * from the current list of pop connections
 *
 * It generates a new tcp.smtp.cdb file by doing these steps :
 *   for mysql backend :
 *     copy the tcp.smtp file to a tmp file
 *     append the ip's from the relay table to the tmp file
 *     compile the tmp file into a new tcp.smtp.cdb file 
 *   for cdb backend :
 *     copy the tcp.smtp file to a tmp file
 *     append the ip's from the open-smtp file to the tmp file
 *     compile the tmp file into a new tcp.smtp.cdb file 
 */ 
int update_rules()
{
 FILE *fs;
 long unsigned pid;
 int wstat;
 char tmpbuf1[MAX_BUFF];

#ifndef USE_SQL
 char tmpbuf2[MAX_BUFF];
 char *tmpstr;
#endif

#ifndef REBUILD_TCPSERVER
  return(0);
#endif

  umask(VPOPMAIL_TCPRULES_UMASK);

  /* open up a tcprules task, and leave it sitting waiting for the
   * new set of rules to be piped in (via the filehandle "tcprules_fdm")
   */
  if ((pid = tcprules_open()) < 0) return(-1);

  /* Open the TCP_FILE if it exists.
   * it is typically named /home/vpopmail/etc/tcp.smtp
   */
  fs = fopen(TCP_FILE, "r");
  if ( fs != NULL ) {
    /* copy the contents of the current tcp.smtp file into the tcprules pipe */
    while ( fgets(tmpbuf1, sizeof(tmpbuf1), fs ) != NULL ) {
      write(tcprules_fdm,tmpbuf1, strlen(tmpbuf1));
    }
    fclose(fs);
  }

#ifdef USE_SQL
  /* suck out a list of ips stored in the 'relay' table
   * and write these into 'tcp.smtp' format for the tcprules pipe
   */
  vupdate_rules(tcprules_fdm);

#else

  /* open up the file that contains the list of recent open connections
   * (by default this is ~vpopmail/etc/open-smtp)
   * This file is generated by the open_smtp() function
   * the file has the following format :
   * x.x.x.x:ALLOW,RELAYCLIENT="",RBLSMTPD=""<TAB>timestamp
   */
  fs = fopen(OPEN_SMTP_CUR_FILE, "r");
  if ( fs != NULL ) {
    /* read each of the recently open connections. */
    while ( fgets(tmpbuf1, sizeof(tmpbuf1), fs ) != NULL ) {
      snprintf(tmpbuf2, sizeof(tmpbuf2), "%s", tmpbuf1);
      /* dump the TAB and everything after it */
      tmpstr = strtok( tmpbuf2, "\t");
      strncat(tmpstr, "\n", sizeof(tmpstr)-strlen(tmpstr)-1);
      /* write the line out to the tcprules pipe */
      write(tcprules_fdm,tmpstr, strlen(tmpstr));
    }
    fclose(fs);
  }
#endif

  /* close the pipe to the tcprules process. This will cause
   * tcprules to generate a new tcp.smtp.cdb file 
   */
  close(tcprules_fdm);  

  /* wait untill tcprules finishes so we don't have zombies */
  waitpid(pid,&wstat,0);

  /* if tcprules encounters an error, then the tempfile will be
   * left behind on the disk. We dont want this because we could
   * possibly end up with a large number of these files cluttering
   * the directory. Therefore we will use unlink now to make
   * sure to zap the temp file if it still exists
   */
  if ( unlink(relay_tempfile) == 0 ) {
    fprintf(stderr, "Warning: update_rules() - tcprules failed\n");
  }

  /* correctly set the ownership of the tcp.smtp.cdb file */
  snprintf(tmpbuf1, sizeof(tmpbuf1), "%s.cdb", TCP_FILE);
  chown(tmpbuf1,VPOPMAILUID,VPOPMAILGID);

  return(0);
}
#endif

/************************************************************************/

int vexit(int err)
{
  vclose();
  exit(err);
}

/************************************************************************/

/* zap the maildirsize file from a users dir */
void remove_maildirsize(char *dir) {
 char maildirsize[MAX_BUFF];
 FILE *fs;

  snprintf(maildirsize, sizeof(maildirsize), "%s/Maildir/maildirsize", dir);
  if ( (fs = fopen(maildirsize, "r+"))!=NULL) {
    fclose(fs);
    unlink(maildirsize);
  }
}

/************************************************************************/
/* update_maildirsize first appeared in 5.4.8 */
void update_maildirsize (char *domain, char *dir, char *quota)
{
  uid_t uid;
  gid_t gid;
  char maildir[MAX_BUFF];

  remove_maildirsize(dir);
  if (strcmp (quota, "NOQUOTA") != 0) {
    snprintf(maildir, sizeof(maildir), "%s/Maildir/", dir);
    umask(VPOPMAIL_UMASK);
    (void)vmaildir_readquota(maildir, quota);
    if ( vget_assign(domain, NULL, 0, &uid, &gid)!=NULL) {
      strcat(maildir, "maildirsize");
      chown(maildir,uid,gid);
    }
  }
}

/************************************************************************/

/* run some tests on the contents of a vpqw struct */
int vcheck_vqpw(struct vqpasswd *inpw, char *domain)
{

  if ( inpw == NULL )   return(VA_NULL_POINTER );
  if ( domain == NULL ) return(VA_NULL_POINTER);

  if ( inpw->pw_name == NULL )         return(VA_NULL_POINTER);
  if ( inpw->pw_passwd == NULL )       return(VA_NULL_POINTER);
  if ( inpw->pw_gecos == NULL )        return(VA_NULL_POINTER);
  if ( inpw->pw_dir == NULL )          return(VA_NULL_POINTER);
  if ( inpw->pw_shell == NULL )        return(VA_NULL_POINTER);
#ifdef CLEAR_PASS
  if ( inpw->pw_clear_passwd == NULL ) return(VA_NULL_POINTER);
#endif

  /* when checking for excess size using strlen, the check needs use >= because you
   * have to allow 1 char for null termination
   */ 
  if ( strlen(inpw->pw_name) > MAX_PW_NAME )    return(VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR
  if ( strlen(inpw->pw_name) == 1 )             return(VA_ILLEGAL_USERNAME);
#endif
  if ( strlen(domain) > MAX_PW_DOMAIN )         return(VA_DOMAIN_NAME_TOO_LONG);
  if ( strlen(inpw->pw_passwd) > MAX_PW_PASS )  return(VA_PASSWD_TOO_LONG);
  if ( strlen(inpw->pw_gecos) > MAX_PW_GECOS )  return(VA_GECOS_TOO_LONG);
  if ( strlen(inpw->pw_dir) > MAX_PW_DIR )      return(VA_DIR_TOO_LONG);
  if ( strlen(inpw->pw_shell) > MAX_PW_QUOTA )  return(VA_QUOTA_TOO_LONG);
#ifdef CLEAR_PASS
  if ( strlen(inpw->pw_clear_passwd) > MAX_PW_CLEAR_PASSWD )
                                                return(VA_CLEAR_PASSWD_TOO_LONG);
#endif
  return(VA_SUCCESS);

}

/************************************************************************/

char *vrandom_pass(char *buffer, int len)
/* write a random password of 'len' characters to buffer and return it */
{
  int gen_char_len; 
  int i, k; 
  static int seeded = 0;

  if (buffer == NULL) return buffer;

  gen_char_len = strlen(gen_chars);

  if (!seeded) {
    seeded = 1;
    srand(time(NULL)^(getpid()<<15));
  }

  for (i = 0; i < len; i++) {
    k = rand()%gen_char_len;
    buffer[i] = gen_chars[k];
  }
  buffer[len] = '\0';  /* NULL terminator */

  return buffer;
}

char *vgen_pass(int len)
/* old function to generate a random password (replaced by vrandom_pass) */
{
  char *p;

  p = malloc(len + 1);
  if (p == NULL) return NULL;
  return (vrandom_pass (p, len));
}


/************************************************************************/

/* if inchar is valid, return 1
 * if inchar is invalid, return 0
 *
 * Michael Bowe 15th August 2003
 * This  function isnt used by vpopmail, cantidate for removal?
 */
int vvalidchar( char inchar ) 
{
 
 /* check lower case a to lower case z */
 if ( inchar >= 'a' && inchar <= 'z' ) return(1);

 /* check upper case a to upper case z */
 if ( inchar >= 'A' && inchar <= 'Z' ) return(1);

 /* check numbers */
 if ( inchar >= '0' && inchar <= '9' ) return(1);

 /* check for '-' and '.' */
 if ( inchar == '-' || inchar == '.' || inchar == '_' ) return(1);

 /* everything else is invalid */
 verrori = VA_INVALID_EMAIL_CHAR;
 return(0);
 
}

/************************************************************************/

/* support all the valid characters except %
 * which might be exploitable in a printf
 */
int is_username_valid( char *user ) 
{
  while(*user != 0 ) {
    if ( (*user == 33) || 
         (*user == 35 ) || 
         (*user == 36 ) || 
         (*user == 38 ) || 
         (*user == 39 ) || 
         (*user == 42 ) || (*user == 43) ||
         (*user >= 45 && *user <= 57) ||
         (*user == 61 ) || (*user == 63 ) ||
         (*user >= 65 && *user <= 90) ||
         (*user >= 94 && *user <= 126 ) ) {
      ++user;
    } else {
      return(VA_ILLEGAL_USERNAME);
    }
  }
  return(0);
}

/************************************************************************/

int is_domain_valid( char *domain ) 
{
  while(*domain != 0 ) {
    if ( (*domain == 45) || (*domain == 46) || 
         (*domain >= 48 && *domain <= 57) ||
         (*domain >= 65 && *domain <= 90) ||
         (*domain >= 97 && *domain <= 122) ) {
      ++domain;
    } else {
      return(VA_INVALID_DOMAIN_NAME);
    }
  }
  return(0);
}

/************************************************************************/

/* add an alias domain to the system  */
int vaddaliasdomain( char *alias_domain, char *real_domain)
{
 int err;
 uid_t uid;
 gid_t gid;
 char Dir[MAX_BUFF];
 
  lowerit(alias_domain);
  lowerit(real_domain);

  if ( (err=is_domain_valid(real_domain)) != VA_SUCCESS ) return(err);
  if ( (err=is_domain_valid(alias_domain)) != VA_SUCCESS ) return(err);

  /* make sure the alias domain does not exceed the max storable size */
  if (strlen(alias_domain) > MAX_PW_DOMAIN) {
    return(VA_DOMAIN_NAME_TOO_LONG);
  }

  /* Make sure that the alias_domain doesnt already exist */
  /* Michael Bowe 21st Aug 2003 
   * Will the alias_domain get overwritten with the real_domain
   * by the call below?
   * Could this mess things up for the calling function?
   */
  if (( vget_assign(alias_domain, NULL, 0, NULL, NULL)) != NULL) {
    return(VA_DOMAIN_ALREADY_EXISTS);
  }

  /* Make sure the real domain exists */
  if (( vget_assign(real_domain, Dir, sizeof(Dir), &uid, &gid)) == NULL) {
    return(VA_DOMAIN_DOES_NOT_EXIST);
  }

  if (strcmp(alias_domain, real_domain)==0) {
    fprintf(stderr, "Error. alias and real domain are the same\n");
    return(VA_DOMAIN_ALREADY_EXISTS);
  }

  /* Add the domain to the assign file */
  add_domain_assign( alias_domain, real_domain, Dir, uid, gid );

  /* signal qmail-send, so it can see the changes */
  signal_process("qmail-send", SIGHUP);


#ifdef ONCHANGE_SCRIPT
  /* tell other programs that data has changed */
  snprintf ( onchange_buf, MAX_BUFF, "%s %s", alias_domain, real_domain );
  call_onchange ( "add_alias_domain" );
#endif

  return(VA_SUCCESS);
}

/************************************************************************/

                /* properly handle the following formats:
                 * "1M", "1024K", "1048576" (set 1 MB quota)
                 * "1MB", "1024KB" (set 1 MB quota)
                 * "NOQUOTA" (no quota)
                 * "1mbs,1000C" (1 MB size, 1000 message limit)
                 * "1048576S,1000C" (1 MB size, 1000 message limit)
                 * "1000C,10MBS" (10 MB size, 1000 message limit)
                 */

char *format_maildirquota(const char *q) {
int     i;
storage_t quota_size;
storage_t quota_count;
char	*p;
static char    tempquota[128];

    if (strcmp (q, "NOQUOTA") == 0) {
      strcpy (tempquota, "NOQUOTA");
      return tempquota;
    }

    /* translate the quota to a number, or leave it */
    quota_size = 0;
    quota_count = 0;
    snprintf (tempquota, sizeof(tempquota), "%s", q);
    p = strtok (tempquota, ",");
    while (p != NULL) {
      i = strlen(p) - 1;
      if (p[i] == 'C') { /* specify a limit on the number of messages (COUNT) */
        quota_count = strtoll(p, NULL, 10);
      } else { /* specify a limit on the size */
        /* strip optional trailing S */
        if ((p[i] == 'S') || (p[i] == 's')) p[i--] = '\0';
        /* strip optional trailing B (for KB, MB) */
        if ((p[i] == 'B') || (p[i] == 'b')) p[i--] = '\0';

        quota_size = strtoll(p, NULL, 10);
        if ((p[i] == 'M') || (p[i] == 'm')) quota_size *= 1024 * 1024;
        if ((p[i] == 'K') || (p[i] == 'k')) quota_size *= 1024;
      }
      p = strtok (NULL, ",");
    }

    if (quota_count == 0)
      if (quota_size == 0) strcpy (tempquota, ""); /* invalid quota */
      else sprintf (tempquota, "%lluS", quota_size);
    else if (quota_size == 0)
      sprintf (tempquota, "%lluC", quota_count);
    else
      sprintf (tempquota, "%lluS,%lluC", quota_size, quota_count);

    return tempquota;
}

/************************************************************************/

/* returns a 39 character Date: header with trailing newline and NULL */
char *date_header()
{
  static char dh[39];
  time_t now;
  struct tm *tm;

  static char *montab[12] = {
  "Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"
  };
  static char *wday[7] = {
  "Sun","Mon","Tue","Wed","Thu","Fri","Sat"
  };

  /* look up current time and fill tm structure */
  time(&now);
  tm = gmtime(&now);

  snprintf (dh, sizeof(dh),
    "Date: %s, %02u %s %u %02u:%02u:%02u +0000\n",
    wday[tm->tm_wday], tm->tm_mday, montab[tm->tm_mon], tm->tm_year + 1900,
    tm->tm_hour, tm->tm_min, tm->tm_sec);

  return dh;
}

char *get_remote_ip()
{
  char *ipenv;
  static char ipbuf[30];
  char *ipaddr;
  char *p;

  ipenv = getenv("TCPREMOTEIP"); /* tcpserver from daemontools */
  if (ipenv == NULL) ipenv = getenv("REMOTE_HOST"); /* xinetd */
  if ((ipenv == NULL) || (strlen(ipenv) > sizeof(ipbuf))) return ipenv;

  strcpy (ipbuf, ipenv);
  ipaddr = ipbuf;

  /* Convert ::ffff:127.0.0.1 format to 127.0.0.1
   * While avoiding buffer overflow.
   */
  if (*ipaddr == ':') {
    ipaddr++;
    if (*ipaddr != '\0') ipaddr++;
    while((*ipaddr != ':') && (*ipaddr != '\0')) ipaddr++;
    if (*ipaddr != '\0') ipaddr++;
  }

  /* remove invalid characters */
  for (p = ipaddr; *(p += strspn(p, ok_env_chars)); ) {*p='_';}

  return ipaddr;  
}

char *maildir_to_email (const char *maildir)
{
	static char email[256];
	char calling_dir[MAX_BUFF];
	int i;
	char *pnt, *last;
	char *mdcopy;
	char *user;
	int sawdot;

	/* prepend the cwd if the maildir starts with ./ */
	if (strlen (maildir) > 1 && maildir[0] == '.' && maildir[1] == '/')
	{
		getcwd(calling_dir, sizeof(calling_dir));
		mdcopy = malloc (strlen (maildir) + strlen (calling_dir) + 1);
		if (mdcopy == NULL) return "";
		strcat (strcpy (mdcopy, calling_dir), maildir + 1);
	}
	else
	{
		mdcopy = malloc (strlen (maildir) + 1);
		if (mdcopy == NULL) return "";
		strcpy (mdcopy, maildir);
	}

	/* find the last occurrence of /Maildir/ */
	pnt = mdcopy;
	do {
		last = pnt;
		pnt = strstr (pnt + 1, "/Maildir/");
	} while (pnt != NULL);

	if ((last == pnt) || (last == mdcopy)) {
		/* no occurrences of "/Maildir/" in path */

	     /*
		    Look for last occurrence of /Maildir\0
		 */

	     pnt = mdcopy;
		 do {
			last = pnt;
			pnt = strstr(pnt + 1, "/Maildir");
		 } while(pnt != NULL);

	     for (pnt = last; *pnt; pnt++);

		 if (strcmp(pnt - 8, "/Maildir")) {
			free (mdcopy);
			return "";
		 }

		 last = (pnt - 8);
	}

	/* last points to /Maildir/ after username, so null terminate
	 * username by changing the '/' to a NUL
	 */
	*last = '\0';
 
 	/* find start of username */
 	i = (int) (last - mdcopy);
 	while (i > 0 && mdcopy[i] != '/') { i--; }
 	
 	if (i == 0) {
 		/* invalid maildir path */
 		free (mdcopy);
 		return "";
	}
	
	user = &mdcopy[i+1];
	
	/* look for first directory name that contains a '.', that's the domain */
	sawdot = 0;
	do {
		mdcopy[i] = '\0';	/* change '/' to NUL to NUL-terminate domain */
		/* search backwards for '/' */
		while (i > 0 && (mdcopy[i] != '/')) {
			if (mdcopy[i] == '.') sawdot = 1;
			i--;
		}
	} while ((i > 0) && !sawdot);
	
	if (i == 0) {
		/* couldn't find domain name */
		free (mdcopy);
		return "";
	}
		
	snprintf (email, sizeof(email), "%s@%s", user, &mdcopy[i+1]);
	free (mdcopy);
	
	return email;
}

/* escape these characters out of strings: ', \, " */
#define ESCAPE_CHARS "'\"\\"

/* qnprintf - Custom version of snprintf for creating SQL queries with escaped
 *            strings.
 *
 * int qnprintf (char *buffer, size_t size, const char *format, ...)
 *
 *   buffer - buffer to print string to
 *   size   - size of buffer
 *   format - a printf-style format string*
 *   ...    - variable arguments for the format string
 *
 *  NOTE: Currently supported formats: %%, %s, %d/%i, %u, %ld/%li, %lu
 *  Since this function was designed to build SQL queries with escaped data,
 *  the formats don't support any extended options.
 *
 * Returns the number of characters that would have been printed to buffer
 * if it was big enough.  (i.e., if return value is larger than (size-1),
 * buffer received an incomplete copy of the formatted string).
 *
 * It is possible to call qnprintf with a NULL buffer of 0 bytes to determine
 * how large the buffer needs to be.  This is inefficient, as qnprintf has
 * to run twice.
 *
 * qnprintf written February 2004 by Tom Collins <tom@tomlogic.com>
 */
int qnprintf (char *buffer, size_t size, const char *format, ...)
{
	va_list ap;
	int printed;   /* number of characters printed */
	const char *f; /* current position in format string */
	char *b;       /* current position in output buffer */
	char n[60];    /* buffer to hold string representation of number */
	
        int argn = 0;  /* used for numbered arguments */
        char argstr[10];

	char *s;       /* pointer to string to insert */

	if (buffer == NULL && size > 0) return -1;

	va_start (ap, format);

	printed = 0;
	b = buffer;
	for (f = format; *f != '\0'; f++) {
		if (*f != '%') {
			if (++printed < (int)size) *b++ = *f;
		} else {
			f++;
			s = n;
			switch (*f) {
				case '%':
					strcpy (n, "%");
					break;
					
				case 'd':
				case 'i':
					snprintf (n, sizeof(n), "%d", va_arg (ap, int));
					break;
					
				case 'u':
					snprintf (n, sizeof(n), "%u", va_arg (ap, unsigned int));
					break;

			    case 'S':
					snprintf(n, sizeof(n), "%llu", va_arg(ap, storage_t));
					break;
					
				case 'l':
					f++;

					switch (*f) {
						case 'd':
						case 'i':
							snprintf (n, sizeof(n), "%ld", va_arg (ap, long));
							break;
					
						case 'u':
							snprintf (n, sizeof(n), "%lu", va_arg (ap, unsigned long));
							break;

						default:
							strcpy (n, "*");
					}
					break;
										
				case 's':
					s = va_arg (ap, char *);
					break;
					
                                default:
                                        argn = 0;
                                        while ((*f >= '0') && (*f <= '9')) {
                                          argn = argn * 10 + atoi(f);
                                          f++;
                                        }
                                        if ((argn > 0) && (*f == '$')) {
                                          f++;
                                          if (*f == 'l') {
                                            f++;
                                            switch (*f) {
                                              case 'i':
                                                snprintf(argstr, sizeof(argstr), "%%%d$ld", argn);
                                                break;
 
                                              case 'u':
                                                snprintf(argstr, sizeof(argstr), "%%%d$lu", argn);
                                                break;
 
                                              default:
                                                snprintf(argstr, sizeof(argstr), "%%%d$l%c", argn, *f);
                                            }
                                          } else {
                                            snprintf(argstr, sizeof(argstr), "%%%d$%c", argn, *f);
                                          }
                                          vsprintf(s, argstr, ap);
                                        } else if(argn > 0) {
                                          while (argn > 10) {
                                            argn = argn / 10;
                                            f--;
                                          }
                                          strcpy (n, "*");
                                        }


			}
			while (*s != '\0') {
				if (strchr (ESCAPE_CHARS, *s) != NULL) {
					if (++printed < (int)size) *b++ = '\\';
				}
				if (++printed < (int)size) *b++ = *s;
				s++;
			}
		}
	}

	va_end (ap);

	*b = '\0';

	/* If the query doesn't fit in the buffer, zero out the buffer.  An
	 * incomplete query could be very dangerous (say if a WHERE clause
	 * got dropped from a DELETE).
	 */
	if (printed >= (int)size) {
		memset (buffer, '\0', size);
	}
	
	return printed;
}

/* Linked-list code for handling valias entries in SQL database (read
 * all entries into memory, close connection to DB, return one entry
 * at a time, freeing old entries as we go.)
 *
 * linklist_{add|del} written September 2004 by Tom Collins <tom@tomlogic.com>
 */

/* create a new entry for data, point list->next to it and return a pointer to it */
struct linklist * linklist_add (struct linklist *list, const char *d1, const char *d2) {
	size_t dlen;
	int i;
	struct linklist *entry;
	
	dlen = strlen (d1) + 1 + strlen (d2);
	/* new entry to hold string, NULL and a pointer to the next entry */
	entry = (struct linklist *) malloc (dlen + 1 + sizeof(struct linklist*) + sizeof(char *));
	if (entry != NULL) {
		if (list != NULL) list->next = entry;
		entry->next = NULL;
		i = sprintf (entry->data, "%s", d1);
		entry->d2 = &entry->data[i+1];
		sprintf (entry->d2, "%s", d2);
	}
	return entry;
}

/* delete the passed entry and return a pointer to the next entry */
struct linklist * linklist_del (struct linklist *list) {
	struct linklist *next;
	
	next = list->next;
	free (list);
	return next;
}

#ifdef ONCHANGE_SCRIPT
/************************************************************************
 *
 * Run an external program to notify other systems that something changed
 * John Simpson <jms1@jms1.net> 2005-01-22
 *
 * 2006-03-30 jms1 - added command line parameters for external program
 *
 * 2007-01-09 jms1 - cleanup, now returns onchange script exit code,
 *   error messages are now accurate.
 *
 * 2007-07-14 jms1 - suppressing "ONCHANGE script not found" message.
 */
char onchange_buf[MAX_BUFF];
int allow_onchange=1;
int call_onchange ( const char *cmd )
{
	char path[MAX_BUFF];
	int pid, rv;

        if( !allow_onchange )  {
           return(0);
           }

	/* build the name */
	snprintf ( path, sizeof(path), "%s/etc/onchange", VPOPMAILDIR );

	/* if it doesn't exist, we're done */
	if( access(path,F_OK) ) { 
           return(0);
           }

	/* it does exist, make sure we're allowed to run it */
	if( access(path,X_OK) ) { 
           fprintf(stderr, "ONCHANGE script %s not executable.\n", path);
           return(EACCES);
           }

	/* okay, let's do it */
	pid = vfork();
	if ( 0 == pid )
	{
		execl ( path, "onchange", cmd, onchange_buf, NULL );
           	fprintf(stderr, "ONCHANGE script %s unable to exec.\n", path);
	        return(0); /* would "_exit(-1)" make more sense here ??? */
	}
	else if ( pid > 0 )
	{
		wait(&rv);
		return(rv);
	}

	fprintf(stderr, "ONCHANGE script %s unable to fork.\n", path);
	return(0);
}
#endif

