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
#include <lber.h>
#include <ldap.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include "config.h"
#include "vauth.h"
#include "vlimits.h"
#include "vpopmail.h"
#include "vldap.h"

LDAP *ld = NULL;
LDAPMessage *glm = NULL;

#ifdef CLEAR_PASS
#define NUM_LDAP_FIELDS 9
#else
#define NUM_LDAP_FIELDS 8
#endif

char *ldap_fields[NUM_LDAP_FIELDS] = {
    "uid",              /* 0 pw_name   */
    "userPassword",     /* 1 pw_passwd */
    "qmailUID",         /* 2 pw_uid    */
    "qmailGID",         /* 3 pw_gid    */
    "qmaildomain",      /* 4 pw_gecos  */
    "mailMessageStore", /* 5 pw_dir    */
    "mailQuota",        /* 6 pw_shell  */
#ifndef CLEAR_PASS
    "objectclass" /* 7 ldap      */
#else
    "clearPassword", /* 7 pw_clear_passwd */
    "objectclass"    /* 8 ldap      */
#endif
};

/***************************************************************************/

/*
 * get ldap connection info
 */
int load_connection_info() {
  FILE *fp;
  char conn_info[256];
  char config[256];
  int eof;
  static int loaded = 0;
  char *port;
  char delimiters[] = "|\n";
  char *conf_read;

  if (loaded) return 0;
  loaded = 1;

  sprintf(config, "%s/etc/%s", VPOPMAILDIR, "vpopmail.ldap");

  fp = fopen(config, "r");
  if (fp == NULL) {
    fprintf(stderr, "vldap: can't read settings from %s\n", config);
    return (VA_NO_AUTH_CONNECTION);
  }

  /* skip comments and blank lines */
  do {
    eof = (fgets(conn_info, sizeof(conn_info), fp) == NULL);
  } while (!eof && ((*conn_info == '#') || (*conn_info == '\n')));

  if (eof) {
    /* no valid data read, return error */
    fprintf(stderr, "vldap: no valid settings in %s\n", config);
    return (VA_NO_AUTH_CONNECTION);
  }

  conf_read = strdup(conn_info);
  VLDAP_SERVER = strtok(conf_read, delimiters);
  if (VLDAP_SERVER == NULL) return VA_PARSE_ERROR;
  port = strtok(NULL, delimiters);
  if (port == NULL) return VA_PARSE_ERROR;
  VLDAP_PORT = atoi(port);
  VLDAP_USER = strtok(NULL, delimiters);
  if (VLDAP_USER == NULL) return VA_PARSE_ERROR;
  VLDAP_PASSWORD = strtok(NULL, delimiters);
  if (VLDAP_PASSWORD == NULL) return VA_PARSE_ERROR;
  VLDAP_BASEDN = strtok(NULL, delimiters);
  if (VLDAP_BASEDN == NULL) return VA_PARSE_ERROR;

  return 0;
}

struct vqpasswd *vauth_getpw(char *user, char *domain) {
  int ret = 0;
  size_t len = 0;
  struct vqpasswd *vpw = NULL;
  LDAPMessage *res = NULL, *msg = NULL;
  struct berval **rval = NULL;
  char *filter = NULL, **vals = NULL, *h = NULL, *t = NULL, *passwd = NULL;
  char *dn = NULL;
  uid_t myuid;
  uid_t uid;
  gid_t gid;

  verrori = 0;
  lowerit(user);
  lowerit(domain);

  vget_assign(domain, NULL, 0, &uid, &gid);

  myuid = geteuid();
  if (myuid != 0 && myuid != uid) {
    return (NULL);
  }

  /* connect to the ldap server (if we havent already got a connection open) */
  if (ld == NULL) {
    if (ldap_connect() != 0) {
      safe_free((void **)&filter);
      return NULL;
    }
  }

  /* take a given domain, and set dn to be this format :
   * ou=somedomain.com,o=vpopmail
   */
  if (compose_dn(&dn, domain) != 0) return NULL;

  /* take the username and create set filter ot be in this format :
   * (&(objectclass=qmailUser)(uid=someusername))
   */
  len = (strlen(user) + 32 + 1);
  filter = (char *)safe_malloc(len);
  memset((char *)filter, 0, len);
  snprintf(filter, len, "(&(objectclass=qmailUser)(uid=%s))", user);

  /* perform an ldap search
   * int ldap_search_s(ld, base, scope, filter, attrs, attrsonly, res)
   *
   * Will search synchronously, and not return until the operation completes.
   * base : DN of the entry at which to start the search
   * scope : scope of the search
   *   LDAP_SCOPE_SUBTREE means to search the object and all of its descendents.
   * filter : filter to apply to the search
   * attrs : attribute types to return from entries that match filter
   * attrsonly : set to 0 for attributes and attributetypes are wanted. 1 if
   * only attributes are wanted.
   */
  ret = ldap_search_ext_s(ld, dn, LDAP_SCOPE_SUBTREE, filter, vldap_attrs, 0,
                          NULL, NULL, NULL, LDAP_NO_LIMIT, &res);

  safe_free((void **)&filter);

  /* see if the search ran without generating an error */
  if (ret != LDAP_SUCCESS) {
    fprintf(stderr, "%s\n", ldap_err2string(ret));
    return NULL;
  }

  /* grab a pointer to the 1st entry in the chain of search results */
  msg = ldap_first_entry(ld, res);
  if (msg == NULL) {
    /* We had an error grabbing the pointer */
    return NULL;
  }

  /* find out how many matches we found */
  ret = ldap_count_entries(ld, msg);
  if (ret == -1) {
    /* an error occurred when counting the entries */
    fprintf(stderr, "%s\n", ldap_err2string(ret));
    return NULL;
  }

  /*
     Fetch userPassword first so we can make sure
     we're able to handle it's password encryption (if any)
  */

  /* userPasswd / pw_password */

  rval = ldap_get_values_len(ld, msg, "userPassword");
  if (rval == NULL) {
    fprintf(stderr, "Error\n");
    return NULL;
  }

  t = h = NULL;

  passwd = (char *)safe_malloc((*rval)->bv_len + 1);
  memset((char *)passwd, 0, (*rval)->bv_len + 1);
  memcpy((char *)passwd, (char *)((*rval)->bv_val), (*rval)->bv_len);

  ldap_value_free_len(rval);

  if (*passwd == '{') {
    for (t = h = (passwd + 1); *t; t++) {
      if (*t == '}') {
        *t++ = '\0';

        /* This is not the best, but we keep the pointer as (h - 1) */
        passwd = t;

        /*
           Check against the encryption method, and if we see something
           we dont recognize or support, invalidate user login.
           vol@inter7.com
        */

        /* Steki <steki@verat.net> Thu Jan 24 17:27:18 CET 2002
         *  Added check for MD5 crypted passwords
         */

        if (strcmp(h, "crypt") && strcmp(h, "MD5")) {
          free(h - 1);
          return NULL;
        }
        break;
      }
    }
    /*
       No terminating brace found, or empty password.
       vol@inter7.com
    */
    if (!(*t)) {
      return NULL;
    }
  }

  /* create a vpw struct, which we will populate with the data we suck in from
   * ldap */
  vpw = (struct vqpasswd *)safe_malloc(sizeof(struct vqpasswd));
  memset((struct vqpasswd *)vpw, 0, sizeof(struct vqpasswd));

  vpw->pw_passwd = (char *)safe_malloc((strlen(passwd) + 1));
  memset((char *)vpw->pw_passwd, 0, (strlen(passwd) + 1));
  memcpy((char *)vpw->pw_passwd, (char *)(passwd), strlen(passwd));

  if (vpw->pw_passwd == NULL) {
    free(h - 1);
    return NULL;
  }

  /*
     Old passwd pointer.
     ..and don't forget to check if you even set the pointer *smack*

     vol@inter7.com
  */
  if (h) free(h - 1);

  /* uid / pw_name */
  rval = ldap_get_values_len(ld, msg, "uid");
  if (rval == NULL) {
    safe_free((void **)&vpw->pw_passwd);
    fprintf(stderr, "Error\n");
    return NULL;
  }

  vpw->pw_name = (char *)safe_malloc((*rval)->bv_len + 1);
  memset((char *)vpw->pw_name, 0, (*rval)->bv_len + 1);
  memcpy((char *)vpw->pw_name, (char *)((*rval)->bv_val), (*rval)->bv_len);

  ldap_value_free_len(rval);

  /* mailQuota / pw_shell */
  rval = ldap_get_values_len(ld, msg, "mailQuota");
  if (rval)
    vpw->pw_shell = (char *)safe_malloc((*rval)->bv_len + 1);
  else
    vpw->pw_shell = (char *)safe_malloc(1);

  if (rval) {
    memset((char *)vpw->pw_shell, 0, (strlen(*vals) + 1));
    memcpy((char *)vpw->pw_shell, (char *)((*rval)->bv_val),
           (*rval)->bv_len + 1);
    ldap_value_free_len(rval);
  } else {
    *vpw->pw_shell = '\0';
    fprintf(stderr, "Error\n");
  }

  /* qmaildomain / pw_gecos */
  rval = ldap_get_values_len(ld, msg, "qmaildomain");
  if (rval) {
    vpw->pw_gecos = (char *)safe_malloc((*rval)->bv_len + 1);
    memset((char *)vpw->pw_gecos, 0, (*rval)->bv_len + 1);
    memcpy((char *)vpw->pw_gecos, (char *)((*rval)->bv_val),
           (*rval)->bv_len + 1);
    ldap_value_free_len(rval);
  } else
    fprintf(stderr, "Error\n");

  /* mailMessageStore / pw_dir */
  rval = ldap_get_values_len(ld, msg, "mailMessageStore");
  if (rval) {
    vpw->pw_dir = (char *)safe_malloc((*rval)->bv_len + 1);
    memset((char *)vpw->pw_dir, 0, (*rval)->bv_len + 1);
    memcpy((char *)vpw->pw_dir, (char *)((*rval)->bv_val), (*rval)->bv_len + 1);
    ldap_value_free_len(rval);
  } else
    fprintf(stderr, "Error\n");

  /* qmailUID / pw_uid */
  rval = ldap_get_values_len(ld, msg, "qmailUID");
  if (rval) {
    vpw->pw_uid = atoi((*rval)->bv_val);
    ldap_value_free_len(rval);
  } else
    fprintf(stderr, "Error\n");

  /* qmailGID / pw_gid */
  rval = ldap_get_values_len(ld, msg, "qmailGID");
  if (rval) {
    vpw->pw_gid = atoi((*rval)->bv_val);
    ldap_value_free_len(rval);
  } else
    fprintf(stderr, "Error\n");

#ifdef CLEAR_PASS
  /* clearPasswd /  pw_clear_passwd */
  rval = ldap_get_values_len(ld, msg, "clearPassword");
  if (rval) {
    vpw->pw_clear_passwd = (char *)safe_malloc((*rval)->bv_len + 1);
    memset((char *)vpw->pw_clear_passwd, 0, (*rval)->bv_len + 1);
    memcpy((char *)vpw->pw_clear_passwd, (char *)((*rval)->bv_val),
           (*rval)->bv_len + 1);
    ldap_value_free_len(rval);
  }
#endif

  vlimits_setflags(vpw, domain);

  return vpw;
}

/***************************************************************************/

void vauth_end_getall() {}

/***************************************************************************/

struct vqpasswd *vauth_getall(char *domain, int first, int sortit) {
  int ret = 0;
  size_t len = 0;
  struct vqpasswd *pw = NULL;
  LDAPMessage *res = NULL;
  char *filter = NULL, **vals = NULL;
  char *basedn = NULL;
  struct berval **rval = NULL;

  /* if 1st time through, extract all users from this chosen domain */
  if (first) {
    lowerit(domain);

    len = (32 + 1);

    filter = (char *)safe_malloc(len);

    memset((char *)filter, 0, len);

    /* connect to the ldap server if we havent already done so */
    if (ld == NULL) {
      if (ldap_connect() != 0) {
        safe_free((void **)&filter);
        return NULL;
      }
    }

    /* set basedn to be of the format :
     *   ou=somedomain,o=vpopmail
     */
    if (compose_dn(&basedn, domain) != 0) {
      safe_free((void **)&filter);
      return NULL;
    }

    snprintf(filter, len, "(objectclass=qmailUser)");

    /* perform the lookup for all users in a given domain */
    ret = ldap_search_ext_s(ld, basedn, LDAP_SCOPE_SUBTREE, filter, vldap_attrs,
                            0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);

    safe_free((void **)&basedn);
    safe_free((void **)&filter);

    if (ret != LDAP_SUCCESS) {
      fprintf(stderr, "Error\n");
      return NULL;
    }

    /* sort the entries alphabetically by username if required */

    /* sorting is deprecated in recent version of openldap ! */
    /*
            if ( sortit ) {
                if ( ldap_sort_entries( ld, &res, "uid", &strncmp ) != 0)  {
                    fprintf(stderr, "Error\n");
                    return NULL;
                }

                if (ret != LDAP_SUCCESS)
                    return NULL;
            }
    */
    /* get a pointer to the first user in the list */
    glm = ldap_first_entry(ld, res);
    if (glm == NULL) return NULL;

    /* grab the ldap properties of this user */
    rval = ldap_get_values_len(ld, glm, "uid");
    if (rval == NULL) {
      fprintf(stderr, "Error\n");
      return NULL;
    }

    /* grab the vpopmail properties of this user */
    pw = vauth_getpw(*vals, domain);

    return pw;
  } else {
    /* not 1st time through, so get next entry from the chain */
    if (glm == NULL) /* Just to be safe. (vol@inter7.com) */
      return NULL;

    res = glm;

    glm = ldap_next_entry(ld, res);
    if (glm == NULL) return NULL;

    rval = ldap_get_values_len(ld, glm, "uid");
    if (rval == NULL) {
      fprintf(stderr, "Error\n");
      return NULL;
    }

    pw = vauth_getpw(*vals, domain);

    ldap_value_free_len(rval);

    return pw;
  }
}

/***************************************************************************/

/*
   Higher-level functions no longer crypt.
   Lame.

   vol@inter7.com
*/
int vauth_adduser(char *user, char *domain, char *password, char *gecos,
                  char *dir, int apop) {
  char *dn = NULL;
  char *dn_tmp = NULL;
  LDAPMod **lm = NULL;
  char dom_dir[156];
  uid_t uid;
  gid_t gid;
  int ret = 0, vd = 0;
  int i, len;
  char *b = NULL;
  char crypted[100] = {0};

  if ((dir) && (*dir)) vd = 1;

  if (gecos == 0 || gecos[0] == 0) gecos = user;

  /* take a given domain, and lookup the dom_dir, uid, gid */
  if (vget_assign(domain, dom_dir, 156, &uid, &gid) == NULL) {
    fprintf(stderr, "failed to vget_assign the domain : %s", domain);
    return (-1);
  }

  if (vd) {
    ret = strlen(dom_dir) + 5 + strlen(dir) + strlen(user);
  } else {
    ret = strlen(dom_dir) + 5 + strlen(user);
  }

  b = (char *)safe_malloc(ret);

  memset((char *)b, 0, ret);

  if (vd) {
    snprintf(b, ret, "%s/%s/%s", dom_dir, dir, user);
  } else {
    snprintf(b, ret, "%s/%s", dom_dir, user);
  }

  dir = b;

  /* make an ldap connection (unless we already have one open) */
  if (ld == NULL) {
    if (ldap_connect() != 0) return -99;
  }

  lm = (LDAPMod **)safe_malloc(sizeof(LDAPMod *) * (NUM_LDAP_FIELDS + 1));

  for (i = 0; i < NUM_LDAP_FIELDS; ++i) {
    lm[i] = (LDAPMod *)safe_malloc(sizeof(LDAPMod));

    memset((LDAPMod *)lm[i], 0, sizeof(LDAPMod));
    lm[i]->mod_op = LDAP_MOD_ADD;
    lm[i]->mod_type = safe_strdup(ldap_fields[i]);
    lm[i]->mod_values = (char **)safe_malloc(sizeof(char *) * 2);
    lm[i]->mod_values[1] = NULL;
  }

  lm[NUM_LDAP_FIELDS] = NULL;

  /* lm[0] will store : uid / pw_name */
  lm[0]->mod_values[0] = safe_strdup(user);

  /* lm[1] will store : userPassword / pw_password */
  memset((char *)crypted, 0, 100);
  if (password[0] == 0) {
    crypted[0] = 0;
  } else {
    mkpasswd3(password, crypted, 100);
  }

  lm[1]->mod_values[0] = (char *)safe_malloc(strlen(crypted) + 7 + 1);
#ifdef MD5_PASSWORDS

  snprintf(lm[1]->mod_values[0], strlen(crypted) + 7 + 1, "{MD5}%s", crypted);
#else

  snprintf(lm[1]->mod_values[0], strlen(crypted) + 7 + 1, "{crypt}%s", crypted);
#endif

  /* lm[2] will store : qmailUID / pw_uid */
  lm[2]->mod_values[0] = (char *)safe_malloc(10);
  if (apop == USE_POP)
    sprintf(lm[2]->mod_values[0], "%d", 1);
  else
    sprintf(lm[2]->mod_values[0], "%d", 2);

  /* lm[3] will store : qmailGID / pw_gid */
  lm[3]->mod_values[0] = (char *)safe_malloc(10);
  sprintf(lm[3]->mod_values[0], "%d", 0);

  /* lm[4] will store : qmaildomain / pw_gecos */
  lm[4]->mod_values[0] = safe_strdup(gecos);

  /* lm[5] will store : mailMessageStore / pw_dir */
  lm[5]->mod_values[0] = safe_strdup(dir);

  /* lm[6] will store : mailQuota / pw_shell */
  lm[6]->mod_values[0] = safe_strdup("NOQUOTA");

  /* When running with clearpasswords enabled,
   * lm[7] will store : clearPassword / pw_clear_password
   */
#ifdef CLEAR_PASS
  /* with clear passwords,
   * lm[7] will store : clearPassword / pw_clear_password
   * lm[8] will store : objectclass
   */
  lm[7]->mod_values[0] = strdup(password);
  lm[8]->mod_values[0] = safe_strdup("qmailUser");
#else
  /* without clear passwords,
   * lm[7] will store : objectclass
   */
  lm[7]->mod_values[0] = safe_strdup("qmailUser");
#endif

  /* set dn_tmp to be of the format :
   *   ou=somedomain.com,o=vpopmail
   */
  if (compose_dn(&dn_tmp, domain) != 0) {
    for (i = 0; i < 8; ++i) {
      safe_free((void **)&lm[i]->mod_type);
      safe_free((void **)&lm[i]->mod_values[0]);
    }
    safe_free((void **)&lm);
    safe_free((void **)&dn);
    return -98;
  }

  /* set dn to be of the format :
   *   uid=someuser, ou=somedomain,o=vpopmail
   */
  len = 4 + strlen(user) + 2 + strlen(VLDAP_BASEDN) + 4 + strlen(domain) + 1;
  dn = (char *)safe_malloc(len);
  memset((char *)dn, 0, len);
  snprintf(dn, len, "uid=%s, %s", user, dn_tmp);
  safe_free((void **)&dn_tmp);

  /* add object to ldap
   *   dn is the DN of the entry to add
   *   lm is the attributes of the entry to add
   */
  ret = ldap_add_ext_s(ld, dn, lm, NULL, NULL);
  safe_free((void **)&dn);

  for (i = 0; i < NUM_LDAP_FIELDS; ++i) {
    safe_free((void **)&lm[i]->mod_type);
    safe_free((void **)&lm[i]->mod_values[0]);
  }

  safe_free((void **)&lm);

  if (ret != LDAP_SUCCESS) {
    fprintf(stderr, "%s\n", ldap_err2string(ret));
    if (ret == LDAP_ALREADY_EXISTS) return VA_USERNAME_EXISTS;
    return -99;
  }
  return VA_SUCCESS;
}

/***************************************************************************/

int vauth_adddomain(char *domain) {
  int ret = 0;
  char *dn = NULL;
  LDAPMod **lm = NULL;

  /* make a connection to the ldap server, if we are not already connected */
  if (ld == NULL) {
    ret = ldap_connect();
    if (ret != 0) {
      return -99;
      /* Attention I am not quite shure, when we return NULL or -99, see above
       */
    }
  }

  lm = (LDAPMod **)safe_malloc(sizeof(LDAPMod *) * 3);

  lm[0] = (LDAPMod *)safe_malloc(sizeof(LDAPMod));

  lm[1] = (LDAPMod *)safe_malloc(sizeof(LDAPMod));
  lm[2] = NULL;

  memset((LDAPMod *)lm[0], 0, sizeof(LDAPMod));
  memset((LDAPMod *)lm[1], 0, sizeof(LDAPMod));

  lm[0]->mod_op = LDAP_MOD_ADD;
  lm[1]->mod_op = LDAP_MOD_ADD;

  lm[0]->mod_type = safe_strdup("ou");
  lm[1]->mod_type = safe_strdup("objectclass");

  lm[0]->mod_values = (char **)safe_malloc(sizeof(char *) * 2);
  lm[1]->mod_values = (char **)safe_malloc(sizeof(char *) * 2);

  lm[0]->mod_values[1] = NULL;
  lm[1]->mod_values[1] = NULL;

  lm[0]->mod_values[0] = safe_strdup(domain);
  lm[1]->mod_values[0] = safe_strdup("organizationalUnit");

  /* set dn to be of the format :
   *   ou=somedomain.com,o=vpopmail
   */
  if (compose_dn(&dn, domain) != 0) {
    safe_free((void **)&lm[0]->mod_type);
    safe_free((void **)&lm[1]->mod_type);
    safe_free((void **)&lm[0]->mod_values[0]);
    safe_free((void **)&lm[1]->mod_values[0]);
    safe_free((void **)&lm[1]);
    safe_free((void **)&lm[0]);
    safe_free((void **)&lm);
    return -98;
  }

  /* dn will be ou=somedomain.com,o=vpopmail
   * lm will be the ldap propoerties of somedomain.com
   */
  ret = ldap_add_ext_s(ld, dn, lm, NULL, NULL);

  if (ret != LDAP_SUCCESS) {
    fprintf(stderr, "%s\n", ldap_err2string(ret));
    return -99;
  }

  safe_free((void **)&dn);
  safe_free((void **)&lm[0]->mod_type);
  safe_free((void **)&lm[1]->mod_type);
  safe_free((void **)&lm[0]->mod_values[0]);
  safe_free((void **)&lm[1]->mod_values[0]);
  safe_free((void **)&lm[2]);
  safe_free((void **)&lm[1]);
  safe_free((void **)&lm[0]);
  safe_free((void **)&lm);

  if (ret != LDAP_SUCCESS) {
    if (ret == LDAP_ALREADY_EXISTS) return VA_USERNAME_EXISTS;
    return -99;
  }

  return VA_SUCCESS;
}

/***************************************************************************/

int vauth_deldomain(char *domain) {
  int ret = 0;
  size_t len = 0;
  char *dn = NULL;
  struct vqpasswd *pw = NULL;

  /* make a connection to the ldap server, if we dont have one already */
  if (ld == NULL) {
    if (ldap_connect() != 0) return -99;
  }

  len = strlen(domain) + strlen(VLDAP_BASEDN) + 4 + 1;

  /* dn will be of the format :
   *   ou=somedomain.com,o=vpopmail
   */
  if (compose_dn(&dn, domain) != 0) return -98;

  /* loop through all the users in the domain, deleting each one */
  for (pw = vauth_getall(domain, 1, 0); pw; pw = vauth_getall(domain, 0, 0))
    vauth_deluser(pw->pw_name, domain);

  /* next, delete the actual domain */
  ret = ldap_delete_ext_s(ld, dn, NULL, NULL);
  safe_free((void **)&dn);

  if (ret != LDAP_SUCCESS) {
    fprintf(stderr, "%s\n", ldap_err2string(ret));
    return -99;
  }

#ifdef VALIAS
  valias_delete_domain(domain);
#endif

  return VA_SUCCESS;
}

/***************************************************************************/

int vauth_vpasswd(char *user, char *domain, char *crypted, int apop) {
  int ret = 0;
  struct vqpasswd *pw = NULL;

  pw = vauth_getpw(user, domain);
  if (pw == NULL) return VA_USER_DOES_NOT_EXIST;

  pw->pw_passwd = safe_strdup(crypted);

  ret = vauth_setpw(pw, domain);

  return ret;
}

/***************************************************************************/

int vauth_deluser(char *user, char *domain) {
  int ret = 0;
  size_t len = 0;
  char *dn = NULL;
  char *dn_tmp = NULL;

  /* make a connection to the ldap server if we dont have one already */
  if (ld == NULL) {
    if (ldap_connect() != 0) return -99;
  }

  len = 4 + strlen(user) + 2 + strlen(VLDAP_BASEDN) + 4 + strlen(domain) + 1;

  /* make dn_tmp to be of the format
   *  ou=somedomain.com,o=vpopmail
   */
  if (compose_dn(&dn_tmp, domain) != 0) return -98;

  dn = (char *)safe_malloc(len);
  memset((char *)dn, 0, len);

  /* make dn to be of the format
   *   uid=someuser, ou=somedomain.com,o=vpopmail
   */
  snprintf(dn, len, "uid=%s, %s", user, dn_tmp);
  safe_free((void **)&dn_tmp);

  /* delete the user */
  ret = ldap_delete_ext_s(ld, dn, NULL, NULL);

  safe_free((void **)&dn);

  if (ret != LDAP_SUCCESS) {
    fprintf(stderr, "%s\n", ldap_err2string(ret));
    return -99;
  }

  return VA_SUCCESS;
}

/***************************************************************************/

int vauth_setquota(char *username, char *domain, char *quota) {
  int ret = 0;
  struct vqpasswd *pw = NULL;

  if (strlen(username) > MAX_PW_NAME) return (VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR

  if (strlen(username) == 1) return (VA_ILLEGAL_USERNAME);
#endif

  if (strlen(domain) > MAX_PW_DOMAIN) return (VA_DOMAIN_NAME_TOO_LONG);
  if (strlen(quota) > MAX_PW_QUOTA) return (VA_QUOTA_TOO_LONG);

  pw = vauth_getpw(username, domain);
  if ((pw == NULL) && (verrori != 0))
    return verrori;
  else if (pw == NULL)
    return VA_USER_DOES_NOT_EXIST;

  pw->pw_shell = safe_strdup(quota);

  ret = vauth_setpw(pw, domain);

  return ret;
}

/***************************************************************************/

int vauth_setpw(struct vqpasswd *inpw, char *domain) {
  int ret = 0;
  size_t len = 0;
  char *dn = NULL;
  char *dn_tmp = NULL;
  LDAPMod **lm = NULL;
  int i;
#ifdef SQWEBMAIL_PASS

  uid_t uid;
  gid_t gid;
#endif

#ifdef USE_ONCHANGE
  char user_domain[MAX_BUFF];
#endif

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", inpw->pw_name, domain);
  on_change("mod_user", user_domain, "-", 0, 0);
#endif

  ret = vcheck_vqpw(inpw, domain);
  if (ret != 0) {
    return (ret);
  }

  if (ld == NULL) {
    if (ldap_connect() != 0) return -99;
  }

  lm = (LDAPMod **)malloc(sizeof(LDAPMod *) * NUM_LDAP_FIELDS + 1);
  for (i = 0; i < NUM_LDAP_FIELDS; ++i) {
    lm[i] = (LDAPMod *)safe_malloc(sizeof(LDAPMod));
    memset((LDAPMod *)lm[i], 0, sizeof(LDAPMod));
    lm[i]->mod_op = LDAP_MOD_REPLACE;
    lm[i]->mod_values = (char **)safe_malloc(sizeof(char *) * 2);
    lm[i]->mod_values[1] = NULL;
    lm[i]->mod_type = safe_strdup(ldap_fields[i]);
  }
  lm[NUM_LDAP_FIELDS] = NULL;

  lm[0]->mod_values[0] = safe_strdup(inpw->pw_name);

  lm[1]->mod_values[0] = safe_malloc(strlen(inpw->pw_passwd) + 7 + 1);
#ifdef MD5_PASSWORDS

  snprintf(lm[1]->mod_values[0], strlen(inpw->pw_passwd) + 7 + 1, "{MD5}%s",
           inpw->pw_passwd);
#else

  snprintf(lm[1]->mod_values[0], strlen(inpw->pw_passwd) + 7 + 1, "{crypt}%s",
           inpw->pw_passwd);
#endif

  lm[2]->mod_values[0] = (char *)safe_malloc(10);
  sprintf(lm[2]->mod_values[0], "%d", inpw->pw_uid);

  lm[3]->mod_values[0] = (char *)safe_malloc(10);
  sprintf(lm[3]->mod_values[0], "%d", inpw->pw_gid);

  if (inpw->pw_gecos == NULL) {
    lm[4]->mod_values[0] = safe_strdup("");
  } else {
    lm[4]->mod_values[0] = safe_strdup(inpw->pw_gecos);
  }
  lm[5]->mod_values[0] = safe_strdup(inpw->pw_dir);
  lm[6]->mod_values[0] = safe_strdup(inpw->pw_shell);
#ifdef CLEAR_PASS

  lm[7]->mod_values[0] = safe_strdup(inpw->pw_clear_passwd);
#endif

  lm[NUM_LDAP_FIELDS - 1]->mod_values[0] = strdup("qmailUser");

  if (compose_dn(&dn_tmp, domain) != 0) {
    safe_free((void **)&lm);
    return -98;
  }

  len = 4 + strlen(inpw->pw_name) + 2 + strlen(VLDAP_BASEDN) + 4 +
        strlen(domain) + 1;
  dn = (char *)safe_malloc(len);
  memset((char *)dn, 0, len);

  snprintf(dn, len, "uid=%s, %s", inpw->pw_name, dn_tmp);

  ret = ldap_modify_ext_s(ld, dn, lm, NULL, NULL);
  safe_free((void **)&dn);

  for (i = 0; i < NUM_LDAP_FIELDS; ++i) safe_free((void **)&lm);

  if (ret != LDAP_SUCCESS) {
    fprintf(stderr, "%s\n", ldap_err2string(ret));
    return -99;
  }
  /* MARK */
#ifdef SQWEBMAIL_PASS
  vget_assign(domain, NULL, 0, &uid, &gid);
  vsqwebmail_pass(inpw->pw_dir, inpw->pw_passwd, uid, gid);
#endif

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", inpw->pw_name, domain);
  on_change("mod_user", user_domain, "-", 1, 1);
#endif

  return VA_SUCCESS;
}

/***************************************************************************/

/*   Verify the connection to the authentication database   */

int vauth_open(int will_update) {
#ifdef VPOPMAIL_DEBUG
  show_trace = (getenv("VPSHOW_TRACE") != NULL);
  show_query = (getenv("VPSHOW_QUERY") != NULL);
  dump_data = (getenv("VPDUMP_DATA") != NULL);
#endif

#ifdef VPOPMAIL_DEBUG
  if (show_trace) {
    fprintf(stderr, "vauth_open()\n");
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

  return (0);
}

/***************************************************************************/

void vclose(void) {
  if (ld) {
    ldap_unbind_ext_s(ld, NULL, NULL);
    ld = NULL;
  }
}

/***************************************************************************/

char *dc_filename(char *domain, uid_t uid, gid_t gid) {
  static char dir_control_file[MAX_DIR_NAME];
  struct passwd *pw;

  /* if we are lucky the domain is in the assign file */
  if (vget_assign(domain, dir_control_file, MAX_DIR_NAME, NULL, NULL) != NULL) {
    strncat(dir_control_file, "/.dir-control",
            MAX_DIR_NAME - strlen(dir_control_file) - 1);

    /* it isn't in the assign file so we have to get it from /etc/passwd */
  } else {
    /* save some time if this is the vpopmail user */
    if (uid == VPOPMAILUID) {
      strncpy(dir_control_file, VPOPMAILDIR, MAX_DIR_NAME);

      /* for other users, look them up in /etc/passwd */
    } else if ((pw = getpwuid(uid)) != NULL) {
      strncpy(dir_control_file, pw->pw_dir, MAX_DIR_NAME);

      /* all else fails return a blank string */
    } else {
      return ("");
    }

    /* stick on the rest of the path */
    strncat(dir_control_file, "/" DOMAINS_DIR "/.dir-control",
            MAX_DIR_NAME - strlen(dir_control_file) - 1);
  }
  return (dir_control_file);
}

int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid) {
  FILE *fs;
  char dir_control_file[MAX_DIR_NAME];
  int i;

  strncpy(dir_control_file, dc_filename(domain, uid, gid), MAX_DIR_NAME);

  if ((fs = fopen(dir_control_file, "r")) == NULL) {
    vdir->cur_users = 0;
    for (i = 0; i < MAX_DIR_LEVELS; ++i) {
      vdir->level_start[i] = 0;
      vdir->level_end[i] = MAX_DIR_LIST - 1;
      vdir->level_index[i] = 0;
    }
    vdir->level_mod[0] = 0;
    vdir->level_mod[1] = 2;
    vdir->level_mod[2] = 4;
    vdir->level_cur = 0;
    vdir->level_max = MAX_DIR_LEVELS;
    vdir->the_dir[0] = 0;
    return (-1);
  }

  fgets(dir_control_file, MAX_DIR_NAME, fs);
  vdir->cur_users = atol(dir_control_file);

  fgets(dir_control_file, MAX_DIR_NAME, fs);
  vdir->level_cur = atoi(dir_control_file);

  fgets(dir_control_file, MAX_DIR_NAME, fs);
  vdir->level_max = atoi(dir_control_file);

  fgets(dir_control_file, MAX_DIR_NAME, fs);
  vdir->level_start[0] = atoi(dir_control_file);
  for (i = 0; dir_control_file[i] != ' '; ++i)
    ;
  ++i;
  vdir->level_start[1] = atoi(&dir_control_file[i]);
  for (i = 0; dir_control_file[i] != ' '; ++i)
    ;
  ++i;
  vdir->level_start[2] = atoi(&dir_control_file[i]);

  fgets(dir_control_file, MAX_DIR_NAME, fs);
  vdir->level_end[0] = atoi(dir_control_file);
  for (i = 0; dir_control_file[i] != ' '; ++i)
    ;
  ++i;
  vdir->level_end[1] = atoi(&dir_control_file[i]);
  for (i = 0; dir_control_file[i] != ' '; ++i)
    ;
  ++i;
  vdir->level_end[2] = atoi(&dir_control_file[i]);

  fgets(dir_control_file, MAX_DIR_NAME, fs);
  vdir->level_mod[0] = atoi(dir_control_file);
  for (i = 0; dir_control_file[i] != ' '; ++i)
    ;
  ++i;
  vdir->level_mod[1] = atoi(&dir_control_file[i]);
  for (i = 0; dir_control_file[i] != ' '; ++i)
    ;
  ++i;
  vdir->level_mod[2] = atoi(&dir_control_file[i]);

  fgets(dir_control_file, MAX_DIR_NAME, fs);
  vdir->level_index[0] = atoi(dir_control_file);
  for (i = 0; dir_control_file[i] != ' '; ++i)
    ;
  ++i;
  vdir->level_index[1] = atoi(&dir_control_file[i]);
  for (i = 0; dir_control_file[i] != ' '; ++i)
    ;
  ++i;
  vdir->level_index[2] = atoi(&dir_control_file[i]);

  fgets(dir_control_file, MAX_DIR_NAME, fs);
  for (i = 0; dir_control_file[i] != 0; ++i) {
    if (dir_control_file[i] == '\n') {
      dir_control_file[i] = 0;
    }
  }

  fgets(dir_control_file, MAX_DIR_NAME, fs);
  for (i = 0; dir_control_file[i] != 0; ++i) {
    if (dir_control_file[i] == '\n') {
      dir_control_file[i] = 0;
    }
  }
  strncpy(vdir->the_dir, dir_control_file, MAX_DIR_NAME);

  fclose(fs);

  return (0);
}

int vwrite_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid) {
  FILE *fs;
  int r;
  char dir_control_file[MAX_DIR_NAME];
  char dir_control_tmp_file[MAX_DIR_NAME];

  strncpy(dir_control_file, dc_filename(domain, uid, gid), MAX_DIR_NAME);
  r = snprintf(dir_control_tmp_file, MAX_DIR_NAME, "%s.%d", dir_control_file,
               getpid());
  if (r == -1) {
    return (-1);
  }

  if ((fs = fopen(dir_control_tmp_file, "w+")) == NULL) {
    return (-1);
  }

  fprintf(fs, "%lu\n", vdir->cur_users);
  fprintf(fs, "%d\n", vdir->level_cur);
  fprintf(fs, "%d\n", vdir->level_max);
  fprintf(fs, "%d %d %d\n", vdir->level_start[0], vdir->level_start[1],
          vdir->level_start[2]);
  fprintf(fs, "%d %d %d\n", vdir->level_end[0], vdir->level_end[1],
          vdir->level_end[2]);
  fprintf(fs, "%d %d %d\n", vdir->level_mod[0], vdir->level_mod[1],
          vdir->level_mod[2]);
  fprintf(fs, "%d %d %d\n", vdir->level_index[0], vdir->level_index[1],
          vdir->level_index[2]);
  fprintf(fs, "%s\n", vdir->the_dir);

  fclose(fs);

  rename(dir_control_tmp_file, dir_control_file);

  chown(dir_control_file, uid, gid);

  return (0);
}

int vdel_dir_control(char *domain) {
  char dir_control_file[MAX_DIR_NAME];

  vget_assign(domain, dir_control_file, 156, NULL, NULL);
  strncat(dir_control_file, "/.dir-control",
          MAX_DIR_NAME - strlen(dir_control_file) - 1);
  return (unlink(dir_control_file));
}

/***************************************************************************/

#ifdef ENABLE_AUTH_LOGGING
int vset_lastauth_time(char *user, char *domain, char *remoteip,
                       time_t cur_time) {
  char *tmpbuf;
  FILE *fs;
  struct vqpasswd *vpw;
  struct utimbuf ubuf;
  uid_t uid;
  gid_t gid;

  if ((vpw = vauth_getpw(user, domain)) == NULL) return (0);

  tmpbuf = (char *)safe_malloc(MAX_BUFF);
  sprintf(tmpbuf, "%s/lastauth", vpw->pw_dir);
  if ((fs = fopen(tmpbuf, "w+")) == NULL) {
    safe_free((void **)&tmpbuf);
    return (-1);
  }
  fprintf(fs, "%s", remoteip);
  fclose(fs);
  ubuf.actime = cur_time;
  ubuf.modtime = cur_time;
  utime(tmpbuf, &ubuf);
  vget_assign(domain, NULL, 0, &uid, &gid);
  chown(tmpbuf, uid, gid);
  safe_free((void **)&tmpbuf);
  return (0);
}

int vset_lastauth(char *user, char *domain, char *remoteip) {
  return (vset_lastauth_time(user, domain, remoteip, time(NULL)));
}

time_t vget_lastauth(struct vqpasswd *pw, char *domain) {
  char *tmpbuf;
  struct stat mystatbuf;

  tmpbuf = (char *)safe_malloc(MAX_BUFF);
  sprintf(tmpbuf, "%s/lastauth", pw->pw_dir);
  if (stat(tmpbuf, &mystatbuf) == -1) {
    safe_free((void **)&tmpbuf);
    return (0);
  }
  safe_free((void **)&tmpbuf);
  return (mystatbuf.st_mtime);
}

char *vget_lastauthip(struct vqpasswd *pw, char *domain) {
  static char tmpbuf[MAX_BUFF];
  FILE *fs;

  snprintf(tmpbuf, MAX_BUFF, "%s/lastauth", pw->pw_dir);
  if ((fs = fopen(tmpbuf, "r")) == NULL) return (NULL);
  fgets(tmpbuf, MAX_BUFF, fs);
  fclose(fs);
  return (tmpbuf);
}
#endif /* ENABLE_AUTH_LOGGING */

/***************************************************************************/

#ifdef IP_ALIAS_DOMAINS
int vget_ip_map(char *ip, char *domain, int domain_size) {
  FILE *fs;
  char tmpbuf[156];
  char *tmpstr;

  if (ip == NULL || strlen(ip) <= 0) return (-1);

  /* open the ip_alias_map file */
  snprintf(tmpbuf, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
  if ((fs = fopen(tmpbuf, "r")) == NULL) return (-1);

  while (fgets(tmpbuf, 156, fs) != NULL) {
    tmpstr = strtok(tmpbuf, IP_ALIAS_TOKENS);
    if (tmpstr == NULL) continue;
    if (strcmp(ip, tmpstr) != 0) continue;

    tmpstr = strtok(NULL, IP_ALIAS_TOKENS);
    if (tmpstr == NULL) continue;
    strncpy(domain, tmpstr, domain_size);
    fclose(fs);
    return (0);
  }
  fclose(fs);
  return (-1);
}

/***************************************************************************/

/*
 * Add an ip to domain mapping
 * It will remove any duplicate entry before adding it
 *
 */
int vadd_ip_map(char *ip, char *domain) {
  FILE *fs;
  char tmpbuf[156];

  if (ip == NULL || strlen(ip) <= 0) return (-1);
  if (domain == NULL || strlen(domain) <= 0) return (-10);

  vdel_ip_map(ip, domain);

  snprintf(tmpbuf, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
  if ((fs = fopen(tmpbuf, "a+")) == NULL) return (-1);
  fprintf(fs, "%s %s\n", ip, domain);
  fclose(fs);

  return (0);
}

int vdel_ip_map(char *ip, char *domain) {
  FILE *fs;
  FILE *fs1;
  char file1[156];
  char file2[156];
  char tmpbuf[156];
  char tmpbuf1[156];
  char *ip_f;
  char *domain_f;

  if (ip == NULL || strlen(ip) <= 0) return (-1);
  if (domain == NULL || strlen(domain) <= 0) return (-1);

  snprintf(file1, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
  if ((fs = fopen(file1, "r")) == NULL) return (-1);

  snprintf(file2, 156, "%s/%s.%d", VPOPMAILDIR, IP_ALIAS_MAP_FILE, getpid());
  if ((fs1 = fopen(file2, "w")) == NULL) {
    fclose(fs);
    return (-1);
  }

  while (fgets(tmpbuf, 156, fs) != NULL) {
    strncpy(tmpbuf1, tmpbuf, 156);

    ip_f = strtok(tmpbuf, IP_ALIAS_TOKENS);
    if (ip_f == NULL) continue;

    domain_f = strtok(NULL, IP_ALIAS_TOKENS);
    if (domain_f == NULL) continue;

    if (strcmp(ip, ip_f) == 0 && strcmp(domain, domain_f) == 0) continue;

    fprintf(fs1, tmpbuf1);
  }
  fclose(fs);
  fclose(fs1);

  if (rename(file2, file1) < 0) return (-1);

  return (0);
}

int vshow_ip_map(int first, char *ip, char *domain) {
  static FILE *fs = NULL;
  char tmpbuf[156];
  char *tmpstr;

  if (ip == NULL) return (-1);
  if (domain == NULL) return (-1);

  if (first == 1) {
    if (fs != NULL) {
      fclose(fs);
      fs = NULL;
    }
    snprintf(tmpbuf, 156, "%s/%s", VPOPMAILDIR, IP_ALIAS_MAP_FILE);
    if ((fs = fopen(tmpbuf, "r")) == NULL) return (-1);
  }
  if (fs == NULL) return (-1);

  while (1) {
    if (fgets(tmpbuf, 156, fs) == NULL) {
      fclose(fs);
      fs = NULL;
      return (0);
    }

    tmpstr = strtok(tmpbuf, IP_ALIAS_TOKENS);
    if (tmpstr == NULL) continue;
    strcpy(ip, tmpstr);

    tmpstr = strtok(NULL, IP_ALIAS_TOKENS);
    if (tmpstr == NULL) continue;
    strcpy(domain, tmpstr);

    return (1);
  }
  return (-1);
}
#endif

/***************************************************************************/

/* take a given domain, and set dn to be a string of this format :
 * ou=somedomain,o=vpopmail
 */
int compose_dn(char **dn, char *domain) {
  size_t len = 0;

  len = strlen(domain) + strlen(VLDAP_BASEDN) + 5;

  *dn = (char *)safe_malloc(len);
  memset((char *)*dn, 0, len);

  snprintf(*dn, len, "ou=%s,%s", domain, VLDAP_BASEDN);

  return 0;
}

/***************************************************************************/

int ldap_connect() {
  char uri[1024];
  int ret = 0;
  struct berval creds;

  /* Set verror here and unset it when successful, is ok, because if one of
  these three steps fail the whole auth_connection failed */
  verrori = load_connection_info();
  if (verrori) return -1;

  snprintf(uri, 1024, "%s:%d", VLDAP_SERVER, VLDAP_PORT);
  ret = ldap_initialize(&ld, uri);
  if (ret != LDAP_SUCCESS) {
    fprintf(stderr, "%s\n", ldap_err2string(ret));
    return -99;
  }

  ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &ldapversion);
  if (ret != LDAP_OPT_SUCCESS) {
    fprintf(stderr, "Failed to set LDAP-Option\n");
    return -99;
  }

  creds.bv_val = VLDAP_PASSWORD;
  creds.bv_len = strlen(VLDAP_PASSWORD);
  ret = ldap_sasl_bind_s(ld, VLDAP_USER, LDAP_SASL_SIMPLE, &creds, NULL, NULL,
                         NULL);

  if (ret != LDAP_SUCCESS) {
    fprintf(stderr, "%s\n", ldap_err2string(ret));
    return (VA_NO_AUTH_CONNECTION);
  }

  verrori = 0;
  return VA_SUCCESS;
}

/***************************************************************************/

void safe_free(void **p) {
  if (*p) {
    free(*p);
    *p = 0;
  }
}

/***************************************************************************/

char *safe_strdup(const char *s) {
  char *p;
  size_t l;

  if (!s || !*s) return 0;
  l = strlen(s) + 1;
  p = (char *)safe_malloc(l);
  memcpy(p, s, l);
  return (p);
}

/***************************************************************************/

void *safe_malloc(size_t siz) {
  void *p;

  if (siz == 0) return 0;
  if ((p = (void *)malloc(siz)) == 0) {
    printf("No more memory...exiting\n");
    exit(1);
  }
  return (p);
}

/***************************************************************************/

int vauth_crypt(char *user, char *domain, char *clear_pass,
                struct vqpasswd *vpw) {
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

/***************************************************************************/

#ifdef VALIAS
struct linklist *valias_current = NULL;

/************************************************************************/
char *valias_select(char *alias, char *domain) {
  int err, len, ret, i = 0;
  char filter[512] = {0}, dn[512] = {0};
  struct linklist *temp_entry = NULL;
  LDAPMessage *res = NULL, *msg = NULL;
  char **aa = NULL, **di = NULL, *fields[] = {"aa", "di", NULL}, *p = NULL;

  /* remove old entries as necessary */
  while (valias_current != NULL) valias_current = linklist_del(valias_current);

  if (ld == NULL) {
    err = ldap_connect();
    if (err) return NULL;
  }

  memset(filter, 0, sizeof(filter));
  snprintf(filter, sizeof(filter), "(aa=%s@%s)",
           strcasecmp(alias, domain) ? alias : "*", domain);

  memset(dn, 0, sizeof(dn));
  snprintf(dn, sizeof(dn), "ou=valias,%s", VLDAP_BASEDN);

  ret = ldap_search_s(ld, dn, LDAP_SCOPE_SUBTREE, filter, fields, 0, &res);

  if (ret != LDAP_SUCCESS) {
    ldap_perror(ld, "Error");
    return NULL;
  }

  /* grab a pointer to the 1st entry in the chain of search results */
  msg = ldap_first_entry(ld, res);
  if (msg == NULL) {
    /* We had an error grabbing the pointer */
    return NULL;
  }

  /* find out how many matches we found */
  ret = ldap_count_entries(ld, msg);
  if (ret == -1) {
    /* an error occurred when counting the entries */
    ldap_perror(ld, "Error");
    ldap_msgfree(res);
    return NULL;
  }

  while (msg) {
    aa = ldap_get_values(ld, msg, "aa");
    if (aa == NULL) {
      fprintf(stderr, "vldap: warning: no address entry\n");
      msg = ldap_next_entry(ld, msg);
      continue;
    }

    di = ldap_get_values(ld, msg, "di");
    if (di == NULL) {
      fprintf(stderr, "vldap: warning: no delivery entries for '%s'\n", *aa);
      ldap_value_free(aa);
      msg = ldap_next_entry(ld, msg);
      continue;
    }

    for (p = *aa; *p; p++) {
      if (*p == '@') {
        *p = '\0';
        break;
      }
    }

    for (i = 0; di[i]; i++) {
      temp_entry = linklist_add(temp_entry, di[i], "");
      if (valias_current == NULL) valias_current = temp_entry;
    }

    ldap_value_free(aa);
    ldap_value_free(di);
    msg = ldap_next_entry(ld, msg);
  }

  if (valias_current == NULL)
    return NULL; /* no results */
  else {
    ldap_msgfree(res);
    return (valias_current->data);
  }
}

/************************************************************************/
char *valias_select_next() {
  if (valias_current == NULL) return NULL;

  valias_current = linklist_del(valias_current);

  if (valias_current == NULL)
    return NULL;
  else
    return valias_current->data;
}

/************************************************************************/
int valias_insert(char *alias, char *domain, char *alias_line) {
  int err, ret = 0, mod = LDAP_MOD_ADD, i = 0;
  LDAPMessage *msg = NULL, *res = NULL;
  LDAPMod **lm = NULL;
  char filter[512] = {0}, dn[512] = {0}, *fields[] = {"aa", NULL},
       ud[512] = {0};

#ifdef USE_ONCHANGE
  char user_domain[MAX_BUFF];
#endif

  if (ld == NULL) {
    if ((err = ldap_connect()) != 0) return (err);
  }

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_insert", user_domain, alias_line, 0, 0);
#endif

  while (*alias_line == ' ' && *alias_line != 0) ++alias_line;

  memset(ud, 0, sizeof(ud));
  snprintf(ud, sizeof(ud), "%s@%s", alias, domain);

  /*
           Check for existing entry to determine LDAP modification
           type
*/

  memset(dn, 0, sizeof(dn));
  snprintf(dn, sizeof(dn), "ou=valias,%s", VLDAP_BASEDN);

  memset(filter, 0, sizeof(filter));
  snprintf(filter, sizeof(filter), "aa=%s", ud);

  ret = ldap_search_s(ld, dn, LDAP_SCOPE_SUBTREE, filter, fields, 0, &res);

  if (ret != LDAP_SUCCESS) {
    ldap_perror(ld, "Error");
    return -1;
  }

  msg = ldap_first_entry(ld, res);

  if (msg == NULL)
    mod = LDAP_MOD_ADD;
  else
    mod = LDAP_MOD_REPLACE;

  ldap_msgfree(res);

  memset(dn, 0, sizeof(dn));
  snprintf(dn, sizeof(dn), "aa=%s,ou=valias,%s", ud, VLDAP_BASEDN);

  lm = malloc(sizeof(LDAPMod *) * 4);
  if (lm == NULL) {
    fprintf(stderr, "vldap: malloc failed\n");
    return -1;
  }

  for (i = 0; i < 3; i++) {
    lm[i] = malloc(sizeof(LDAPMod));
    if (lm[i] == NULL) {
      fprintf(stderr, "vldap: malloc failed\n");
      return -1;
    }

    memset(lm[i], 0, sizeof(LDAPMod));

    lm[i]->mod_op = mod;
    lm[i]->mod_values = malloc(sizeof(char *) * 2);
    lm[i]->mod_values[0] = NULL;
    lm[i]->mod_values[1] = NULL;
  }

  lm[0]->mod_type = safe_strdup("objectClass");
  lm[0]->mod_values[0] = safe_strdup("valias");

  lm[1]->mod_type = safe_strdup("aa");
  lm[1]->mod_values[0] = safe_strdup(ud);

  lm[2]->mod_op = LDAP_MOD_ADD;
  lm[2]->mod_type = safe_strdup("di");
  lm[2]->mod_values[0] = safe_strdup(alias_line);

  lm[3] = NULL;

  if (mod == LDAP_MOD_ADD)
    ret = ldap_add_s(ld, dn, lm);
  else
    ret = ldap_modify_s(ld, dn, lm);

  for (i = 0; i < 3; i++) {
    free(lm[i]->mod_type);
    free(lm[i]->mod_values[1]);
    free(lm[i]);
  }

  free(lm);

  if (ret != LDAP_SUCCESS) {
    ldap_perror(ld, "Error");
    return -1;
  }

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_insert", user_domain, alias_line, 1, 1);
#endif

  return (0);
}

/************************************************************************/
int valias_remove(char *alias, char *domain, char *alias_line) {
  int err, ret = 0, i = 0;
  LDAPMod **lm = NULL;
  LDAPMessage *res = NULL, *msg = NULL;
  char **di = NULL, *fields[] = {"di", NULL};
  char ud[512] = {0}, dn[512] = {0}, filter[512] = {0};

#ifdef USE_ONCHANGE
  char user_domain[MAX_BUFF];
#endif

  if ((err = ldap_connect()) != 0) return (err);

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_remove", user_domain, alias_line, 1, 0);
#endif

  memset(ud, 0, sizeof(ud));
  snprintf(ud, sizeof(ud), "%s@%s", alias, domain);

  memset(dn, 0, sizeof(dn));
  snprintf(dn, sizeof(dn), "aa=%s,ou=valias,%s", ud, VLDAP_BASEDN);

  lm = malloc(sizeof(LDAPMod *) * 2);
  if (lm == NULL) {
    fprintf(stderr, "vldap: malloc failed\n");
    return -1;
  }

  for (i = 0; i < 1; i++) {
    lm[i] = malloc(sizeof(LDAPMod));
    if (lm[i] == NULL) {
      fprintf(stderr, "vldap: malloc failed\n");
      return -1;
    }

    memset(lm[i], 0, sizeof(LDAPMod));

    lm[i]->mod_op = LDAP_MOD_DELETE;
    lm[i]->mod_values = malloc(sizeof(char *) * 2);
    lm[i]->mod_values[0] = NULL;
    lm[i]->mod_values[1] = NULL;
  }

  lm[0]->mod_type = safe_strdup("di");
  lm[0]->mod_values[0] = safe_strdup(alias_line);

  lm[1] = NULL;

  ret = ldap_modify_s(ld, dn, lm);

  for (i = 0; i < 1; i++) {
    free(lm[i]->mod_type);
    free(lm[i]->mod_values[0]);
    free(lm[i]);
  }

  free(lm);

  if (ret != LDAP_SUCCESS) {
    ldap_perror(ld, "Error");
    return -1;
  }

  /*
      If there are no delivery instructions left, delete
          entry entirely
*/

  memset(dn, 0, sizeof(dn));
  snprintf(dn, sizeof(dn), "ou=valias,%s", VLDAP_BASEDN);

  memset(filter, 0, sizeof(filter));
  snprintf(filter, sizeof(filter), "aa=%s", ud);

  ret = ldap_search_s(ld, dn, LDAP_SCOPE_SUBTREE, filter, fields, 0, &res);
  if (ret != LDAP_SUCCESS) {
    ldap_perror(ld, "Error");
    return -1;
  }

  msg = ldap_first_entry(ld, res);
  if (msg == NULL) {
    ldap_perror(ld, "Error");
    return -1;
  }

  ret = ldap_count_entries(ld, msg);
  if (ret == -1) {
    ldap_perror(ld, "Error");
    return -1;
  }

  di = ldap_get_values(ld, msg, "di");
  if ((di == NULL) || (di[0] == NULL)) {
    if (di) ldap_value_free(di);

    ldap_msgfree(res);
    return valias_delete(alias, domain);
  }

  ldap_value_free(di);
  ldap_msgfree(res);

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_remove", user_domain, alias_line, 0, 1);
#endif

  return (0);
}

/************************************************************************/
int valias_delete(char *alias, char *domain) {
  int err, ret = 0;
  char ud[512] = {0}, dn[512] = {0};

#ifdef USE_ONCHANGE
  char user_domain[MAX_BUFF];
#endif

  if ((err = ldap_connect()) != 0) return (err);

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_delete", user_domain, "-", 1, 0);
#endif

  memset(ud, 0, sizeof(ud));
  snprintf(ud, sizeof(ud), "%s@%s", alias, domain);

  memset(dn, 0, sizeof(dn));
  snprintf(dn, sizeof(dn), "aa=%s,ou=valias,%s", ud, VLDAP_BASEDN);

  ret = ldap_delete_s(ld, dn);
  if (ret != LDAP_SUCCESS) {
    ldap_perror(ld, "Error");
    return -1;
  }

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_delete", user_domain, "-", 0, 1);
#endif

  return (0);
}

/************************************************************************/
int valias_delete_domain(char *domain) {
  int err, ret;
  char filter[512] = {0}, dn[512] = {0};
  LDAPMessage *res = NULL, *msg = NULL;
  char **aa = NULL, *fields[] = {"aa", NULL}, *p = NULL;

  if (ld == NULL) {
    err = ldap_connect();
    if (err) return 0;
  }

  memset(filter, 0, sizeof(filter));
  snprintf(filter, sizeof(filter), "aa=*@%s", domain);

  memset(dn, 0, sizeof(dn));
  snprintf(dn, sizeof(dn), "ou=valias,%s", VLDAP_BASEDN);

  ret = ldap_search_s(ld, dn, LDAP_SCOPE_SUBTREE, filter, fields, 0, &res);

  if (ret != LDAP_SUCCESS) {
    ldap_perror(ld, "Error");
    return 0;
  }

  msg = ldap_first_entry(ld, res);
  if (msg == NULL) {
    ldap_msgfree(res);
    return 0;
  }

  ret = ldap_count_entries(ld, msg);
  if (ret == -1) {
    ldap_perror(ld, "Error");
    ldap_msgfree(res);
    return 0;
  }

  while (msg) {
    aa = ldap_get_values(ld, msg, "aa");
    if (aa == NULL) {
      fprintf(stderr, "vldap: warning: no address entry\n");
      msg = ldap_next_entry(ld, msg);
      continue;
    }

    for (p = *aa; *p; p++) {
      if (*p == '@') {
        *p = '\0';
        break;
      }
    }

    ret = valias_delete(*aa, domain);
    if (ret == -1)
      fprintf(stderr,
              "vldap: valias_delete_domain: valias_delete(%s@%s) failed\n", *aa,
              domain);

    ldap_value_free(aa);
    msg = ldap_next_entry(ld, msg);
  }

  return (0);
}

/************************************************************************/
char *valias_select_all(char *alias, char *domain) {
  int err, len, ret, i = 0;
  char filter[512] = {0}, dn[512] = {0};
  struct linklist *temp_entry = NULL;
  LDAPMessage *res = NULL, *msg = NULL;
  char **aa = NULL, **di = NULL, *fields[] = {"aa", "di", NULL}, *p = NULL;

  if (ld == NULL) {
    err = ldap_connect();
    if (err) return NULL;
  }

  memset(filter, 0, sizeof(filter));
  snprintf(filter, sizeof(filter), "aa=%s@%s",
           strcasecmp(alias, domain) ? alias : "*", domain);

  memset(dn, 0, sizeof(dn));
  snprintf(dn, sizeof(dn), "ou=valias,%s", VLDAP_BASEDN);

  while (valias_current != NULL) valias_current = linklist_del(valias_current);

  ret = ldap_search_s(ld, dn, LDAP_SCOPE_SUBTREE, filter, fields, 0, &res);
  if (ret != LDAP_SUCCESS) {
    ldap_perror(ld, "Error");
    return NULL;
  }

  if (ldap_sort_entries(ld, &res, "aa", &strcasecmp) != 0) {
    ldap_perror(ld, "Error");
    return NULL;
  }

  msg = ldap_first_entry(ld, res);
  if (msg == NULL) {
    ldap_msgfree(res);
    return NULL;
  }

  ret = ldap_count_entries(ld, msg);
  if (ret == -1) {
    ldap_msgfree(res);
    ldap_perror(ld, "Error");
    return NULL;
  }

  while (msg) {
    aa = ldap_get_values(ld, msg, "aa");
    if (aa == NULL) {
      fprintf(stderr, "vldap: warning: no address entry\n");
      msg = ldap_next_entry(ld, msg);
      continue;
    }

    di = ldap_get_values(ld, msg, "di");
    if (di == NULL) {
      fprintf(stderr, "vldap: warning: no delivery entries for '%s'\n", *aa);
      ldap_value_free(aa);
      msg = ldap_next_entry(ld, msg);
      continue;
    }

    for (p = *aa; *p; p++) {
      if (*p == '@') {
        *p = '\0';
        break;
      }
    }

    for (i = 0; di[i]; i++) {
      temp_entry = linklist_add(temp_entry, di[i], *aa);
      if (valias_current == NULL) valias_current = temp_entry;
    }

    ldap_value_free(aa);
    ldap_value_free(di);
    msg = ldap_next_entry(ld, msg);
  }

  if (valias_current == NULL)
    return NULL; /* no results */
  else {
    ldap_msgfree(res);
    strcpy(alias, valias_current->d2);
    return (valias_current->data);
  }
}

/************************************************************************/
char *valias_select_all_next(char *alias) {
  if (valias_current == NULL) return NULL;
  valias_current = linklist_del(valias_current);

  if (valias_current == NULL)
    return NULL; /* no results */
  else {
    strcpy(alias, valias_current->d2);
    return (valias_current->data);
  }
}

/************************************************************************
 *
 *  valias_select_names
 */

char *valias_select_names(char *alias, char *domain) {
  int err, ret;
  char filter[512] = {0}, dn[512] = {0};
  struct linklist *temp_entry = NULL;
  LDAPMessage *res = NULL, *msg = NULL;
  char **aa = NULL, *fields[] = {"aa", NULL}, *p = NULL;

  if (ld == NULL) {
    err = ldap_connect();
    if (err) return NULL;
  }

  /*
         Passed via alias
  */

  domain = alias;

  memset(filter, 0, sizeof(filter));
  snprintf(filter, sizeof(filter), "aa=*@%s", domain);

  memset(dn, 0, sizeof(dn));
  snprintf(dn, sizeof(dn), "ou=valias,%s", VLDAP_BASEDN);

  while (valias_current != NULL) valias_current = linklist_del(valias_current);

  ret = ldap_search_s(ld, dn, LDAP_SCOPE_SUBTREE, filter, fields, 0, &res);
  if (ret != LDAP_SUCCESS) {
    ldap_perror(ld, "Error");
    return NULL;
  }

  if (ldap_sort_entries(ld, &res, "aa", &strcasecmp) != 0) {
    ldap_perror(ld, "Error");
    ldap_msgfree(res);
    return NULL;
  }

  msg = ldap_first_entry(ld, res);
  if (msg == NULL) {
    ldap_msgfree(res);
    return NULL;
  }

  ret = ldap_count_entries(ld, msg);
  if (ret == -1) {
    ldap_perror(ld, "Error");
    ldap_msgfree(res);
    return NULL;
  }

  while (msg) {
    aa = ldap_get_values(ld, msg, "aa");
    if (aa == NULL) {
      fprintf(stderr, "vldap: warning: no address entry\n");
      msg = ldap_next_entry(ld, msg);
      continue;
    }

    for (p = *aa; *p; p++) {
      if (*p == '@') {
        *p = '\0';
        break;
      }
    }

    temp_entry = linklist_add(temp_entry, *aa, *aa);
    if (valias_current == NULL) valias_current = temp_entry;

    ldap_value_free(aa);
    msg = ldap_next_entry(ld, msg);
  }

  if (valias_current == NULL)
    return NULL; /* no results */
  else {
    strcpy(alias, valias_current->d2);
    ldap_msgfree(res);
    return (valias_current->data);
  }
}

/************************************************************************
 *
 *  valias_select_names_next
 */

char *valias_select_names_next(char *alias) {
  if (valias_current == NULL) return NULL;
  valias_current = linklist_del(valias_current);

  if (valias_current == NULL)
    return NULL; /* no results */
  else {
    strcpy(alias, valias_current->d2);
    return (valias_current->data);
  }
}

/************************************************************************
 *
 *  valias_select_names_end
 */

void valias_select_names_end() {
  //  not needed by ldap
}

#endif
