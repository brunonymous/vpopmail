/*
 * $Id: vldap.h 1014 2011-02-03 16:04:37Z volz0r $
 * Copyright (C) 2000-2009 Inter7 Internet Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License  
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* NOTE: From of vpopmail 5.4.15, LDAP connection info is stored in
   ~vpopmail/etc/vpopmail.ldap.  The format of the file is as follows:
   
   ldap server|ldap port|ldap user|ldap password|ldap basedn
   
   Comments (lines starting with '#') are allowed. 
   
   Port should be the actual port.
   
   For example:
   
   # This is the LDAP configuration file for vpopmail.
   localhost|389|cn=vpopmailuser, o=vpopmail|vpoppasswd|o=vpopmail
   
 */

int ldapversion = 3;

void *safe_malloc (size_t siz);
char *safe_strdup (const char *s);
void safe_free (void **p);
int ldap_connect ();
int compose_dn (char **dn, char *domain);

#ifndef VPOPMAIL_LDAP_H
#define VPOPMAIL_LDAP_H

char *VLDAP_SERVER;
int VLDAP_PORT = LDAP_PORT;
char *VLDAP_USER;
char *VLDAP_PASSWORD;
char *VLDAP_BASEDN;

static char *vldap_attrs[] = {
  "name",
  "uid",
  "qmailGID",
  "qmailUID",
  "qmaildomain",
  "userPassword",
  "mailQuota",
  "mailMessageStore",  
#ifdef CLEAR_PASS
  "clearPassword",
#endif
NULL
};
#endif
