/*
 * $Id: vchangepw.c 1014 2011-02-03 16:04:37Z volz0r $
 * Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
 *
 * Modified version of vpasswd created by Rolf Eike Beer, November 2003
 *
 * Usage Note: 
 * Set up another user account with this binary as shell. Then chmod
 * it to suid vpopmail. Now users can ssh to the box as this user and
 * change the password remote without asking anyone. If you only allow
 * logins via ssh the password wont be sent unencrypted.
 *
 * Copyright (C) 1999,2001 Inter7 Internet Technologies, Inc.
 * Copyright (C) 2003-2006 Rolf Eike Beer
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
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
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

int main(void)
{
	int i;
	struct vqpasswd *vpw = NULL;
	char Email[MAX_BUFF];
	char User[MAX_BUFF];
	char Domain[MAX_BUFF];
	char Passwd[128];	/* must be at least the size of the buffer in vpopmail.c::getpass */
	char *passwdtmp;

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

	memset(Passwd, 0, sizeof(Passwd));
	memset(Domain, 0, sizeof(Domain));
	memset(User, 0, sizeof(User));

	fputs("Please enter the email address: ", stdout);

	if (fgets(Email, sizeof(Email), stdin) == NULL) {
		puts("\n");
		return 0;	// exit, no address entered
	} else {
		i = strlen(Email) - 1;
		if (i >= 0 && (Email[i] == '\n' || Email[i] == '\r')) {
			Email[i] = '\0';
		} else {
			puts("\nError: email address too long");
			return 3;
		}
	}

	puts(Email);

	if ( (i = parse_email( Email, User, Domain, MAX_BUFF)) != 0 ) {
		fputs("Error: ", stdout);
		puts(verror(i));
		vexit(i);
	}

	openlog("vchangepw", 0, LOG_AUTH);

	passwdtmp = getpass("Enter old password: ");
	i = strlen(passwdtmp);
	if (i >= sizeof(Passwd)) {
		puts("Error: password too long.");
		syslog(LOG_NOTICE, "Too long password for user <%s>\n", Email);
		closelog();
		vexit(3);
	}
	strncpy(Passwd, passwdtmp, i + 1);

	if ( (vpw = vauth_getpw(User, Domain)) != NULL ) {
		vget_assign(Domain, NULL, 0, NULL, NULL);
		if ( vauth_crypt(User, Domain, Passwd, vpw) != 0 ) {
			puts("Error: authentication failed!");
			syslog(LOG_NOTICE, "Wrong password for user <%s>\n", Email);
			closelog();
			vexit(3);
		}
	} else {
		puts("Error: authentication failed!");
		syslog(LOG_NOTICE, "Domain of address <%s> does not exist\n", Email);
		closelog();
		vexit(3);
	}

	vgetpasswd(Email, Passwd, sizeof(Passwd));

	if ( (i = vpasswd( User, Domain, Passwd, USE_POP )) != 0 ) {
		printf("Error: %s\n", verror(i));
		syslog(LOG_NOTICE, "Error changing users password! User <%s>, message: ""%s""\n",
			Email, verror(i));
		vexit(i);
	} else {
		printf("Password successfully changed.\n");
		syslog(LOG_DEBUG, "User <%s> changed password\n", Email);
	}
	closelog();
	return vexit(i);
}
