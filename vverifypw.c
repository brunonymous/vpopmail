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

#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

int crypted_pass = 0;
char Email[MAX_BUFF];
char User[MAX_BUFF];
char Domain[MAX_BUFF];
char Passwd[MAX_BUFF];

void usage();
void get_options(int argc, char **argv);

int main(int argc, char **argv) {
  int i = 0;
  struct vqpasswd *vpw = NULL;
  char *passwdtmp = NULL;

  if (vauth_open(1)) {
    vexiterror(stderr, "Initial open.");
  }

  memset(Email, 0, sizeof(Email));
  memset(User, 0, sizeof(User));
  memset(Domain, 0, sizeof(Domain));
  memset(Passwd, 0, sizeof(Domain));

  get_options(argc, argv);

  if (strlen(Email) == 0) {
    fputs("Please enter the email address: ", stdout);
    if (fgets(Email, sizeof(Email), stdin) == NULL) {
      puts("\n");
      return -1;  // exit, no address entered
    } else {
      i = strlen(Email) - 1;
      if (i >= 0 && (Email[i] == '\n' || Email[i] == '\r')) {
        Email[i] = '\0';
      } else {
        puts("\nError: email address too long");
        vexit(-1);
      }
    }
  }

  if (strlen(Passwd) == 0) {
    passwdtmp = getpass("Enter password: ");
  } else {
    passwdtmp = Passwd;
  }

  if ((i = parse_email(Email, User, Domain, MAX_BUFF)) != 0) {
    fputs("Error: ", stdout);
    puts(verror(i));
    vexit(i);
  }

  if ((vpw = vauth_getpw(User, Domain)) != NULL) {
    vget_assign(Domain, NULL, 0, NULL, NULL);
    if (crypted_pass == 0) {
      if (vauth_crypt(User, Domain, passwdtmp, vpw) != 0) {
        puts("Error: authentication failed!");
        vexit(-1);
      }
    } else {
      if (strcmp(passwdtmp, vpw->pw_passwd) != 0) {
        puts("Error: authentication failed!");
        vexit(-1);
      }
    }
  } else {
    puts("Error: authentication failed!");
    vexit(-1);
  }

  puts("User authenticated.");

  return vexit(0);
}

void usage() {
  printf(
      "vverifypw: usage: [options] [email_addr] [password] (or empty to read "
      "from terminal)\n");
  printf("options: -h ( display usage )\n");
  printf("options: -v ( display the vpopmail version number )\n");
  printf("options: -e ( the password is already encrypted )\n");
}

void get_options(int argc, char **argv) {
  int c;
  extern int optind;

  crypted_pass = 0;
  while ((c = getopt(argc, argv, "hve")) != -1) {
    switch (c) {
      case 'h':
        usage();
        vexit(0);
        break;
      case 'v':
        printf("version: %s\n", VERSION);
        break;
      case 'e':
        crypted_pass = 1;
        break;
      default:
        usage();
        vexit(-1);
        break;
    }
  }

  if (optind < argc) {
    snprintf(Email, sizeof(Email), "%s", argv[optind]);
    ++optind;
  }

  if (optind < argc) {
    snprintf(Passwd, sizeof(Passwd), "%s", argv[optind]);
    ++optind;
  }
}
