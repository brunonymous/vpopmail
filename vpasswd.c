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

#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "config.h"
#include "vauth.h"
#include "vpopmail.h"

char Email[MAX_BUFF];
char User[MAX_BUFF];
char Domain[MAX_BUFF];
char Passwd[MAX_BUFF];
int apop;
int RandomPw;

void usage();
void get_options(int argc, char **argv);

int main(int argc, char *argv[]) {
  int i;

  if (vauth_open(1)) {
    vexiterror(stderr, "Initial open.");
  }

  get_options(argc, argv);

  if ((i = parse_email(Email, User, Domain, sizeof(User))) != 0) {
    printf("Error: %s\n", verror(i));
    vexit(i);
  }

  if (strlen(Passwd) <= 0) {
    vgetpasswd(Email, Passwd, sizeof(Passwd));
  }

  if ((i = vpasswd(User, Domain, Passwd, apop)) != 0) {
    printf("Error: %s\n", verror(i));
    vexit(i);
  }
  if (RandomPw) printf("Random password: %s\n", Passwd);
  return (vexit(0));
}

void usage() {
  printf("vpasswd: usage: [options] email_address [password]\n");
  printf("options: -v (print version number)\n");
  printf(
      "         -r[len] (generate a len (default 12) char random password)\n");
}

void get_options(int argc, char **argv) {
  int c;
  int errflag;
  extern int optind;
  extern char *optarg;

  memset(Email, 0, sizeof(Email));
  memset(Passwd, 0, sizeof(Passwd));
  memset(Domain, 0, sizeof(Domain));
  apop = USE_POP;
  RandomPw = 0;

  errflag = 0;
  while (!errflag && (c = getopt(argc, argv, "vr::")) != -1) {
    switch (c) {
      case 'v':
        printf("version: %s\n", VERSION);
        break;
      case 'r':
        RandomPw = 1;
        if (optarg) {
          int sz = atoi(optarg);
          if (sz > 128) {
            printf("Error: %s\n", verror(VA_PASSWD_TOO_LONG));
            vexit(VA_PASSWD_TOO_LONG);
          }
          vrandom_pass(Passwd, atoi(optarg));
        } else {
          vrandom_pass(Passwd, 12);
        }
        break;
      default:
        errflag = 1;
        break;
    }
  }

  if (optind < argc) {
    snprintf(Email, sizeof(Email), "%s", argv[optind]);
    ++optind;
  }

  if (optind < argc) {
    if (RandomPw == 0) {
      snprintf(Passwd, sizeof(Passwd), "%s", argv[optind]);
      ++optind;
    } else {
      printf(
          "Error: don't use -r option when giving password on command line\n");
      vexit(-1);
    }
  }

  if (Email[0] == 0) {
    usage();
    vexit(-1);
  }
}
