/*
 * vmakedotqmail v. 1.0.1 (Nov 11, 2023)
 * Roberto Puzzanghera - https://notes.sagredo.eu
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

/*
 * This program can be useful to create the user's .qmail file with the content of
 * control/defauldelivery. It can also handle domain's .qmail-default files.
 * Look at the documentation concerning the defaultdelivery feature in the
 * doc/README.defaultdelivery file or at the
 * https://notes.sagredo.eu/en/qmail-notes-185/installing-and-configuring-vpopmail-81.html
 * web page.
 *
 *
 * Usage: vmakedotqmail [option] [argument]
 *
 * options: -u <username@domain> install .qmail for the user <username@domain>
 *          -d <domain>          install .qmail for all users of domain <domain>
 *          -A                   install .qmail for all users of all domains
 *          -o (overwrite)       do not skip existing .qmail files. Use with -A|-d|-u
 *          -r (reverse)         remove the existing .qmail files. Use with -A|-d|-u
 *          -q                   reinstall the .qmail-default in domain -d <domain>
 *                               or in ALL domains (-A).
 *          -t (testing mode)    do not really open or write the .qmail
 *          -h                   this help
 *
 * Existing .qmail files won't be overwritten unless you pass -o
 *
 * Examples:
 *
 *       Install .qmail-default with vdelivermail (delete option) for domain 'domain.tld'
 *       vmakedotqmail -d domain.tld -q default
 *
 *       Install .qmail-default with your favourite LDA for all domains
 *       vmakedotqmail -A -q "My LDA instruction as quoted argument here"
 */

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include "config.h"
#include "vauth.h"
#include "vpopmail.h"

#define DOT_QMAIL_DEFAULT_OPTION "delete"
#define AUTH_SIZE 156
int overwriting = 0;
int reverse = 0;
int testing   = 0;
char *qValue = NULL;
char *dValue = NULL;


/**********************************************************
 * retrieve user's homedir
 *
 * user    = input username
 * domain  = input domain
 * homedir = output home directory
 *
 * @return   0 on success
 *          -1 on error
 **********************************************************/
int get_homedir(char *user, char *domain, char *homedir) {
  struct vqpasswd *mypw;
  if ((mypw = vauth_getpw(user, domain)) == NULL) {
    if (domain[0] == 0 || strlen(domain)==0) printf("no such domain %s\n", domain);
    else printf("no such user %s@%s\n", user, domain);
    vexit(-1);
  }
  snprintf(homedir, MAX_BUFF, "%s", mypw->pw_dir);

  return 0;
}


/*****************************************************************************************
 * create the .qmail file
 *
 * homedir = user's home directory where to save the .qmail file
 *
 * @return  0 on success
 *          1 skip, .qmail already exists
 *          2 .qmail already exists but overwriting
 *          3 .qmail removed
 *         -1 on error (missing control/defaultdelivery)
 *          VA_COULD_NOT_OPEN_DOT_QMAIL (-19) on .qmail read error
 *****************************************************************************************/
int make_dotqmail(char *homedir) {
  int overwritingFlag = 0;
  FILE *fs;
  char tmpbuf[MAX_BUFF];
  char ch, defaultdelivery_file[MAX_BUFF];
  FILE *defaultdelivery;

  // exit if control/defaultdelivery already has vdelivermail, to avoid vpopmail loop
  if (!reverse) {
    snprintf(defaultdelivery_file, sizeof(defaultdelivery_file), "%s/control/defaultdelivery", QMAILDIR);
    defaultdelivery = fopen(defaultdelivery_file, "r");
    while((fgets(tmpbuf, MAX_BUFF, defaultdelivery)!=NULL)) {
      if(strstr(tmpbuf, "vdelivermail")!=NULL) {
        return 4;
        break;
      }
    }
    rewind(defaultdelivery);
  }

  // build .qmail path
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/.qmail", homedir);
  // return if file exists already unless -r removing. Continue if overwriting is active
  if (access(tmpbuf, F_OK)==0 && !reverse) {
    // exit
    if (!overwriting) return 1;
    // continue if overwriting, but mark
    else overwritingFlag = 1;
  }

  // do not touch/remove nor fill the .qmail if testing
  if (testing) {
    if (overwritingFlag) return 2;
    else if (reverse) return 3;
    else return 0;
  }

  // if -r delete the .qmail
  if (reverse && remove(tmpbuf)==-1) {
    printf("Unable to remove %s\n", tmpbuf);
    exit -1;
  }
  else if (!reverse) {
    // open .qmail
    if ((fs = fopen(tmpbuf, "w+"))==NULL) {
      printf("Could not open %s\n", tmpbuf);
      vexit(VA_COULD_NOT_OPEN_DOT_QMAIL);
    }
    /* setup the permission of the .qmail file */
    chown(tmpbuf, VPOPMAILUID, VPOPMAILGID);
    chmod(tmpbuf, 0600);

    /* Copy the content of control/defaultdelivery into ~userhomedir/.qmail */
    snprintf(defaultdelivery_file, sizeof(defaultdelivery_file), "%s/control/defaultdelivery", QMAILDIR);
    defaultdelivery = fopen(defaultdelivery_file, "r");
    if(defaultdelivery == NULL)
    {
      printf("\nERROR: Missing %s/control/defaultdelivery file.\n", QMAILDIR);
      printf("To create a %s/control/defaultdelivery type:\n", QMAILDIR);
      printf("echo \"| %s/bin/vdelivermail '' delete\" > %s/control/defaultdelivery\n\n", VPOPMAILDIR, QMAILDIR);
      vexit(-1);
    }

    while ((ch = fgetc(defaultdelivery)) != EOF) fputc(ch, fs);

    fclose(defaultdelivery); // close control/defaultdelivery
    fclose(fs);              // close .qmail
  }

  if (overwritingFlag) return 2;
  else if (reverse) return 3;
  else return 0;
}


/**********************************************************
 * Rebuild the .qmail-default on each domain with the
 *
 * domain = input domain
 * option = - preferred LDA instruction
 *          - default (install vdelivermail with delete option)
 *
 * @return  0 on success
 *         -1 on error
 **********************************************************/
int make_dotqmail_default(char *domain) {
  FILE *fs;
  char tmpbuf[MAX_BUFF];
  char ldabuf[MAX_BUFF];
  char ch;
  char *realdomain = vget_assign(domain, NULL, 0, NULL, NULL); // path of real domain

  // the lda will be vdelivermail if -q default
  if (strcmp(qValue, "default")==0) snprintf(ldabuf, sizeof(ldabuf), "| %s/bin/vdelivermail '' %s", VPOPMAILDIR, DOT_QMAIL_DEFAULT_OPTION);
  else snprintf(ldabuf, sizeof(ldabuf), "%s", qValue);

  /* process domain */
  printf("%s: rewriting .qmail-default: \"%s\": ", domain, ldabuf);
  snprintf(tmpbuf, sizeof(tmpbuf), "%s/.qmail-default", realdomain);

  // do not rewrite the .qmail-default if testing
  if (testing) {
    printf("**TESTING**\n");
    return 0;
  }

  // open .qmail-default
  if ((fs = fopen(tmpbuf, "w+"))==NULL) {
    printf("Could not open %s\n", tmpbuf);
    return VA_COULD_NOT_OPEN_DOT_QMAIL;
  }
  /* setup the permission of the .qmail file */
  chown(tmpbuf, VPOPMAILUID, VPOPMAILGID);
  chmod(tmpbuf, 0600);

  // write the contents in .qmail-default
  fprintf(fs, "%s", ldabuf);

  // close .qmail-default
  fclose(fs);

  printf("DONE\n");

  return 0;
}


/**********************************************************
 * Make the job for a specific mailbox
 *
 * address = input email address
 *
 * @return  0 on success
 *         -1 on error
 **********************************************************/
int make_mailbox(char *address) {
  char user[AUTH_SIZE];
  char domain[AUTH_SIZE];
  char homedir[MAX_BUFF];
  int i;
  char *teststr = (testing) ? "**TESTING** " : "";

  memset (homedir, 0, MAX_BUFF);

  if( (parse_email(address, user, domain, AUTH_SIZE)) == 0 ) {
    if (domain[0] == 0 || strlen(domain)==0) {
      printf("missing domain\n");
      exit(-1);
    }
    // get user's home directory
    get_homedir(user, domain, homedir);
    // install qmail in user's home dir
    if ((i = make_dotqmail(homedir))==0) printf("%s%s DONE\n", teststr, address);
    else if (i == 4) printf("%s%s SKIP (control/defaultdelivery already has vdelivermail)\n", teststr, address);
    else if (i == 3) printf("%s%s REMOVED existing .qmail\n", teststr, address);
    else if (i == 2) printf("%s%s DONE (existing .qmail overwritten)\n", teststr, address);
    else if (i == 1) printf("%s%s SKIP (.qmail already exists)\n", teststr, address);
  }
  else exit(-1);

  return 0;
}


/**********************************************************
 * Make the job for all mailboxes of a specific domain
 *
 * domain  = input domain
 *
 * @return  0 on success
 *         -1 on error
 **********************************************************/
int make_domain(char *domain) {
  static struct vqpasswd *mypw;
  char address[AUTH_SIZE];
  int first = 1;
  domain_entry *entry;

  printf("==================================================================\n");
  printf("Domain: %s\n\n", domain);

  // id -d passed check if exists (check already done if -A)
  if (dValue) {
    entry = get_domain_entries(domain);
    // check if the domain exists
    if (entry == NULL) {
      if (verrori) {
        printf("Error: Can't get domain entries - %s\n", verror(verrori));
        exit(verrori);
      }
      else {
        printf("Error: Domain %s does not exist\n\n", domain);
        exit(-1);
      }
    }
  }

  // if -q was found make the .qmail-default
  if (qValue) make_dotqmail_default(domain);
  // else proceed to make the mailbox's .qmail
  else {
    while (mypw = vauth_getall(domain, first, 1)) {
      first = 0;
      // build the mailbox address
      sprintf(address, "%s@%s", mypw->pw_name, domain);
      make_mailbox(address);
    }
  }
  printf("==================================================================\n\n");
  return 0;
}


/**********************************************************
 * Make the job for all mailboxes of all domains
 *
 * @return  0 on success
 *         -1 on error
 **********************************************************/
int make_all_domains() {
  domain_entry *entry;
  entry = get_domain_entries("");

  if (entry == NULL) {
    printf("Something went wrong on domain_entry (err 51)\n");
    return -1;
  }
  while (entry) {
    /* we won't process domain aliases */
    if (!strcmp(entry->realdomain, entry->domain)) {
      /* process domain */
      make_domain(entry->domain);
    }
    else {
      printf("==================================================================\n");
      printf("SKIP domain: %s (alias of %s)\n", entry->domain, entry->realdomain);
      printf("==================================================================\n\n");
    }
    entry = get_domain_entries(NULL);
  }
  return 0;
}


void usage()
{
  printf("\n");
  printf("Usage: vmakedotqmail [option] [argument]\n\n");

  printf("options: -u <username@domain>  install .qmail for the user <username@domain>\n");
  printf("         -d <domain>           install .qmail for all users of domain <domain>\n");
  printf("         -A                    install .qmail for all users of all domains\n");
  printf("         -o (overwrite)        do not skip existing .qmail files. Use with -A|-d|-u\n");
  printf("         -r (reverse)          remove the existing .qmail files. Use with -A|-d|-u\n");
  printf("         -q [default|argument] reinstall the .qmail-default in domain -d <domain>\n");
  printf("                               or in ALL domains (-A).\n");
  printf("         -t (testing mode)     do not really open or write the .qmail\n");
  printf("         -h                    this help\n\n");

  printf("Existing .qmail files won't be overwritten unless you pass -o\n\n");

  printf("Examples:\n\n");

  printf("\tInstall control/defaultdelivery to .qmail of all mailboxes of all domain (overwrite -o active)\n");
  printf("\tvmakedotqmail -o -A\n\n");

  printf("\tInstall control/defaultdelivery to .qmail of user <username@domain> (skip if existing)\n");
  printf("\tvmakedotqmail -o -u <username@domain>\n\n");

  printf("\tInstall .qmail-default with vdelivermail (delete option) for domain 'domain.tld'\n");
  printf("\tvmakedotqmail -d domain.tld -q default\n\n");

  printf("\tInstall .qmail-default with vdelivermail (delete option) for domain 'domain.tld'\n");
  printf("\tvmakedotqmail -d domain.tld -q default\n\n");

  printf("\tInstall .qmail-default with your favourite LDA for all domains\n");
  printf("\tvmakedotqmail -A -q \"My LDA instruction as quoted argument here\"\n\n");
}


int make(int argc, char *argv[])
{
  int c;
  int errFlag = 0;
  int AFlag = 0;
  char *uValue = NULL;

  while((c=getopt(argc,argv,"aAu:d:q:orth")) != -1) {
    switch(c) {
      case 'a':
      case 'A':
        AFlag = 1;
        break;

      case 'd':
        dValue = optarg;
        break;

      case 'u':
        uValue = optarg;
        break;

      case 'q':
        qValue = optarg;
        break;

      case 'o':
        overwriting = 1;
        break;

      case 'r':
        reverse = 1;
        break;

      case 't':
        testing = 1;
        break;

      case 'h':
        errFlag = 1;
        break;

      default:
        errFlag = 1;
        break;
    }
  }

  if (errFlag) {
    usage();
    return -1;
  }

  if (qValue && !AFlag && !dValue) {
    printf("If using -q, always pass argument -d <domain> or -A (all)\n");
    usage();
    return -1;
  }

  if (AFlag) {
    dValue = NULL; // overwrites -d
    uValue = NULL; // overwrites -u
    return make_all_domains();
  }
  else if (dValue) {
    uValue = NULL; // overwrites -u
    return make_domain(dValue);
  }
  else if (uValue) return make_mailbox(uValue);
  else if (qValue == NULL) {
    usage();
    return -1;
  }
}


int main(int argc, char *argv[])
{
#ifndef DEFAULT_DELIVERY
  printf("\nPlease use option --enable-defaultdelivery at configure time\n\n");
  exit(-1);
#else
  exit(make(argc, argv));
#endif
}
