/*
 * $Id: vlimits.c 1014 2011-02-03 16:04:37Z volz0r $
 * Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
 *
 * handle domain limits in both file format
 * Brian Kolaci <bk@galaxy.net>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#include "vlimits.h"

#define TOKENS " :\t\n\r"

void vdefault_limits (struct vlimits *limits)
{
    /* initialize structure */
    memset(limits, 0, sizeof(*limits));
    limits->maxpopaccounts = -1;
    limits->maxaliases = -1;
    limits->maxforwards = -1;
    limits->maxautoresponders = -1;
    limits->maxmailinglists = -1;

    /* // if this fails, we have the very basic limits above
    vlimits_read_limits_file(VLIMITS_DEFAULT_FILE, limits);*/
}

/* read in the limits file pointed contained in dir
 * parse the contents of the file and return result in a vlimits struct 
 */
int vlimits_read_limits_file(const char *dir, struct vlimits * limits)
{
    char buf[2048];
    char * s1;
    char * s2;
#if 0
    FILE * fs;
#endif
	ssize_t rret = 0;
	char *h = NULL, *t = NULL;
	int fd = 0, in_bytes = 0;

	fd = open(dir, O_RDONLY);
	if (fd == -1)
	   return -1;

	in_bytes = 0;
	h = t = buf;

    while(1) {
	   /*
		  Read any more available data if buffer is not full
		  and we haven't reached EOF
	   */

	  if ((fd != -1) && (in_bytes < sizeof(buf))) {
		 rret = read(fd, (buf + in_bytes), (sizeof(buf) - in_bytes));

		 /*
			EOF or error
		 */

		 if (rret < 1) {
			close(fd);
			fd = -1;

			/*
			   Error occurred
			*/

			if (rret == -1)
			   return -1;
		 }

		 else {
			in_bytes += rret;
			*(buf + in_bytes) = '\0';
		 }
	  }

	  /*
		 Find next line
	  */

	  for (; ((*h) && (h < (buf + in_bytes))); h++) {
		 if ((*h == '\r') || (*h == '\n'))
			break;
	  }

	  /*
		 No newline found
	  */

	  if ((*h != '\n') && (*h != '\r')) {
		 if (fd != -1) {
			/*
			   Out of space in buffer
			*/

			if (in_bytes >= sizeof(buf))
			   break;

			/*
			   Make space in buffer
			*/

			memmove(buf, t, (h - buf));
			in_bytes = (h - buf);
			h = t = buf;

			/*
			   ..and begin again
			*/

			continue;
		 }

		 /*
			Continue on and use remaining data then break out of loop
		 */

		 h = NULL;
	  }

	  else
		 *h++ = '\0';

	  /*
		 Hand data to parser
	  */

	  if ((*t) && (*t != '#')) {
		 /*
			Seperate name and value
		 */

		 for (s1 = s2 = t; *s2; s2++) {
			if ((*s2 == ' ') || (*s2 == '\t') || (*s2 == ':'))
			   break;
		 }

		 if (*s2) {
			*s2++ = '\0';

			while((*s2 == ' ') || (*s2 == '\t') || (*s2 == ':'))
			   s2++;
		 }

		 else
			s2 = NULL;

            if (!strcmp(s1, "maxpopaccounts")) {
                if (s2)
                limits->maxpopaccounts = atoi(s2);
            }

			else if (!strcmp(s1, "maxaliases")) {
                if (s2)
                limits->maxaliases = atoi(s2);
            }

			else if (!strcmp(s1, "maxforwards")) {
                if (s2)
                limits->maxforwards = atoi(s2);
            }

			else if (!strcmp(s1, "maxautoresponders")) {
                if (s2)
                limits->maxautoresponders = atoi(s2);
            }

			else if (!strcmp(s1, "maxmailinglists")) {
                if (s2)
                limits->maxmailinglists = atoi(s2);
            }

			else if (!strcmp(s1, "quota")) {
                if (s2)
                limits->diskquota = strtoll(s2, NULL, 10);
            }

			else if (!strcmp(s1, "maxmsgcount")) {
                if (s2)
                limits->maxmsgcount = strtoll(s2, NULL, 10);
            }

            if (!strcmp(s1, "default_quota")) {
                if (s2)
                limits->defaultquota = strtoll(s2, NULL, 10);
            }

			else if (!strcmp(s1, "default_maxmsgcount")) {
                if (s2)
                limits->defaultmaxmsgcount = strtoll(s2, NULL, 10);
            }

			else if (!strcmp(s1, "disable_pop")) {
                limits->disable_pop = 1;
            }

			else if (!strcmp(s1, "disable_imap")) {
                limits->disable_imap = 1;
            }

			else if (!strcmp(s1, "disable_dialup")) {
                limits->disable_dialup = 1;
            }

			else if (!strcmp(s1, "disable_password_changing")) {
                limits->disable_passwordchanging = 1;
            }

			else if (!strcmp(s1, "disable_external_relay")) {
                limits->disable_relay = 1;
            }

			else if (!strcmp(s1, "disable_smtp")) {
                limits->disable_smtp = 1;
            }

			else if (!strcmp(s1, "disable_webmail")) {
                limits->disable_webmail = 1;
            }

			else if (!strcmp(s1, "disable_spamassassin")) {
                limits->disable_spamassassin = 1;
            }

			else if (!strcmp(s1, "delete_spam")) {
                limits->delete_spam = 1;
            }

			else if (!strcmp(s1, "disable_maildrop")) {
                limits->disable_maildrop = 1;
            }

			else if (!strcmp(s1, "perm_account")) {
                if (s2)
                limits->perm_account = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

			else if (!strcmp(s1, "perm_alias")) {
                if (s2)
                limits->perm_alias = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

			else if (!strcmp(s1, "perm_forward")) {
                if (s2)
                limits->perm_forward = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

			else if (!strcmp(s1, "perm_autoresponder")) {
                if (s2)
                limits->perm_autoresponder = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

			else if (!strcmp(s1, "perm_maillist")) {
                unsigned long perm;
                if (s2) {
                perm = atol(s2);
                limits->perm_maillist = perm & VLIMIT_DISABLE_ALL;
                perm >>= VLIMIT_DISABLE_BITS;
                limits->perm_maillist_users = perm & VLIMIT_DISABLE_ALL;
                perm >>= VLIMIT_DISABLE_BITS;
                limits->perm_maillist_moderators = perm & VLIMIT_DISABLE_ALL;
				}
            }

			else if (!strcmp(s1, "perm_quota")) {
                if (s2)
                limits->perm_quota = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

			else if (!strcmp(s1, "perm_defaultquota")) {
                if (s2)
                limits->perm_defaultquota = atoi(s2) & VLIMIT_DISABLE_ALL;
            }
	  }

	  if (h == NULL)
		 break;

	  /*
		 Reset tail
	  */

	  t = h;
    }

	if (fd != -1)
	   close(fd);

	return 0;

#if 0

    /* open the nominated limits file */
    if ((fs = fopen(dir, "r")) == NULL) return (-1);

    /* suck in each line of the file */
    while (fgets(buf, sizeof(buf), fs) != NULL) {

            /* skip comments */
            if (*buf == '#') continue;

            /* if the line contains no tokens, skip on to next line */
            if ((s1 = strtok(buf, TOKENS)) == NULL)
                continue;

            if (!strcmp(s1, "maxpopaccounts")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxpopaccounts = atoi(s2);
            }

            if (!strcmp(s1, "maxaliases")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxaliases = atoi(s2);
            }

            if (!strcmp(s1, "maxforwards")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxforwards = atoi(s2);
            }

            if (!strcmp(s1, "maxautoresponders")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxautoresponders = atoi(s2);
            }

            if (!strcmp(s1, "maxmailinglists")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxmailinglists = atoi(s2);
            }

            if (!strcmp(s1, "quota")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->diskquota = atoi(s2);
            }

            if (!strcmp(s1, "maxmsgcount")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->maxmsgcount = atoi(s2);
            }

            if (!strcmp(s1, "default_quota")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->defaultquota = atoi(s2);
            }

            if (!strcmp(s1, "default_maxmsgcount")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->defaultmaxmsgcount = atoi(s2);
            }

            if (!strcmp(s1, "disable_pop")) {
                limits->disable_pop = 1;
            }

            if (!strcmp(s1, "disable_imap")) {
                limits->disable_imap = 1;
            }

            if (!strcmp(s1, "disable_dialup")) {
                limits->disable_dialup = 1;
            }

            if (!strcmp(s1, "disable_password_changing")) {
                limits->disable_passwordchanging = 1;
            }

            if (!strcmp(s1, "disable_external_relay")) {
                limits->disable_relay = 1;
            }

            if (!strcmp(s1, "disable_smtp")) {
                limits->disable_smtp = 1;
            }

            if (!strcmp(s1, "disable_webmail")) {
                limits->disable_webmail = 1;
            }

            if (!strcmp(s1, "disable_spamassassin")) {
                limits->disable_spamassassin = 1;
            }

            if (!strcmp(s1, "delete_spam")) {
                limits->delete_spam = 1;
            }

            if (!strcmp(s1, "disable_maildrop")) {
                limits->disable_maildrop = 1;
            }

            if (!strcmp(s1, "perm_account")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_account = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_alias")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_alias = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_forward")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_forward = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_autoresponder")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_autoresponder = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_maillist")) {
                unsigned long perm;
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                perm = atol(s2);
                limits->perm_maillist = perm & VLIMIT_DISABLE_ALL;
                perm >>= VLIMIT_DISABLE_BITS;
                limits->perm_maillist_users = perm & VLIMIT_DISABLE_ALL;
                perm >>= VLIMIT_DISABLE_BITS;
                limits->perm_maillist_moderators = perm & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_quota")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_quota = atoi(s2) & VLIMIT_DISABLE_ALL;
            }

            if (!strcmp(s1, "perm_defaultquota")) {
                if ((s2 = strtok(NULL, TOKENS)) == NULL)
                    continue;
                limits->perm_defaultquota = atoi(s2) & VLIMIT_DISABLE_ALL;
            }
    }
    fclose(fs);
    return 0;
#endif
}

/* Take the limits struct, and write it out as a .qmailadmin-limits
 * in the nominated dir
 */
int vlimits_write_limits_file(const char *dir, const struct vlimits *limits)
{
    FILE * fs;

    /* open the limits file (overwrite if it already exists) */
    if ((fs = fopen(dir, "w+")) != NULL) {
        /* write out limits into the file */
        fprintf(fs, "maxpopaccounts: %d\n", limits->maxpopaccounts);
        fprintf(fs, "maxaliases: %d\n", limits->maxaliases);
        fprintf(fs, "maxforwards: %d\n", limits->maxforwards);
        fprintf(fs, "maxautoresponders: %d\n", limits->maxautoresponders);
        fprintf(fs, "maxmailinglists: %d\n", limits->maxmailinglists);
        fprintf(fs, "quota: %llu\n", limits->diskquota);
        fprintf(fs, "maxmsgcount: %llu\n", limits->maxmsgcount);
        fprintf(fs, "default_quota: %llu\n", limits->defaultquota);
        fprintf(fs, "default_maxmsgcount: %llu\n", limits->defaultmaxmsgcount);
        if (limits->disable_pop) fprintf(fs, "disable_pop\n");
        if (limits->disable_imap) fprintf(fs, "disable_imap\n");
        if (limits->disable_dialup) fprintf(fs, "disable_dialup\n");
        if (limits->disable_passwordchanging) fprintf(fs, "disable_password_changing\n");
        if (limits->disable_webmail) fprintf(fs, "disable_webmail\n");
        if (limits->disable_relay) fprintf(fs, "disable_external_relay\n");
        if (limits->disable_smtp) fprintf(fs, "disable_smtp\n");
        if (limits->disable_spamassassin) fprintf(fs, "disable_spamassassin\n");
        if (limits->delete_spam) fprintf(fs, "delete_spam\n");
        if (limits->disable_maildrop) fprintf(fs, "disable_maildrop\n");
        fprintf(fs, "perm_account: %d\n", limits->perm_account);
        fprintf(fs, "perm_alias: %d\n", limits->perm_alias);
        fprintf(fs, "perm_forward: %d\n", limits->perm_forward);
        fprintf(fs, "perm_autoresponder: %d\n", limits->perm_autoresponder);
        fprintf(fs, "perm_maillist: %d\n", limits->perm_maillist);
        fprintf(fs, "perm_quota: %d\n",
          (limits->perm_quota)|(limits->perm_maillist_users<<VLIMIT_DISABLE_BITS)|(limits->perm_maillist_moderators<<(VLIMIT_DISABLE_BITS*2)));
        fprintf(fs, "perm_defaultquota: %d\n", limits->perm_defaultquota);
        fclose(fs);
    } else {
        fprintf(stderr, "vlimits: failed to open limits file (%d):  %s\n", errno, dir);
        return -1;
    }

    return 0;
}

int vlimits_get_flag_mask(struct vlimits *limits)
 {
    int mask = 0;
    if (limits->disable_pop != 0) {
        mask |= NO_POP;
    }
    if (limits->disable_smtp != 0) {
        mask |= NO_SMTP;
    }
    if (limits->disable_imap != 0) {
        mask |= NO_IMAP;
    }
    if (limits->disable_relay != 0) {
        mask |= NO_RELAY;
    }
    if (limits->disable_webmail != 0) {
        mask |= NO_WEBMAIL;
    }
    if (limits->disable_passwordchanging != 0) {
        mask |= NO_PASSWD_CHNG;
    }
    if (limits->disable_dialup != 0) {
        mask |= NO_DIALUP;
    }
    if (limits->disable_spamassassin != 0) {
        mask |= NO_SPAMASSASSIN;
    }
    if (limits->delete_spam != 0) {
        mask |= DELETE_SPAM;
    }
    if (limits->disable_maildrop != 0) {
        mask |= NO_MAILDROP;
    }

    return mask;
    /* this feature has been temporarily disabled until we can figure
     * out a solution to the problem where edited users will have domain
     * limits saved into their user limits.
     */
    //return 0;
}

#ifndef ENABLE_MYSQL_LIMITS

/* grab the limits for this domain
 * look first for a ~vpopmail/domains/domain/.qmailadmin-limits
 * if not found, try ~vpopmail/etc/vlimits.default
 * if neither found, return error
 */
int vget_limits(const char *domain, struct vlimits *limits)
{
    char mydomain[MAX_BUFF];
    char dir[MAX_BUFF];
    uid_t uid;
    gid_t gid;

    /* initialise a limits struct. */
    vdefault_limits(limits);

    /* use copy of name as vget_assign may change it on us */
    snprintf(mydomain, sizeof(mydomain), "%s", domain);

    /* extract the dir, uid, gid of the domain */
    if (vget_assign(mydomain, dir, sizeof(dir), &uid, &gid) == NULL) {
      fprintf (stderr, "Error. Domain %s was not found in the assign file\n", mydomain);
      return (-1);
    }

    /* work out the location of the .qmailadmin-limits file */
    strncat (dir, "/.qmailadmin-limits", sizeof(dir)-strlen(dir)-1);

    /* try to read in the contents of the .qmailadmin-limits file.
     * and populate the limits struct with the result
     */
    if (vlimits_read_limits_file (dir, limits) == 0) {
        /* Successfully read the file in */
        chown(dir,uid,gid);
        chmod(dir, S_IRUSR|S_IWUSR);
    } else if (vlimits_read_limits_file (VLIMITS_DEFAULT_FILE, limits) == 0) {
        /* We couldn't find a .qmailadmin-limits in the domain's dir.
         * but we did find a global file at ~vpopmail/etc/vlimits.default file
         * so we have used that instead
         */
    } else {
        /* No ~vpopmail/domains/domain/.qmailadmin-limits
         * and also no ~vpopmail/etc/vlimits.default
         * so return error
         */ 
        return -1;
    }
    return 0;
}

/* Take the limits struct, and write it out as a .qmailadmin-limits
 * in the nominated domain's dir
 */
int vset_limits(const char *domain, const struct vlimits *limits)
{
    char mydomain[MAX_BUFF];
    char dir[MAX_BUFF];
    uid_t uid;
    gid_t gid;

    /* use copy of name as vget_assign may change it on us */
    snprintf(mydomain, sizeof(mydomain), "%s", domain);

    /* get the dir, uid and gid of the nominated domain */
    if (vget_assign(mydomain, dir, sizeof(dir), &uid, &gid) == NULL) {
      fprintf (stderr, "Error. Domain %s was not found in the assign file\n",mydomain);
      return(-1);
    }

    strncat(dir, "/.qmailadmin-limits", sizeof(dir)-strlen(dir)-1);  
    
    if (vlimits_write_limits_file (dir, limits) != 0) {
    	return -1;
    }

    return 0;
}

/* delete the .qmailadmin-limits file for the nominated domain */
int vdel_limits(const char *domain)
{
    char mydomain[MAX_BUFF];
    char dir[MAX_BUFF];
    uid_t uid;
    gid_t gid;

    /* use copy of name as vget_assign may change it on us */
    snprintf(mydomain, sizeof(mydomain), "%s", domain);

    /* get filename */
    if (vget_assign(mydomain, dir, sizeof(dir), &uid, &gid) == NULL) {
      printf ("Failed vget_assign for %s\n",mydomain);
      return (-1);
    }
    strncat(dir, "/.qmailadmin-limits", sizeof(dir)-strlen(dir)-1);
    return unlink(dir);
}
#endif

void vlimits_setflags (struct vqpasswd *pw, char *domain)
{
    struct vlimits limits;

    if ((! (pw->pw_gid & V_OVERRIDE))
      && (vget_limits (domain, &limits) == 0)) {
        pw->pw_flags = pw->pw_gid | vlimits_get_flag_mask (&limits);
    } else pw->pw_flags = pw->pw_gid;
}
