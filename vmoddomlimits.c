/*
 * $Id: vmoddomlimits.c 1014 2011-02-03 16:04:37Z volz0r $
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"
#include "vlimits.h"

char Domain[MAX_BUFF];

char DomainQuota[MAX_BUFF];
char DefaultUserQuota[MAX_BUFF];
char DomainMaxMsgCount[MAX_BUFF];
char DefaultUserMaxMsgCount[MAX_BUFF];
char MaxPopAccounts[MAX_BUFF];
char MaxAliases[MAX_BUFF];
char MaxForwards[MAX_BUFF];
char MaxAutoresponders[MAX_BUFF];
char MaxMailinglists[MAX_BUFF];
char GidFlagString[MAX_BUFF];
char PermAccountFlagString[MAX_BUFF];
char PermAliasFlagString[MAX_BUFF];
char PermForwardFlagString[MAX_BUFF];
char PermAutoresponderFlagString[MAX_BUFF];
char PermMaillistFlagString[MAX_BUFF];
char PermMaillistUsersFlagString[MAX_BUFF];
char PermMaillistModeratorsFlagString[MAX_BUFF];
char PermQuotaFlagString[MAX_BUFF];
char PermDefaultQuotaFlagString[MAX_BUFF];

int GidFlag = 0;
int PermAccountFlag = 0;
int PermAliasFlag = 0;
int PermForwardFlag = 0;
int PermAutoresponderFlag = 0;
int PermMaillistFlag = 0;
int PermMaillistUsersFlag = 0;
int PermMaillistModeratorsFlag = 0;
int PermQuotaFlag = 0;
int PermDefaultQuotaFlag = 0;

int QuotaFlag = 0;
int ShowLimits = 0;
int DeleteLimits = 0;
int EditDefaultLimits = 0;

struct vlimits limits;

void usage();
void get_options(int argc,char **argv);

int main(int argc, char *argv[])
{
 int i;
 char OptionString[MAX_BUFF];
 

    if( vauth_open( 1 )) {
        vexiterror( stderr, "Initial open." );
    }

    get_options(argc,argv);
    
    if (EditDefaultLimits || vget_assign(Domain, NULL, 0, NULL, NULL ) != NULL) {    
        if (EditDefaultLimits) {
            if (vlimits_read_limits_file(VLIMITS_DEFAULT_FILE, &limits) != 0) {
                printf ("Failed to read the vlimits.default file.\n");
                vexit(-1);
            }
            if (DeleteLimits) {
          	printf ("Default limits must not be deleted. If you really want to do this,\n");
          	printf ("remove the vlimits.default file.\n");
          	printf ("But be warned: this might stop vpopmail from working!!\n");
          	vexit(-1);
            }
        } else {
            if (vget_limits(Domain,&limits) != 0) {
                printf ("Failed to vget_limits\n");
                vexit(-1);
            }
            if (DeleteLimits) {
                if (vdel_limits(Domain)==0) {
                    printf ("Limits deleted\n");
                    vexit(0);
                } else {
                    printf ("Failed to delete limits\n");
                    vexit(-1);
                }
            }
        }
        if (ShowLimits) {
            memset (OptionString, 0, sizeof(OptionString));
            if (EditDefaultLimits)
                printf("Default limits: %s\n", VLIMITS_DEFAULT_FILE);
            else
                printf("Domain: %s\n", Domain);

            printf("--\n");
            printf("Max Pop Accounts: %d\n", limits.maxpopaccounts);
            printf("Max Aliases: %d\n", limits.maxaliases);
            printf("Max Forwards: %d\n", limits.maxforwards);
            printf("Max Autoresponders: %d\n", limits.maxautoresponders);
            printf("Max Mailinglists: %d\n", limits.maxmailinglists);
            printf("GID Flags:\n");
            if (limits.disable_imap != 0) {
                printf("  NO_IMAP\n");
                strncat(OptionString, "i", sizeof(OptionString)-strlen(OptionString)-1);
            }
            if (limits.disable_smtp != 0) {
                printf("  NO_SMTP\n");
                strncat(OptionString, "s", sizeof(OptionString)-strlen(OptionString)-1);
            }
            if (limits.disable_pop != 0) {
                printf("  NO_POP\n");
                strncat(OptionString, "p", sizeof(OptionString)-strlen(OptionString)-1);
            }
            if (limits.disable_webmail != 0) {
                printf("  NO_WEBMAIL\n");
                strncat(OptionString, "w", sizeof(OptionString)-strlen(OptionString)-1);
            }
            if (limits.disable_passwordchanging != 0) {
                printf("  NO_PASSWD_CHNG\n");
                strncat(OptionString, "d", sizeof(OptionString)-strlen(OptionString)-1);
            }
            if (limits.disable_relay != 0) {
                printf("  NO_RELAY\n");
                strncat(OptionString, "r", sizeof(OptionString)-strlen(OptionString)-1);
            }
            if (limits.disable_dialup != 0) {
                printf("  NO_DIALUP\n");
                strncat(OptionString, "u", sizeof(OptionString)-strlen(OptionString)-1);
            }
            if (limits.disable_spamassassin != 0) {
                printf("  NO_SPAMASSASSIN\n");
                strncat(OptionString, "c", sizeof(OptionString)-strlen(OptionString)-1);
            }
            if (limits.delete_spam != 0) {
                printf("  DEL_SPAM\n");
                strncat(OptionString, "x", sizeof(OptionString)-strlen(OptionString)-1);
            }
            if (limits.disable_maildrop != 0) {
                printf("  NO_MAILDROP\n");
                strncat(OptionString, "m", sizeof(OptionString)-strlen(OptionString)-1);
            }
            printf("Flags (for commandline): %s\n", OptionString);
            printf("Flags for non postmaster accounts:");
            printf("\n  pop account:            ");
            printf ((limits.perm_account & VLIMIT_DISABLE_CREATE ? "DENY_CREATE  " :"ALLOW_CREATE ") );
            printf ((limits.perm_account & VLIMIT_DISABLE_MODIFY ? "DENY_MODIFY  " :"ALLOW_MODIFY ") );
            printf ((limits.perm_account & VLIMIT_DISABLE_DELETE ? "DENY_DELETE  " :"ALLOW_DELETE ") );
            printf("\n  alias:                  ");
            printf ((limits.perm_alias & VLIMIT_DISABLE_CREATE ? "DENY_CREATE  " :"ALLOW_CREATE ") );
            printf ((limits.perm_alias & VLIMIT_DISABLE_MODIFY ? "DENY_MODIFY  " :"ALLOW_MODIFY ") );
            printf ((limits.perm_alias & VLIMIT_DISABLE_DELETE ? "DENY_DELETE  " :"ALLOW_DELETE ") );
            printf("\n  forward:                ");
            printf ((limits.perm_forward & VLIMIT_DISABLE_CREATE ? "DENY_CREATE  " :"ALLOW_CREATE ") );
            printf ((limits.perm_forward & VLIMIT_DISABLE_MODIFY ? "DENY_MODIFY  " :"ALLOW_MODIFY ") );
            printf ((limits.perm_forward & VLIMIT_DISABLE_DELETE ? "DENY_DELETE  " :"ALLOW_DELETE ") );
            printf("\n  autoresponder:          ");
            printf ((limits.perm_autoresponder & VLIMIT_DISABLE_CREATE ? "DENY_CREATE  " :"ALLOW_CREATE ") );
            printf ((limits.perm_autoresponder & VLIMIT_DISABLE_MODIFY ? "DENY_MODIFY  " :"ALLOW_MODIFY ") );
            printf ((limits.perm_autoresponder & VLIMIT_DISABLE_DELETE ? "DENY_DELETE  " :"ALLOW_DELETE ") );
            printf("\n  mailinglist:            ");
            printf ((limits.perm_maillist & VLIMIT_DISABLE_CREATE ? "DENY_CREATE  " :"ALLOW_CREATE ") );
            printf ((limits.perm_maillist & VLIMIT_DISABLE_MODIFY ? "DENY_MODIFY  " :"ALLOW_MODIFY ") );
            printf ((limits.perm_maillist & VLIMIT_DISABLE_DELETE ? "DENY_DELETE  " :"ALLOW_DELETE ") );
            printf("\n  mailinglist users:      ");
            printf ((limits.perm_maillist_users & VLIMIT_DISABLE_CREATE ? "DENY_CREATE  " :"ALLOW_CREATE ") );
            printf ((limits.perm_maillist_users & VLIMIT_DISABLE_MODIFY ? "DENY_MODIFY  " :"ALLOW_MODIFY ") );
            printf ((limits.perm_maillist_users & VLIMIT_DISABLE_DELETE ? "DENY_DELETE  " :"ALLOW_DELETE ") );
            printf("\n  mailinglist moderators: ");
            printf ((limits.perm_maillist_moderators & VLIMIT_DISABLE_CREATE ? "DENY_CREATE  " :"ALLOW_CREATE ") );
            printf ((limits.perm_maillist_moderators & VLIMIT_DISABLE_MODIFY ? "DENY_MODIFY  " :"ALLOW_MODIFY ") );
            printf ((limits.perm_maillist_moderators & VLIMIT_DISABLE_DELETE ? "DENY_DELETE  " :"ALLOW_DELETE ") );
            printf("\n  quota:                  ");
            printf ((limits.perm_quota & VLIMIT_DISABLE_CREATE ? "DENY_CREATE  " :"ALLOW_CREATE ") );
            printf ((limits.perm_quota & VLIMIT_DISABLE_MODIFY ? "DENY_MODIFY  " :"ALLOW_MODIFY ") );
            printf ((limits.perm_quota & VLIMIT_DISABLE_DELETE ? "DENY_DELETE  " :"ALLOW_DELETE ") );
            printf("\n  default quota:          ");
            printf ((limits.perm_defaultquota & VLIMIT_DISABLE_CREATE ? "DENY_CREATE  " :"ALLOW_CREATE ") );
            printf ((limits.perm_defaultquota & VLIMIT_DISABLE_MODIFY ? "DENY_MODIFY  " :"ALLOW_MODIFY ") );
            printf ((limits.perm_defaultquota & VLIMIT_DISABLE_DELETE ? "DENY_DELETE  " :"ALLOW_DELETE ") );
            
            printf("\n");
            printf("Domain Quota: %llu MB\n", limits.diskquota);
            printf("Default User Quota: %llu bytes\n", limits.defaultquota);
            printf("Max Domain Messages: %llu\n", limits.maxmsgcount);
            printf("Default Max Messages per User: %llu\n", limits.defaultmaxmsgcount);
            return(vexit(0));
        }
                
        if (MaxPopAccounts[0] != 0) {
            limits.maxpopaccounts = atoi(MaxPopAccounts);
        }
        if (MaxAliases[0] != 0) {
            limits.maxaliases = atoi(MaxAliases);
        }
        if (MaxForwards[0] != 0) {
            limits.maxforwards = atoi(MaxForwards);
        }
        if (MaxAutoresponders[0] != 0) {
            limits.maxautoresponders = atoi(MaxAutoresponders);
        }
        if (MaxMailinglists[0] != 0) {
            limits.maxmailinglists = atoi(MaxMailinglists);
        }
        
        /* quota & message count limits */
        if (DomainQuota[0] != 0) {
            limits.diskquota = strtoll(DomainQuota, NULL, 10);
        }
        if (DomainMaxMsgCount[0] != 0) {
            limits.maxmsgcount = strtoll(DomainMaxMsgCount, NULL, 10);
        }
        if (DefaultUserQuota[0] != 0) {
            limits.defaultquota = strtoll(format_maildirquota(DefaultUserQuota), NULL, 10);
        }
        if (DefaultUserMaxMsgCount[0] != 0) {
            limits.defaultmaxmsgcount = strtoll(DefaultUserMaxMsgCount, NULL, 10);
        }
        
        if (GidFlag == 1) {
            GidFlag = 0;
            limits.disable_dialup = 0;
            limits.disable_passwordchanging = 0;
            limits.disable_pop = 0;
            limits.disable_smtp = 0;
            limits.disable_webmail = 0;
            limits.disable_imap = 0;
            limits.disable_relay = 0;
            limits.disable_spamassassin = 0;
            limits.delete_spam = 0;
            limits.disable_maildrop = 0;
            for (i=0; i<(int)strlen(GidFlagString); i++) {
                switch(GidFlagString[i]) {
                    case 'u': limits.disable_dialup = 1; break;
                    case 'd': limits.disable_passwordchanging = 1; break;
                    case 'p': limits.disable_pop = 1; break;
                    case 's': limits.disable_smtp = 1; break;
                    case 'w': limits.disable_webmail = 1; break;
                    case 'i': limits.disable_imap = 1; break;
                    case 'r': limits.disable_relay = 1; break;
                    case 'c': limits.disable_spamassassin = 1; break;
                    case 'x': limits.delete_spam = 1; break;
                    case 'm': limits.disable_maildrop = 1; break;
                }
            }
        }
        if (PermAccountFlag == 1) {
            limits.perm_account=0;
            for (i=0; i<(int)strlen(PermAccountFlagString); i++) {
                switch(PermAccountFlagString[i]) {
                    case 'a': limits.perm_account|=VLIMIT_DISABLE_ALL; break;
                    case 'c': limits.perm_account|=VLIMIT_DISABLE_CREATE; break;
                    case 'm': limits.perm_account|=VLIMIT_DISABLE_MODIFY; break;
                    case 'd': limits.perm_account|=VLIMIT_DISABLE_DELETE; break;
                }
            }
        }
        if (PermAliasFlag == 1) {
            limits.perm_alias=0;
            for (i=0; i<(int)strlen(PermAliasFlagString); i++) {
                switch(PermAliasFlagString[i]) {
                    case 'a': limits.perm_alias|=VLIMIT_DISABLE_ALL; break;
                    case 'c': limits.perm_alias|=VLIMIT_DISABLE_CREATE; break;
                    case 'm': limits.perm_alias|=VLIMIT_DISABLE_MODIFY; break;
                    case 'd': limits.perm_alias|=VLIMIT_DISABLE_DELETE; break;
                }
            }
        }
        if (PermForwardFlag == 1) {
            limits.perm_forward=0;
            for (i=0; i<(int)strlen(PermForwardFlagString); i++) {
                switch(PermForwardFlagString[i]) {
                    case 'a': limits.perm_forward|=VLIMIT_DISABLE_ALL; break;
                    case 'c': limits.perm_forward|=VLIMIT_DISABLE_CREATE; break;
                    case 'm': limits.perm_forward|=VLIMIT_DISABLE_MODIFY; break;
                    case 'd': limits.perm_forward|=VLIMIT_DISABLE_DELETE; break;
                }
            }
        }
        if (PermAutoresponderFlag == 1) {
            limits.perm_autoresponder=0;
            for (i=0; i<(int)strlen(PermAutoresponderFlagString); i++) {
                switch(PermAutoresponderFlagString[i]) {
                    case 'a': limits.perm_autoresponder|=VLIMIT_DISABLE_ALL; break;
                    case 'c': limits.perm_autoresponder|=VLIMIT_DISABLE_CREATE; break;
                    case 'm': limits.perm_autoresponder|=VLIMIT_DISABLE_MODIFY; break;
                    case 'd': limits.perm_autoresponder|=VLIMIT_DISABLE_DELETE; break;
                }
            }
        }
        if (PermMaillistFlag == 1) {
            limits.perm_maillist=0;
            for (i=0; i<(int)strlen(PermMaillistFlagString); i++) {
                switch(PermMaillistFlagString[i]) {
                    case 'a': limits.perm_maillist|=VLIMIT_DISABLE_ALL; break;
                    case 'c': limits.perm_maillist|=VLIMIT_DISABLE_CREATE; break;
                    case 'm': limits.perm_maillist|=VLIMIT_DISABLE_MODIFY; break;
                    case 'd': limits.perm_maillist|=VLIMIT_DISABLE_DELETE; break;
                }
            }
        }
        if (PermMaillistUsersFlag == 1) {
            limits.perm_maillist_users=0;
            for (i=0; i<(int)strlen(PermMaillistUsersFlagString); i++) {
                switch(PermMaillistUsersFlagString[i]) {
                    case 'a': limits.perm_maillist_users|=VLIMIT_DISABLE_ALL; break;
                    case 'c': limits.perm_maillist_users|=VLIMIT_DISABLE_CREATE; break;
                    case 'm': limits.perm_maillist_users|=VLIMIT_DISABLE_MODIFY; break;
                    case 'd': limits.perm_maillist_users|=VLIMIT_DISABLE_DELETE; break;
                }
            }
        }
        if (PermMaillistModeratorsFlag == 1) {
            limits.perm_maillist_moderators=0;
            for (i=0; i<(int)strlen(PermMaillistModeratorsFlagString); i++) {
                switch(PermMaillistModeratorsFlagString[i]) {
                    case 'a': limits.perm_maillist_moderators|=VLIMIT_DISABLE_ALL; break;
                    case 'c': limits.perm_maillist_moderators|=VLIMIT_DISABLE_CREATE; break;
                    case 'm': limits.perm_maillist_moderators|=VLIMIT_DISABLE_MODIFY; break;
                    case 'd': limits.perm_maillist_moderators|=VLIMIT_DISABLE_DELETE; break;
                }
            }
        }
        if (PermQuotaFlag == 1) {
            limits.perm_quota=0;
            for (i=0; i<(int)strlen(PermQuotaFlagString); i++) {
                switch(PermQuotaFlagString[i]) {
                    case 'a': limits.perm_quota|=VLIMIT_DISABLE_ALL; break;
                    case 'c': limits.perm_quota|=VLIMIT_DISABLE_CREATE; break;
                    case 'm': limits.perm_quota|=VLIMIT_DISABLE_MODIFY; break;
                    case 'd': limits.perm_quota|=VLIMIT_DISABLE_DELETE; break;
                }
            }
        }
        if (PermDefaultQuotaFlag == 1) {
            limits.perm_defaultquota=0;
            for (i=0; i<(int)strlen(PermDefaultQuotaFlagString); i++) {
                switch(PermDefaultQuotaFlagString[i]) {
                    case 'a': limits.perm_defaultquota|=VLIMIT_DISABLE_ALL; break;
                    case 'c': limits.perm_defaultquota|=VLIMIT_DISABLE_CREATE; break;
                    case 'm': limits.perm_defaultquota|=VLIMIT_DISABLE_MODIFY; break;
                    case 'd': limits.perm_defaultquota|=VLIMIT_DISABLE_DELETE; break;
                }
            }
        }
        if (EditDefaultLimits) {
            if (vlimits_write_limits_file(VLIMITS_DEFAULT_FILE, &limits)) {
            	printf ("Failed to write vlimits.default file");
            	return (vexit(-1));
            }
        } else {
            if (vset_limits(Domain,&limits) != 0) {
                printf ("Failed to vset_limits\n");
                return (vexit(-1));
            }
        }
    }
    
    return(vexit(0));

}

void usage()
{
    printf( "vmoddomlimits: usage: [options] domain \n");
    printf("options: -v ( display the vpopmail version number )\n");
    printf("         -d ( use the vlimits.default file, instead of domain )\n");
    printf("         -S ( show current settings )\n");
    printf("         -D ( delete limits for this domain, i.e. switch to default limits)\n");
    printf("         -Q quota-in-megabytes ( set domain disk quota, '100' = 100 MB )\n");
    printf("         -q quota-in-bytes ( set default user quota, '10M' = 10 MB )\n");
    printf("         -M count ( set domain max msg count )\n");
    printf("         -m count ( set default user max msg count )\n");
    printf("         -P count ( set max amount of pop accounts )\n");
    printf("         -A count ( set max amount of aliases )\n");
    printf("         -F count ( set max amount of forwards )\n");
    printf("         -R count ( set max amount of autoresponders )\n");
    printf("         -L count ( set max amount of mailing lists )\n");
    

    printf("the following options are bit flags in the gid int field\n");
    printf("         -g \"flags\"  (set flags, see below)\n");
    printf("         gid flags:\n");
    printf("            u ( set no dialup flag )\n");
    printf("            d ( set no password changing flag )\n");
    printf("            p ( set no pop access flag )\n");
    printf("            s ( set no smtp access flag )\n");
    printf("            w ( set no web mail access flag )\n");
    printf("            i ( set no imap access flag )\n");
    printf("            r ( set no external relay flag )\n");
    printf("            c ( set no spamassasssin flag )\n");
    printf("            x ( set delete spam flag )\n");
    printf("            m ( set no maildrop flag )\n");

    
    printf("the following options are bit flags for non postmaster admins\n");
    printf("         -p \"flags\"  (set pop account flags)\n");
    printf("         -a \"flags\"  (set alias flags)\n");
    printf("         -f \"flags\"  (set forward flags)\n");
    printf("         -r \"flags\"  (set autoresponder flags)\n");
    printf("         -l \"flags\"  (set mailinglist flags)\n");
    printf("         -u \"flags\"  (set mailinglist users flags)\n");
    printf("         -o \"flags\"  (set mailinglist moderators flags)\n");
    printf("         -x \"flags\"  (set quota flags)\n");
    printf("         -z \"flags\"  (set default quota flags)\n");
    printf("         perm flags:\n");
    printf("            a ( set deny all flag )\n");
    printf("            c ( set deny create flag )\n");
    printf("            m ( set deny modify flag )\n");
    printf("            d ( set deny delete flag )\n");
                
}

void get_options(int argc,char **argv)
{
 int c;
 int errflag;
 extern char *optarg;
 extern int optind;

    memset(Domain, 0, sizeof(Domain));
    memset(DomainQuota, 0, sizeof(DomainQuota));
    memset(DefaultUserQuota, 0, sizeof(DefaultUserQuota));
    memset(DomainMaxMsgCount, 0, sizeof(DomainMaxMsgCount));
    memset(DefaultUserMaxMsgCount, 0, sizeof(DefaultUserMaxMsgCount));
    memset(MaxPopAccounts, 0, sizeof(MaxPopAccounts));
    memset(MaxAliases, 0, sizeof(MaxAliases));
    memset(MaxForwards, 0, sizeof(MaxForwards));
    memset(MaxAutoresponders, 0, sizeof(MaxAutoresponders));
    memset(MaxMailinglists, 0, sizeof(MaxMailinglists));
    memset(GidFlagString, 0, sizeof(GidFlagString));
    
    memset(PermAccountFlagString,0, sizeof(PermAccountFlagString));
    memset(PermAliasFlagString,0, sizeof(PermAliasFlagString));
    memset(PermForwardFlagString,0, sizeof(PermForwardFlagString));
    memset(PermAutoresponderFlagString,0, sizeof(PermAutoresponderFlagString));
    memset(PermMaillistFlagString,0, sizeof(PermMaillistFlagString));
    memset(PermMaillistUsersFlagString,0, sizeof(PermMaillistUsersFlagString));
    memset(PermMaillistModeratorsFlagString,0, sizeof(PermMaillistModeratorsFlagString));
    memset(PermQuotaFlagString,0, sizeof(PermQuotaFlagString));
    memset(PermDefaultQuotaFlagString,0, sizeof(PermDefaultQuotaFlagString));
    
    QuotaFlag = 0;
    GidFlag = 0;
    PermAccountFlag = 0;
    PermAliasFlag = 0;
    PermForwardFlag = 0;
    PermAutoresponderFlag = 0;
    PermMaillistFlag = 0;
    PermMaillistUsersFlag = 0;
    PermMaillistModeratorsFlag = 0;
    PermQuotaFlag = 0;
    PermDefaultQuotaFlag = 0;
    //NoMakeIndex = 0;
    ShowLimits = 0;
    DeleteLimits = 0;
    EditDefaultLimits = 0;
    errflag = 0;
    while( (c=getopt(argc,argv,"vSDdQ:q:M:m:P:A:F:R:L:g:p:a:f:r:l:u:o:x:z:h")) != -1 ) {
        switch(c) {
            case 'v':
                printf("version: %s\n", VERSION);
                break;
            case 'S':
                ShowLimits = 1;
                break;
            case 'D':
                DeleteLimits = 1;
                break;
            case 'd':
                EditDefaultLimits = 1;
                snprintf(Domain, sizeof(Domain), "Default limits: %s", VLIMITS_DEFAULT_FILE);
                break;
            case 'Q':
                snprintf(DomainQuota, sizeof(DomainQuota), "%s", optarg);
                break;
            case 'q':
                snprintf(DefaultUserQuota, sizeof(DefaultUserQuota), "%s", optarg);
                break;
            case 'M':
                snprintf(DomainMaxMsgCount, sizeof(DomainMaxMsgCount), "%s", optarg);
                break;
            case 'm':
                snprintf(DefaultUserMaxMsgCount, sizeof(DefaultUserMaxMsgCount), "%s", optarg);
                break;
            case 'P':
                snprintf(MaxPopAccounts, sizeof(MaxPopAccounts), "%s", optarg);
                break;
            case 'A':
                snprintf(MaxAliases, sizeof(MaxAliases), "%s", optarg);
                break;
            case 'F':
                snprintf(MaxForwards, sizeof(MaxForwards), "%s", optarg);
                break;
            case 'R':
                snprintf(MaxAutoresponders, sizeof(MaxAutoresponders), "%s", optarg);
                break;
            case 'L':
                snprintf(MaxMailinglists, sizeof(MaxMailinglists), "%s", optarg);
                break;
            case 'g':
                snprintf(GidFlagString, sizeof(GidFlagString), "%s", optarg);
                GidFlag = 1;
                break;
            case 'p':
                snprintf(PermAccountFlagString, sizeof(PermAccountFlagString), "%s", optarg);
                PermAccountFlag = 1;
                break;
            case 'a':
                snprintf(PermAliasFlagString, sizeof(PermAliasFlagString), "%s", optarg);
                PermAliasFlag = 1;
                break;
            case 'f':
                snprintf(PermForwardFlagString, sizeof(PermForwardFlagString), "%s", optarg);
                PermForwardFlag = 1;
                break;
            case 'r':
                snprintf(PermAutoresponderFlagString, sizeof(PermAutoresponderFlagString), "%s", optarg);
                PermAutoresponderFlag = 1;
                break;
            case 'l':
                snprintf(PermMaillistFlagString, sizeof(PermMaillistFlagString), "%s", optarg);
                PermMaillistFlag = 1;
                break;
            case 'u':
                snprintf(PermMaillistUsersFlagString, sizeof(PermMaillistUsersFlagString), "%s", optarg);
                PermMaillistUsersFlag = 1;
                break;
            case 'o':
                snprintf(PermMaillistModeratorsFlagString, sizeof(PermMaillistModeratorsFlagString), "%s", optarg);
                PermMaillistModeratorsFlag = 1;
                break;
            case 'x':
                snprintf(PermQuotaFlagString, sizeof(PermQuotaFlagString), "%s", optarg);
                PermQuotaFlag = 1;
                break;
            case 'z':
                snprintf(PermDefaultQuotaFlagString, sizeof(PermDefaultQuotaFlagString), "%s", optarg);
                PermDefaultQuotaFlag = 1;
                break;
            case 'h':
                usage();
                vexit(0);
            default:
                errflag = 1;
                break;
        }
    }

    if ( optind < argc && EditDefaultLimits == 0) {
        snprintf(Domain, sizeof(Domain), "%s", argv[optind]);
        ++optind;
    }

    if ( Domain[0] == 0 && EditDefaultLimits == 0) { 
        usage();
        vexit(-1);
    }
}
