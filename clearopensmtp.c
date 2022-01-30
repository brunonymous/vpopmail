/*
 * $Id: clearopensmtp.c 1014 2011-02-03 16:04:37Z volz0r $
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
#include <time.h>
#include <string.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

#ifdef POP_AUTH_OPEN_RELAY

#ifndef USE_SQL
static char TmpBuf1[MAX_BUFF];
static char TmpBuf2[MAX_BUFF];
#endif /* ndef USE_SQL */

int main()
{
#ifndef USE_SQL
 FILE *fs_smtp_cur;
 FILE *fs_smtp_tmp;
 char *tmpstr;
 time_t file_time;
#endif /* ndef USE_SQL */
 time_t mytime;
 time_t clear_minutes;

	if( vauth_open( 0 )) {
		vexiterror( stderr, "Initial open." );
	}

	clear_minutes = RELAY_CLEAR_MINUTES * 60;
	mytime = time(NULL);

#ifdef USE_SQL
        /* scan the relays table in mysql, and purge out any
         * entries that are older than our specified timestamp
         */
	vclear_open_smtp(clear_minutes, mytime);
#else
        /* OPEN_SMTP_CUR_FILE is typically ~vpopmail/etc/open-smtp */
	fs_smtp_cur = fopen(OPEN_SMTP_CUR_FILE, "r+");
	if ( fs_smtp_cur != NULL ) {

                /* OPEN_SMTP_TMP_FILE is typically ~vpopmail/etc/open-smtp.tmp */
 		/* create this file */
		fs_smtp_tmp = fopen(OPEN_SMTP_TMP_FILE, "w+");
		if ( fs_smtp_tmp == NULL ) {
			printf ("Error, could not create open-smtp.tmp\n");
			vexit(-1);
		}

		/* read in the contents of the open-smtp file */
		while ( fgets(TmpBuf1, MAX_BUFF, fs_smtp_cur ) != NULL ) {
			/* format is x.x.x.x:ALLOW,RELAYCLIENT="",RBLSMTPD=""<TAB>timestamp */
			snprintf(TmpBuf2, sizeof(TmpBuf2), "%s", TmpBuf1);

			tmpstr = strtok( TmpBuf2, "\t");
			tmpstr = strtok( NULL, "\t");
			/* extract the timestamp for this line */
			if ( tmpstr != NULL ) {
				/* compare the timestamp to see if it is not too old */
				file_time = atoi(tmpstr);
				if ( file_time + clear_minutes > mytime) {
					/* if not too old, copy line out to .tmp file */
					fputs(TmpBuf1, fs_smtp_tmp);
				}
			}
		}
		fclose(fs_smtp_cur);
		fclose(fs_smtp_tmp);

		/* replace open-relay with open-relay.tmp */
		rename(OPEN_SMTP_TMP_FILE, OPEN_SMTP_CUR_FILE);
		/* set correct permissions on file */
		chown(OPEN_SMTP_CUR_FILE,VPOPMAILUID,VPOPMAILGID);
	}
#endif
	/* Now, regardless of backend, build a new tcp.smtp.cdb file
	 *
	 * For mysql this involves combining the tcp.smtp file with
         * the contents of the relay table.
         * For cdb this involves combining the tcp.smtp file with
         * the contents of the open-relay file.
         * The resultant file will then be compiled by the tcprules tool
         * to make a new tcp.smtp.cdb file for tcpserver to use
         */
	update_rules();
	return(vexit(0));
}
#else
int main()
{
	printf("vpopmail not configure with --enable-roaming-users\n");
	return(vexit(0));
}
#endif /* POP_AUTH_OPEN_RELAY */
