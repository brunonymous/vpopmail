/*
 * $Id: vrcptcheck.c 2021-09-23
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
 * Recipient check for s/qmail.
 * Just call this program within /var/qmail/control/recipients as follows:
 * cat /home/vpopmail/bin/vrcptcheck > /var/qmail/control/recipients

 * @file vrcptcheck.c
   @return 0: virtual user exists
           1: virtual user does not exist
           111: temporary problem
 */

#include <dirent.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "vpopmail.h"

#define FDAUTH 3
char inputbuf[MAX_BUFF];

void pam_exit(int fail, DIR *dir)
{
	int i;
	close(FDAUTH);
	for (i = 0; i < sizeof(inputbuf); ++i) inputbuf[i] = 0;
	if (dir != NULL) closedir(dir);
	vexit(fail);
}

void main(int argc, char *argv[])
{
	char path[MAX_BUFF];
	DIR *dir;

        /* read input */
        if (read(FDAUTH, inputbuf, sizeof(inputbuf)) == -1)
        {
                fprintf(stderr, "qmail-smtpd: Error while reading file descriptor in vrcptcheck\n");
                pam_exit(111,NULL);
        }
        close(FDAUTH);

        /* retrieve username/domain (assuming that MAV has already been done) */
        int i = 0;
        char *p = strtok (inputbuf, "@");
        char *recipient[2];
        while (p != NULL)
        {
                recipient[i++] = p;
                p = strtok (NULL, "@");
        }

	/* recipient check */
	snprintf(path, MAX_BUFF, "%s/%s", vget_assign(recipient[1], NULL, 0, NULL, NULL), recipient[0]);
	dir = opendir(path);
	if (dir) pam_exit(0, dir);
	else pam_exit(1, dir);
}
