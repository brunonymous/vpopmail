/*
 * $Id: backfill.c 1014 2011-02-03 16:04:37Z volz0r $
 * Copyright (C) 2009 Inter7 Internet Technologies, Inc.
 *
 * Revision 2.1  2009-01-12 10:38:56+05:30  Cprogrammer
 * function to backfill empty slots in dir_control
 *
 */
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "vpopmail.h"
#include "file_lock.h"
#include "vauth.h"

/*
 * Generic remove a line from a file utility
 * input: template to search for
 *        file to search inside
 *
 * output: less than zero on failure
 *         0 if successful
 *         1 if match found
 */
int
remove_line(char *template, char *filename, mode_t mode, int once_only)
{
	int             found;
	char            bak_file[MAX_BUFF], tmpbuf[MAX_BUFF];
	struct stat     statbuf;
	char           *ptr;
	FILE           *fs1, *fs2;
	int             fd;
#ifdef FILE_LOCKING
	int             lockfd;
	char 			lockfile[MAX_BUFF];
#endif

	if (stat(filename, &statbuf))
	{
		fprintf(stderr, "%s: %s\n", filename, strerror(errno));
		return (-1);
	}
#ifdef FILE_LOCKING
	snprintf(lockfile, sizeof(lockfile), "%s.lock", filename);
	if ((lockfd = open(lockfile, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR)) < 0)
	{
		fprintf(stderr, "could not open lock file %s: %s\n", lockfile, strerror(errno));
		return(-1);
	}
	if (get_write_lock(lockfd) < 0 )
		return(-1);
#endif
	/*- format a new string */
	snprintf(bak_file, MAX_BUFF, "%s.bak", filename);
	if (rename(filename, bak_file))
	{
		fprintf(stderr, "rename %s->%s: %s\n", filename, bak_file, strerror(errno));
#ifdef FILE_LOCKING
		unlock_lock(lockfd, 0, SEEK_SET, 0);
		close(lockfd);
#endif
		return(-1);
	}
	/*- open the file and check for error */
	if (!(fs1 = fopen(filename, "w+")))
	{
		rename(bak_file, filename);
#ifdef FILE_LOCKING
		unlock_lock(lockfd, 0, SEEK_SET, 0);
		close(lockfd);
#endif
		fprintf(stderr, "fopen(%s, w+: %s\n", filename, strerror(errno));
		return (-1);
	}
	fd = fileno(fs1);
	if (fchmod(fd, mode) || fchown(fd, statbuf.st_uid, statbuf.st_gid))
	{
		rename(bak_file, filename);
#ifdef FILE_LOCKING
		unlock_lock(lockfd, 0, SEEK_SET, 0);
		close(lockfd);
#endif
		fprintf(stderr, "chmod(%s, %d, %d, %o): %s\n", filename, statbuf.st_uid, statbuf.st_gid, mode, 
				strerror(errno));
		return (-1);
	}
	/*- open in read mode and check for error */
	if (!(fs2 = fopen(bak_file, "r+")))
	{
		rename(bak_file, filename);
#ifdef FILE_LOCKING
		unlock_lock(lockfd, 0, SEEK_SET, 0);
		close(lockfd);
#endif
		fprintf(stderr, "fopen(%s, r+): %s\n", filename, strerror(errno));
		fclose(fs1);
		return (-1);
	}
	/*- pound away on the files run the search algorythm */
	for (found = 0;;)
	{
		if (!fgets(tmpbuf, MAX_BUFF, fs2))
			break;
		if ((ptr = strchr(tmpbuf, '\n')) != NULL)
			*ptr = 0;
		if (once_only & found)
		{
			fprintf(fs1, "%s\n", tmpbuf);
			continue;
		}
		if (strncmp(template, tmpbuf, strlen(template)))
			fprintf(fs1, "%s\n", tmpbuf);
		else
			found++;
	}
	fclose(fs1);
	fclose(fs2);
	unlink(bak_file);
#ifdef FILE_LOCKING
	unlock_lock(lockfd, 0, SEEK_SET, 0);
	close(lockfd);
#endif
	/*
	 * return 0 = everything went okay, but we didn't find it
	 *        1 = everything went okay and we found a match
	 */
	return (found);
}

char *
backfill(char *username, char *domain, char *path, int operation)
{
    vdir_type       vdir;
	char           *ptr = (char *) 0;
	char            filename[MAX_BUFF];
	static char     tmpbuf[MAX_BUFF];
	int             count, len;
#ifdef FILE_LOCKING
	char            lockfile[MAX_BUFF];
	int             lockfd;
#endif
	uid_t           uid;
	gid_t           gid;
	FILE           *fp;

	if (!domain || !*domain)
		return ((char *) 0);
	if (!(ptr = vget_assign(domain, NULL, 0, &uid, &gid)))
	{
		fprintf(stderr, "%s: No such domain\n", domain);
		return((char *) 0);
	}
	snprintf(filename, MAX_BUFF, "%s/.dir_control_free", ptr);
	if (operation == 1) /*- Delete */
	{
		if (!(fp = fopen(filename, "r")))
			return ((char *) 0);
		for (count = 1;;count++)
		{
			if (!fgets(tmpbuf, MAX_BUFF - 2, fp))
			{
				fclose(fp);
				return ((char *) 0);
			}
			if (tmpbuf[(len = strlen(tmpbuf)) - 1] != '\n')
			{
				fprintf(stderr, "Line No %d in %s Exceeds %d chars\n", count, filename, MAX_BUFF - 2);
				fclose(fp);
				return ((char *) 0);
			}
			if ((ptr = strchr(tmpbuf, '#')))
				*ptr = '\0';
			for (ptr = tmpbuf; *ptr && isspace((int) *ptr); ptr++);
			if (!*ptr)
				continue;
			tmpbuf[len - 1] = 0;
			break;
		}
		fclose(fp);
		if (remove_line(ptr, filename, VPOPMAIL_QMAIL_MODE, 1) == 1)
		{
			vread_dir_control(&vdir, domain, uid, gid);
			if (vdir.cur_users)
				++vdir.cur_users;
			vwrite_dir_control(&vdir, domain, uid, gid);
			return (ptr);
		}
	} else
	if (operation == 2) /*- add */
	{
		(void) strncpy(tmpbuf, path, MAX_BUFF);
		if ((ptr = strstr(tmpbuf, username)))
		{
			if (ptr != tmpbuf)
				ptr--;
			if (*ptr == '/')
				*ptr = 0;
		}
		if ((ptr = strstr(tmpbuf, domain)))
		{
			ptr += strlen(domain);
			if (*ptr == '/')
				ptr++;
			if (ptr && *ptr)
			{
#ifdef FILE_LOCKING
				snprintf(lockfile, sizeof(lockfile), "%s.lock", filename);
				if ((lockfd = open(lockfile, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR)) < 0)
				{
					fprintf(stderr, "could not open lock file %s: %s\n", lockfile, strerror(errno));
					return((char *) 0);
				}
				if (get_write_lock(lockfd) < 0 )
					return((char *) 0);
#endif
				if (!(fp = fopen(filename, "a")))
				{
#ifdef FILE_LOCKING
					unlock_lock(lockfd, 0, SEEK_SET, 0);
					close(lockfd);
#endif
					return((char *) 0);
				}
				fprintf(fp, "%s\n", ptr);
				fclose(fp);
#ifdef FILE_LOCKING
				unlock_lock(lockfd, 0, SEEK_SET, 0);
				close(lockfd);
#endif
				return(ptr);
			}
		}
	}
	return((char *) 0);
}
