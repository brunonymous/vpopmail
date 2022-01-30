/*
 * $Id: maildirquota.c 1029 2011-02-28 16:59:25Z volz0r $
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
 *
 */

/* include files */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>
#include "vauth.h"
#include "vpopmail.h"
#include "vlimits.h"
#include "maildirquota.h"
#include "config.h"
#include "conf.h"
#include "storage.h"
#include "client.h"

/* private functions - no name clashes with courier */
static char *makenewmaildirsizename(const char *, int *);
static int countcurnew(const char *dir, time_t *maxtime, storage_t *sizep, storage_t *cntp);
static int countsubdir(const char *dir, const char *subdir, time_t *maxtime, storage_t *sizep, storage_t *cntp);
static int statcurnew(const char *dir, time_t *maxtimestamp);
static int statsubdir(const char *dir, const char *subdir, time_t *maxtime);
static int doaddquota(const char *dir, int maildirsize_fd, const char *quota_type, 
                      storage_t maildirsize_size, storage_t maildirsize_cnt, int isnew);
static int docheckquota(const char *dir, int *maildirsize_fdptr, const char *quota_type, 
                        storage_t xtra_size, storage_t xtra_cnt, int *percentage);
static int docount(const char *dir, time_t *dirstamp, storage_t *sizep, storage_t *cntp);
static int maildir_checkquota(const char *dir, int *maildirsize_fdptr, const char *quota_type, storage_t xtra_size, storage_t xtra_cnt);
/*  moved into maildirquota.h as non-static
static int maildir_addquota(const char *dir, int maildirsize_fd,
	const char *quota_type, long maildirsize_size, int maildirsize_cnt);
*/
static int maildir_safeopen(const char *path, int mode, int perm);
static char *str_pid_t(pid_t t, char *arg);
static char *str_time_t(time_t t, char *arg);
static int maildir_parsequota(const char *n, storage_t *s);

#define  NUMBUFSIZE      60
#define	MDQUOTA_SIZE	'S'	/* Total size of all messages in maildir */
#define	MDQUOTA_BLOCKS	'B'	/* Total # of blocks for all messages in
				maildir -- NOT IMPLEMENTED */
#define	MDQUOTA_COUNT	'C'	/* Total number of messages in maildir */

int quota_mtos(const char *, storage_t *, storage_t *);
int quota_user_usage(const char *, storage_t *, storage_t *);

/* bk: add domain limits functionality */
int domain_over_maildirquota(const char *userdir)
{
struct  stat    stat_buf;
char	domdir[MAX_PW_DIR];
char	*p;
char	domain[256], qb[256] = { 0 };
storage_t size = 0;
storage_t maxsize = 0;
storage_t cnt = 0;
int	ret = 0;
storage_t maxcnt = 0;
struct vlimits limits;
   storage_t susage = 0, cusage = 0;

        if (fstat(0, &stat_buf) == 0 && S_ISREG(stat_buf.st_mode) &&
                stat_buf.st_size > 0)
        {

		/* locate the domain directory */
		p = maildir_to_email(userdir);
		if (p == NULL) return -1;

		p = strchr (p, '@');
		if (p == NULL) return -1;

		strcpy(domain, p + 1);

		/* get the domain quota */
		if (vget_limits(domain, &limits)) return 0;
		/* convert from MB to bytes */
		maxsize = limits.diskquota * 1024 * 1024;
		maxcnt = limits.maxmsgcount;

                /* only check the quota if one is set  */
                if(( maxsize==0 ) && (maxcnt==0)) return 0;

		if (vget_assign (domain, domdir, sizeof(domdir), NULL, NULL) == NULL)
			return -1;

		/* get the domain usage */

		 ret = strlen(domain);

		 if ((ret + 2) < sizeof(qb)) {
			*qb = '@';
			memcpy((qb + 1), domain, ret);
			*(qb + ret + 1) = '\0';

			ret = client_query_quick(qb, &susage, &cusage);
			if (ret) {
			   if ((susage + stat_buf.st_size) > maxsize)
				  return 1;

			   if ((maxcnt) && (cusage >= maxcnt))
				  return 1;

			   return 0;
			}
		 }

		 if (readdomainquota(domdir, &size, &cnt)) return -1;

		/* check if either quota (size/count) would be exceeded */
		if (maxsize > 0 && (size + stat_buf.st_size) > maxsize) return 1;
		else if (maxcnt > 0 && cnt >= maxcnt) return 1;
        }

        return 0;
}

int readdomainquota(const char *dir, storage_t *sizep, storage_t *cntp)
{
int tries;
char	checkdir[256];
DIR	*dirp;
struct dirent *de;


	if (dir == NULL || sizep == NULL || cntp == NULL)
		return -1;

	*sizep = 0;
	*cntp = 0;

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;

#ifdef USERS_BIG_DIR
		if (strlen(de->d_name) == 1) {
			/* recursive call for hashed directory */
			snprintf (checkdir, sizeof(checkdir), "%s/%s", dir, de->d_name);
			if (readdomainquota (checkdir, sizep, cntp) == -1) {
				return -1;
			}
		} else
#endif
		{
			snprintf(checkdir, sizeof(checkdir), "%s/%s/Maildir/", dir, de->d_name);
			tries = 5;
			while (tries-- && readuserquota(checkdir, sizep, cntp))
			{
				if (errno != EAGAIN) return -1;
				sleep(1);
			}
			if (tries <= 0)
				return -1;
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			return (-1);
		}
#endif
	}

	return 0;
}

int wrapreaduserquota(const char* dir, storage_t *sizep, storage_t *cntp)
{
time_t	tm;
time_t	maxtime;
DIR	*dirp;
struct dirent *de;

	maxtime=0;

	if (countcurnew(dir, &maxtime, sizep, cntp))
	{
		return (-1);
	}

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (countsubdir(dir, de->d_name, &maxtime, sizep, cntp))
		{
			closedir(dirp);
			return (-1);
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			return (-1);
		}
#endif
	}

	/* make sure nothing changed while calculating this... */
	tm=0;

	if (statcurnew(dir, &tm))
	{
		return (-1);
	}

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (statsubdir(dir, de->d_name, &tm))
		{
			closedir(dirp);
			return (-1);
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			return (-1);
		}
#endif
	}

	if (tm != maxtime)	/* Race condition, someone changed something */
	{
		errno=EAGAIN;
		return (-1);
	}
	errno=0;

	return 0;
}
int readuserquota(const char* dir, storage_t *sizep, storage_t *cntp)
{
	int retval;
	storage_t s;
	
	s = (off_t) *sizep;
	retval = wrapreaduserquota(dir, &s, cntp);
	*sizep = (long) s;
	return retval;
}

int user_over_maildirquota( const char *dir, const char *q)
{
struct  stat    stat_buf;
int     quotafd = -1;
int     ret_value = 0;

        //   stat file              is regular file                size > 0               what is q?
        if (fstat(0, &stat_buf) == 0 && S_ISREG(stat_buf.st_mode) && stat_buf.st_size > 0 && *q)
        {       //   check the quota, and not again error
                if (maildir_checkquota(dir, &quotafd, q, stat_buf.st_size, 1) && errno != EAGAIN)
                {
                        if (quotafd >= 0)       close(quotafd);
                        ret_value = 1;
                } else {
                        //maildir_addquota(dir, quotafd, q, stat_buf.st_size, 1);
                        if (quotafd >= 0)       close(quotafd);
                        ret_value = 0;
                }
        } else {
                ret_value = 0;
        }

        return(ret_value);
}

void add_warningsize_to_quota( const char *dir, const char *q)
{
struct  stat    stat_buf;
int     quotafd;
char    quotawarnmsg[500];

        snprintf(quotawarnmsg, sizeof(quotawarnmsg), "%s/%s/.quotawarn.msg", VPOPMAILDIR, DOMAINS_DIR);

        if (stat(quotawarnmsg, &stat_buf) == 0 && S_ISREG(stat_buf.st_mode) &&
                stat_buf.st_size > 0 && *q)
        {
                maildir_checkquota(dir, &quotafd, q, stat_buf.st_size, 1);
                if (quotafd >= 0)       close(quotafd);
                maildir_addquota(dir, quotafd, q, 
                    stat_buf.st_size, 1);
                if (quotafd >= 0)       close(quotafd);
        }
}

/* Read the maildirsize file */

static int maildirsize_read(const char *filename,	/* The filename */
	int *fdptr,	/* Keep the file descriptor open */
	storage_t *sizeptr,	/* Grand total of maildir size */
	storage_t *cntptr, /* Grand total of message count */
	unsigned *nlines, /* # of lines in maildirsize */
	struct stat *statptr)	/* The stats on maildirsize */
{
 char buf[5120];
 int f;
 char *p;
 unsigned l;
 storage_t n;
 int first;
 int ret = 0;

	if ((f=maildir_safeopen(filename, O_RDWR|O_APPEND, 0)) < 0)
		return (-1);
	p=buf;
	l=sizeof(buf);

	/*
		 Maildir++ specification says to rebuild the maildirsize file if the
		 file is 5120 or more bytes, or is more than 15 minutes old
    */

	ret = fstat(f, statptr);
	if ((ret != -1) && ((statptr->st_size >= 5120) || (time(NULL) > statptr->st_mtime + (15*60)))) {
	   unlink(filename);
	   close(f);
	   return -1;
    }

	while (l)
	{
		n=read(f, p, l);
		if (n < 0)
		{
			close(f);
			return (-1);
		}
		if (n == 0)	break;
		p += n;
		l -= n;
	}
	if (l == 0 || ret)	/* maildir too big */
	{
		close(f);
		return (-1);
	}

	*sizeptr=0;
	*cntptr=0;
	*nlines=0;
	*p=0;
	p=buf;
	first=1;
	while (*p)
	{
	storage_t n=0;
	storage_t c=0;
	char	*q=p;

		while (*p)
			if (*p++ == '\n')
			{
				p[-1]=0;
				break;
			}

		if (first)
		{
			first=0;
			continue;
		}
		sscanf(q, "%llu %llu", &n, &c);
		*sizeptr += n;
		*cntptr += c;
		++ *nlines;
	}
	*fdptr=f;
	return (0);
}

static int qcalc(storage_t s, storage_t n, const char *quota, int *percentage)
{
storage_t i;
int	spercentage=0;
int	npercentage=0;

	errno=ENOSPC;
	while (quota && *quota)
	{
		int x=1;

		if (*quota < '0' || *quota > '9')
		{
			++quota;
			continue;
		}
		i=0;
		while (*quota >= '0' && *quota <= '9')
			i=i*10 + (*quota++ - '0');
		switch (*quota)	{
		default:
			if (i < s)
			{
				*percentage=100;
				return (-1);
			}

#if 0
			/*
			** For huge quotas, over 20mb,
			** divide numerator & denominator by 1024 to prevent
			** an overflow when multiplying by 100
			*/

			x=1;
			if (i > 20000000) x=1024;
#endif

			spercentage = i ? (s/x) * 100 / (i/x):100;
			break;
		case 'C':

			if (i < n)
			{
				*percentage=100;
				return (-1);
			}

#if 0
			/* Ditto */

			x=1;
			if (i > 20000000) x=1024;
#endif

			npercentage = i ? ((off_t)n/x) * 100 / (i/x):100;
			break;
		}
	}
	*percentage = spercentage > npercentage ? spercentage:npercentage;
	return (0);
}

static int maildir_checkquota(const char *dir,
	int *maildirsize_fdptr,
	const char *quota_type,
	storage_t xtra_size,
	storage_t xtra_cnt)
{
int	dummy, ret = 0;

   if ((xtra_size == 0) || (xtra_cnt == 0))
	  return 0;

   /*
	  Ping the daemon
   */

   ret = client_query_quick(" ", NULL, NULL);
   if (ret) {
      ret = vmaildir_readquota(dir, quota_type);
	  if (ret >= 100)
		 return -1;

	  return 0;
   }

   /*
	  Fall back
   */

	return (docheckquota(dir, maildirsize_fdptr, quota_type,
		xtra_size, xtra_cnt, &dummy));
}

int vmaildir_readquota(const char *dir, const char *quota_type)
{
   int	percentage=0;
   int	fd=-1;
   int ret = 0;
   char *email = NULL;
   storage_t uusage = 0, dusage = 0, usquota = 0, ucquota = 0;

   /*
	  Get user usage
   */

   email = maildir_to_email(dir);
   ret = client_query_quick(email, &uusage, &dusage);
   if (ret) {
	  if (uusage != -1) {
		 /*
			Convert quota string to integers
		 */

		 quota_mtos(quota_type, &usquota, &ucquota);

		 /*
			Return percentage
		 */

		 fd = (int)((long double)((long double)uusage/(long double)usquota) * (long double)100.0);
		 if (fd > 100)
			fd = 100;

		 if (fd < 0)
			fd = 0;

		 return fd;
	  }

	  return 0;
   }

   /*
	  If usage daemon is not running, fall back on old methods
   */

	(void)docheckquota(dir, &fd, quota_type, 0, 0, &percentage);
	if (fd >= 0)
		close(fd);
	return (percentage);
}

static int docheckquota(const char *dir,
	int *maildirsize_fdptr,
	const char *quota_type,
	storage_t xtra_size,
	storage_t xtra_cnt,
	int *percentage)
{
char	*checkfolder=(char *)malloc(strlen(dir)+sizeof("/maildirfolder"));
char	*newmaildirsizename;
struct stat stat_buf;
int	maildirsize_fd = -1;
storage_t maildirsize_size;
storage_t maildirsize_cnt;
unsigned maildirsize_nlines;
int	n;
time_t	tm;
time_t	maxtime;
DIR	*dirp;
struct dirent *de;

	if (checkfolder == 0)	return (-1);
	*maildirsize_fdptr= -1;
	strcat(strcpy(checkfolder, dir), "/maildirfolder");
	if (stat(checkfolder, &stat_buf) == 0)	/* Go to parent */
	{
		strcat(strcpy(checkfolder, dir), "/..");
		n=docheckquota(checkfolder, maildirsize_fdptr,
			quota_type, xtra_size, xtra_cnt, percentage);
		free(checkfolder);
		return (n);
	}
	if (!quota_type || !*quota_type)	return (0);

	strcat(strcpy(checkfolder, dir), "/maildirsize");
	time(&tm);
	if (maildirsize_read(checkfolder, &maildirsize_fd,
		&maildirsize_size, &maildirsize_cnt,
		&maildirsize_nlines, &stat_buf) == 0)
	{
		n=qcalc(maildirsize_size+xtra_size, maildirsize_cnt+xtra_cnt,
			quota_type, percentage);

		if (n == 0)
		{
			free(checkfolder);
			*maildirsize_fdptr=maildirsize_fd;
			return (0);
		}
		close(maildirsize_fd);

		if (maildirsize_nlines == 1 && tm < stat_buf.st_mtime + 15*60)
			return (n);
	}

        /* rebuild the maildirsizefile  */

	maxtime=0;
	maildirsize_size=0;
	maildirsize_cnt=0;

	if (countcurnew(dir, &maxtime, &maildirsize_size, &maildirsize_cnt))
	{
		free(checkfolder);
		return (-1);
	}

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (countsubdir(dir, de->d_name, &maxtime, &maildirsize_size,
			&maildirsize_cnt))
		{
			free(checkfolder);
			closedir(dirp);
			return (-1);
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			free(checkfolder);
			return (-1);
		}
#endif
	}

	newmaildirsizename=makenewmaildirsizename(dir, &maildirsize_fd);
	if (!newmaildirsizename)
	{
		free(checkfolder);
		return (-1);
	}

	chown(newmaildirsizename, VPOPMAILUID, VPOPMAILGID);
	*maildirsize_fdptr=maildirsize_fd;

	if (doaddquota(dir, maildirsize_fd, quota_type, maildirsize_size,
		maildirsize_cnt, 1))
	{
		close(maildirsize_fd);
		unlink(newmaildirsizename);
		*maildirsize_fdptr= -1;
		free(newmaildirsizename);
		free(checkfolder);
		return (-1);
	}

	strcat(strcpy(checkfolder, dir), "/maildirsize");

	if (rename(newmaildirsizename, checkfolder))
	{
		unlink(newmaildirsizename);
		close(maildirsize_fd);
		*maildirsize_fdptr= -1;
	}
	free(checkfolder);
	free(newmaildirsizename);

	tm=0;

	if (statcurnew(dir, &tm))
	{
		close(maildirsize_fd);
		*maildirsize_fdptr= -1;
		return (-1);
	}

	dirp=opendir(dir);
	while (dirp && (de=readdir(dirp)) != 0)
	{
		if (statsubdir(dir, de->d_name, &tm))
		{
			close(maildirsize_fd);
			*maildirsize_fdptr= -1;
			closedir(dirp);
			return (-1);
		}
	}
	if (dirp)
	{
#if	CLOSEDIR_VOID
		closedir(dirp);
#else
		if (closedir(dirp))
		{
			close(maildirsize_fd);
			*maildirsize_fdptr= -1;
			return (-1);
		}
#endif
	}

	if (tm != maxtime)	/* Race condition, someone changed something */
	{
		errno=EAGAIN;
		return (-1);
	}

	return (qcalc(maildirsize_size+xtra_size, maildirsize_cnt+xtra_cnt,
		quota_type, percentage));
}

int	maildir_addquota(const char *dir, int maildirsize_fd,
	const char *quota_type, storage_t maildirsize_size, storage_t maildirsize_cnt)
{
   int ret = 0;

   /*
	  Ping the usage daemon
	  If it's running, we're done here.
   */

   ret = client_query_quick(" ", NULL, NULL);
   if (ret)
	  return 0;

   /*
	  Fall back
   */

	if (!quota_type || !*quota_type)	return (0);
	return (doaddquota(dir, maildirsize_fd, quota_type, maildirsize_size,
			maildirsize_cnt, 0));
}

static int doaddquota(const char *dir, int maildirsize_fd,
	const char *quota_type, storage_t maildirsize_size, storage_t maildirsize_cnt,
	int isnew)
{
union	{
	char	buf[100];
	struct stat stat_buf;
	} u;				/* Scrooge */
char	*newname2=0;
char	*newmaildirsizename=0;
struct	iovec	iov[3];
int	niov;
struct	iovec	*p;
int	n;

	niov=0;
	if ( maildirsize_fd < 0)
	{
		newname2=(char *)malloc(strlen(dir)+sizeof("/maildirfolder"));
		if (!newname2)	return (-1);
		strcat(strcpy(newname2, dir), "/maildirfolder");
		if (stat(newname2, &u.stat_buf) == 0)
		{
			strcat(strcpy(newname2, dir), "/..");
			n=doaddquota(newname2, maildirsize_fd, quota_type,
					maildirsize_size, maildirsize_cnt,
					isnew);
			free(newname2);
			return (n);
		}

		strcat(strcpy(newname2, dir), "/maildirsize");

		if ((maildirsize_fd=maildir_safeopen(newname2,
			O_RDWR|O_APPEND, 0644)) < 0)
		{
			newmaildirsizename=makenewmaildirsizename(dir, &maildirsize_fd);
			if (!newmaildirsizename)
			{
				free(newname2);
				return (-1);
			}

			maildirsize_fd=maildir_safeopen(newmaildirsizename,
				O_CREAT|O_RDWR|O_APPEND, 0644);

			if (maildirsize_fd < 0)
			{
				free(newname2);
				return (-1);
			}
			isnew=1;
		}
	}

	if (isnew)
	{
		iov[0].iov_base=(void *)quota_type;
		iov[0].iov_len=strlen(quota_type);
		iov[1].iov_base="\n";
		iov[1].iov_len=1;
		niov=2;
	}

	sprintf(u.buf, "%llu %llu\n", maildirsize_size, maildirsize_cnt);
	iov[niov].iov_base=u.buf;
	iov[niov].iov_len=strlen(u.buf);

	p=iov;
	++niov;
	n=0;
	while (niov)
	{
		if (n)
		{
			if (n < p->iov_len)
			{
				p->iov_base=
					((char *)p->iov_base + n);
				p->iov_len -= n;
			}
			else
			{
				n -= p->iov_len;
				++p;
				--niov;
				continue;
			}
		}

		n=writev( maildirsize_fd, p, niov);

		if (n <= 0)
		{
			if (newname2)
			{
				close(maildirsize_fd);
				free(newname2);
			}
			return (-1);
		}
	}
	if (newname2)
	{
		close(maildirsize_fd);

		if (newmaildirsizename)
		{
			rename(newmaildirsizename, newname2);
			free(newmaildirsizename);
		}
		free(newname2);
	}
	return (0);
}

/* New maildirsize is built in the tmp subdirectory */

static char *makenewmaildirsizename(const char *dir, int *fd)
{
char	hostname[256];
struct	stat stat_buf;
time_t	t;
char	*p;
int i;

	hostname[0]=0;
	hostname[sizeof(hostname)-1]=0;
	gethostname(hostname, sizeof(hostname)-1);
	p=(char *)malloc(strlen(dir)+strlen(hostname)+130);
	if (!p)	return (0);

        /* do not hang forever */
	for (i=0;i<3;++i)
	{
	char	tbuf[NUMBUFSIZE];
	char	pbuf[NUMBUFSIZE];

		time(&t);
		strcat(strcpy(p, dir), "/tmp/");
		sprintf(p+strlen(p), "%s.%s_NeWmAiLdIrSiZe.%s",
			str_time_t(t, tbuf),
			str_pid_t(getpid(), pbuf), hostname);

		if (stat( (const char *)p, &stat_buf) < 0 &&
			(*fd=maildir_safeopen(p,
				O_CREAT|O_RDWR|O_APPEND, 0644)) >= 0)
			break;
		usleep(100);
	}
	return (p);
}

static int statcurnew(const char *dir, time_t *maxtimestamp)
{
char	*p=(char *)malloc(strlen(dir)+5);
struct	stat	stat_buf;

	if (!p)	return (-1);
	strcat(strcpy(p, dir), "/cur");
	if ( stat(p, &stat_buf) == 0 && stat_buf.st_mtime > *maxtimestamp)
		*maxtimestamp=stat_buf.st_mtime;
	strcat(strcpy(p, dir), "/new");
	if ( stat(p, &stat_buf) == 0 && stat_buf.st_mtime > *maxtimestamp)
		*maxtimestamp=stat_buf.st_mtime;
	free(p);
	return (0);
}

static int statsubdir(const char *dir, const char *subdir, time_t *maxtime)
{
char	*p;
int	n;

	if ( *subdir != '.' || strcmp(subdir, ".") == 0 ||
		strcmp(subdir, "..") == 0 || strcmp(subdir, ".Trash") == 0)
		return (0);

	p=(char *)malloc(strlen(dir)+strlen(subdir)+2);
	if (!p)	return (-1);
	strcat(strcat(strcpy(p, dir), "/"), subdir);
	n=statcurnew(p, maxtime);
	free(p);
	return (n);
}

static int countcurnew(const char *dir, time_t *maxtime, storage_t *sizep, storage_t *cntp)
{
char	*p=(char *)malloc(strlen(dir)+5);
int	n;

	if (!p)	return (-1);
	strcat(strcpy(p, dir), "/new");
	n=docount(p, maxtime, sizep, cntp);
	if (n == 0)
	{
		strcat(strcpy(p, dir), "/cur");
		n=docount(p, maxtime, sizep, cntp);
	}
	free(p);
	return (n);
}

static int countsubdir(const char *dir, const char *subdir, time_t *maxtime, storage_t *sizep, storage_t *cntp)
{
char	*p;
int	n;

	if ( *subdir != '.' || strcmp(subdir, ".") == 0 ||
		strcmp(subdir, "..") == 0 || strcmp(subdir, ".Trash") == 0)
		return (0);

	p=(char *)malloc(strlen(dir)+strlen(subdir)+2);
	if (!p)	return (2);
	strcat(strcat(strcpy(p, dir), "/"), subdir);
	n=countcurnew(p, maxtime, sizep, cntp);
	free(p);
	return (n);
}

static int docount(const char *dir, time_t *dirstamp, storage_t *sizep, storage_t *cntp)
{
struct	stat	stat_buf;
char	*p;
DIR	*dirp;
struct dirent *de;
storage_t s;

	if (stat(dir, &stat_buf))	return (0);	/* Ignore */
	if (stat_buf.st_mtime > *dirstamp)	*dirstamp=stat_buf.st_mtime;
	if ((dirp=opendir(dir)) == 0)	return (0);
	while ((de=readdir(dirp)) != 0)
	{
	const char *n=de->d_name;

		if (*n == '.')	continue;

		/* PATCH - do not count msgs marked as deleted */

		for ( ; *n; n++)
		{
			if (n[0] != ':' || n[1] != '2' ||
				n[2] != ',')	continue;
			n += 3;
			while (*n >= 'A' && *n <= 'Z')
			{
				if (*n == 'T')	break;
				++n;
			}
			break;
		}
		if (*n == 'T')	continue;
		n=de->d_name;


		if (maildir_parsequota(n, &s) == 0)
		   *sizep += s;
		else
		{
			p=(char *)malloc(strlen(dir)+strlen(n)+2);
			if (!p)
			{
				closedir(dirp);
				return (-1);
			}
			strcat(strcat(strcpy(p, dir), "/"), n);
			if (stat(p, &stat_buf))
			{
				free(p);
				continue;
			}
			free(p);
			*sizep += stat_buf.st_size;
		}
		++*cntp;
	}

#if	CLOSEDIR_VOID
	closedir(dirp);
#else
	if (closedir(dirp))
		return (-1);
#endif
	return (0);
}

static int maildir_safeopen(const char *path, int mode, int perm)
{
struct  stat    stat1, stat2;

int     fd=open(path, mode
#ifdef  O_NONBLOCK
                        | O_NONBLOCK
#else
                        | O_NDELAY
#endif
                                , perm);

        if (fd < 0)     return (fd);
        if (fcntl(fd, F_SETFL, (mode & O_APPEND)) || fstat(fd, &stat1)
            || lstat(path, &stat2))
        {
                close(fd);
                return (-1);
        }

        if (stat1.st_dev != stat2.st_dev || stat1.st_ino != stat2.st_ino)
        {
                close(fd);
                errno=ENOENT;
                return (-1);
        }

        return (fd);
}

static char *str_pid_t(pid_t t, char *arg)
{
char    buf[NUMBUFSIZE];
char    *p=buf+sizeof(buf)-1;

        *p=0;
        do
        {
                *--p= '0' + (t % 10);
                t=t / 10;
        } while(t);
        return (strcpy(arg, p));
}

static char *str_time_t(time_t t, char *arg)
{
char    buf[NUMBUFSIZE];
char    *p=buf+sizeof(buf)-1;

        *p=0;
        do
        {
                *--p= '0' + (t % 10);
                t=t / 10;
        } while(t);
        return (strcpy(arg, p));
}

static int maildir_parsequota(const char *n, storage_t *s)
{
const char *o;
int     yes;

        if ((o=strrchr(n, '/')) == 0)   o=n;

        for (; *o; o++)
                if (*o == ':')  break;
        yes=0;
        for ( ; o >= n; --o)
        {
                if (*o == '/')  break;

                if (*o == ',' && o[1] == 'S' && o[2] == '=')
                {
                        yes=1;
                        o += 3;
                        break;
                }
        }
        if (yes)
        {
                *s=0;
                while (*o >= '0' && *o <= '9')
                        *s= *s*10 + (*o++ - '0');

                return (0);
        }
        return (-1);
}

/*
   Converts a Maildir++ quota to storage_t values
   Does not perform full syntax checking on quota format
*/

int quota_mtos(const char *quota, storage_t *size, storage_t *count)
{
   storage_t ts = 0;
   const char *h = NULL, *t = NULL;

   if (quota == NULL)
	  return 0;

   /*
	  Set default values
   */

   if (size != NULL)
	  *size = 0;

   if (count != NULL)
	  *count = 0;

   /*
	  Parse out seperate Maildir++ parts
   */

   h = t = quota;

   while(1) {
	  if ((*h == ',') || (!(*h))) {
		 switch(*(h - 1)) {
			case 'S':
			   if (size) {
				  ts = strtoll(t, NULL, 10);
				  if (ts != -1)
					 *size = ts;

				  size = NULL;
			   }

			   break;

			case 'C':
			   if (count) {
				  ts = strtoll(t, NULL, 10);
				  if (ts != -1)
					 *count = ts;

				  count = NULL;
			   }

			   break;

			default:
			   /*
				  Default is type S
			   */

			   if ((!(*h)) && (size)) {
				  ts = strtoll(t, NULL, 10);
				  if (ts != -1)
					 *size = ts;

				  size = NULL;
			   }

			   /*
				  Unknown type
			   */

			   break;
		 }

		 if (!(*h))
			break;

		 while(*h == ',')
			h++;

		 t = h;
	  }

	  else
		 h++;
   }

   return 1;
}

/*
   Returns disk usage information for user and user's domain from
   the vpopmail usage daemon
*/

int quota_user_usage(const char *user, storage_t *uusage, storage_t *dusage)
{
   int ret = 0;

   if ((user == NULL) || (uusage == NULL) || (dusage == NULL) || (!(*user)))
	  return 0;

   ret = client_query_quick(user, uusage, dusage);
   return ret;
}

