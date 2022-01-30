/* 
   $Id: maildirquota.h 1014 2011-02-03 16:04:37Z volz0r $
   Copyright (C) 2009 Inter7 Internet Technologies, Inc.
 
   This is a composite of deliverquota's maildirquota.h, maildirmisc.h, and 
   numlib.h.  I only consolidated them to keep this patch to vpopmail  a bit 
   less intrusive.
   -Bill Shupp
 */

#include "storage.h"

#define QUOTA_WARN_PERCENT 90

/* I've removed pretty much the whole file execept for
   some public functions so as to not conflict with courier.
   I"ve made the courier functions static.
   - Brian Kolaci
*/
int readdomainquota(const char *dir, storage_t *sizep, storage_t *cntp);
int readuserquota(const char* dir, storage_t *sizep, storage_t *cntp);
int domain_over_maildirquota(const char *userdir);
int user_over_maildirquota(const char *dir, const char *quota);
int vmaildir_readquota(const char *dir,	const char *quota);

int maildir_addquota(const char *,	/* Pointer to the maildir */
	int,	/* Must be the int pointed to by 2nd arg to checkquota */
	const char *,	/* The quota */
	storage_t,	/* +/- bytes */
	storage_t);	/* +/- files */

/* skip the rest... */
#if 0

/* from maildirquota.h */

#ifndef	maildirquota_h
#define	maildirquota_h

/*
** Copyright 1998 - 1999 Double Precision, Inc.
** See COPYING for distribution information.
*/

#include	<sys/types.h>
#include	<stdio.h>
#include	<time.h>

#ifdef  __cplusplus
extern "C" {
#endif

static const char maildirquota_h_rcsid[]="$Id: maildirquota.h 1014 2011-02-03 16:04:37Z volz0r $";

int maildir_checkquota(const char *,	/* Pointer to directory */
	int *,	/* Initialized to -1, or opened descriptor for maildirsize */
	const char *,	/* The quota */
	long,		/* Extra bytes planning to add/remove from maildir */
	int);		/* Extra messages planning to add/remove from maildir */

int maildir_readquota(const char *,	/* Directory */
	const char *);			/* Quota, from getquota */

int maildir_parsequota(const char *, unsigned long *);
	/* Attempt to parse file size encoded in filename.  Returns 0 if
	** parsed, non-zero if we didn't parse. */

#ifdef  __cplusplus
}
#endif

#endif




/* from maildirmisc.h */


#ifndef	maildirmisc_h
#define	maildirmisc_h

/*
** Copyright 2000 Double Precision, Inc.
** See COPYING for distribution information.
*/

#ifdef  __cplusplus
extern "C" {
#endif

static const char maildirmisc_h_rcsid[]="$Id: maildirquota.h 1014 2011-02-03 16:04:37Z volz0r $";

/*
**
** Miscellaneous maildir-related code
**
*/

/* Some special folders */

#define	INBOX	"INBOX"
#define	DRAFTS	"Drafts"
#define	SENT	"Sent"
#define	TRASH	"Trash"

#define	SHAREDSUBDIR	"shared-folders"

char *maildir_folderdir(const char *,		/* maildir */
	const char *);				/* folder name */
	/* Returns the directory corresponding to foldername (foldername is
	** checked to make sure that it's a valid name, else we set errno
	** to EINVAL, and return (0).
	*/

char *maildir_filename(const char *,		/* maildir */
	const char *,				/* folder */
	const char *);				/* filename */
	/*
	** Builds the filename to this message, suitable for opening.
	** If the file doesn't appear to be there, search the maildir to
	** see if someone changed the flags, and return the current filename.
	*/

int maildir_safeopen(const char *,		/* filename */
	int,				/* mode */
	int);				/* perm */

/*
**	Same arguments as open().  When we're accessing a shared maildir,
**	prevent someone from playing cute and dumping a bunch of symlinks
**	in there.  This function will open the indicate file only if the
**	last component is not a symlink.
**	This is implemented by opening the file with O_NONBLOCK (to prevent
**	a DOS attack of someone pointing the symlink to a pipe, causing
**	the open to hang), clearing O_NONBLOCK, then stat-int the file
**	descriptor, lstating the filename, and making sure that dev/ino
**	match.
*/

int maildir_semisafeopen(const char *,	/* filename */
	int,				/* mode */
	int);				/* perm */

/*
** Same thing, except that we allow ONE level of soft link indirection,
** because we're reading from our own maildir, which points to the
** message in the sharable maildir.
*/

int maildir_mkdir(const char *);	/* directory */
/*
** Create maildir including all subdirectories in the path (like mkdir -p)
*/

void maildir_purgetmp(const char *);		/* maildir */
	/* purges old stuff out of tmp */

void maildir_purge(const char *,		/* directory */
	unsigned);				/* time_t to purge */

void maildir_getnew(const char *,		/* maildir */
	const char *);				/* folder */
	/* move messages from new to cur */

int maildir_deletefolder(const char *,		/* maildir */
	const char *);				/* folder */
	/* deletes a folder */

int maildir_mddelete(const char *);	/* delete a maildir folder by path */

void maildir_list_sharable(const char *,	/* maildir */
	void (*)(const char *, void *),		/* callback function */
	void *);				/* 2nd arg to callback func */
	/* list sharable folders */

int maildir_shared_subscribe(const char *,	/* maildir */
		const char *);			/* folder */
	/* subscribe to a shared folder */

void maildir_list_shared(const char *,		/* maildir */
	void (*)(const char *, void *),		/* callback function */
	void *);			/* 2nd arg to the callback func */
	/* list subscribed folders */

int maildir_shared_unsubscribe(const char *,	/* maildir */
		const char *);			/* folder */
	/* unsubscribe from a shared folder */

char *maildir_shareddir(const char *,		/* maildir */
	const char *);				/* folder */
	/*
	** Validate and return a path to a shared folder.  folderdir must be
	** a name of a valid shared folder.
	*/

void maildir_shared_sync(const char *);		/* maildir */
	/* "sync" the shared folder */

int maildir_sharedisro(const char *);		/* maildir */
	/* maildir is a shared read-only folder */

int maildir_unlinksharedmsg(const char *);	/* filename */
	/* Remove a message from a shared folder */

/* Internal function that reads a symlink */

char *maildir_getlink(const char *);

	/* Determine whether the maildir filename has a certain flag */

int maildir_hasflag(const char *filename, char);

#define	MAILDIR_DELETED(f)	maildir_hasflag((f), 'T')

#ifdef  __cplusplus
}
#endif

#endif






/* from numlib.h */



#ifndef	numlib_h
#define	numlib_h

/*
** Copyright 1998 - 1999 Double Precision, Inc.
** See COPYING for distribution information.
*/

#ifdef	__cplusplus
extern "C" {
#endif

static const char numlib_h_rcsid[]="$Id: maildirquota.h 1014 2011-02-03 16:04:37Z volz0r $";

#define	NUMBUFSIZE	60

/* Convert various system types to decimal */

char	*str_time_t(time_t, char *);
char	*str_off_t(off_t, char *);
char	*str_pid_t(pid_t, char *);
char	*str_ino_t(ino_t, char *);
char	*str_uid_t(uid_t, char *);
char	*str_gid_t(gid_t, char *);
char	*str_size_t(size_t, char *);

char	*str_sizekb(unsigned long, char *);	/* X Kb or X Mb */

/* Convert selected system types to hex */

char	*strh_time_t(time_t, char *);
char	*strh_pid_t(pid_t, char *);
char	*strh_ino_t(ino_t, char *);

#ifdef	__cplusplus
}
#endif
#endif
#endif
