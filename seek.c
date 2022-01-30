/*
 * $Id: seek.c 1014 2011-02-03 16:04:37Z volz0r $
 * Copyright (C) 2009 Inter7 Internet Technologies, Inc.
 *
 * Copyright (c) 1987 University of Maryland Computer Science Department.
 * All rights reserved.
 * Permission to copy for any purpose is hereby granted so long as this
 * copyright notice remains intact.
 *
 * Changed MakeSeekable to use tmpfile() - marcus@quintic.co.uk
 */

/*
 * Seekable is a predicate which returns true iff a Unix fd is seekable.
 *
 * MakeSeekable forces an input stdio file to be seekable, by copying to
 * a temporary file if necessary.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

/* commented out for bsd users */
/* long	lseek(); */
char	*getenv();

int
Seekable(fd)
	int fd;
{

	return (lseek(fd, 0L, 1) >= 0 && !isatty(fd));
}

int
MakeSeekable(f)
	register FILE *f;
{
	register int tf, n;
	FILE *tmpf;
	int blksize;
#ifdef MAXBSIZE
	char buf[MAXBSIZE];
	struct stat st;
#else
	char buf[BUFSIZ];
#endif

	if (Seekable(fileno(f)))
		return (0);

	tmpf = tmpfile(); /* tmpfile() is not safe on all systems */
	if (tmpf == NULL) return -1; /* Failed to create temp file */
        tf = fileno(tmpf);

	/* copy from input file to temp file */
#ifdef MAXBSIZE
	if (fstat(tf, &st))	/* how can this ever fail? */
		blksize = MAXBSIZE;
	else
		blksize = vmin(MAXBSIZE, st.st_blksize);
#else
	blksize = BUFSIZ;
#endif
	while ((n = fread(buf, 1, blksize, f)) > 0) {
		if (write(tf, buf, n) != n) {
			(void) close(tf);
			return (-1);
		}
	}
	/* ferror() is broken in Ultrix 1.2; hence the && */
	if (ferror(f) && !feof(f)) {
		(void) close(tf);
		return (-1);
	}

	/*
	 * Now switch f to point at the temp file.  Since we hit EOF, there
	 * is nothing in f's stdio buffers, so we can play a dirty trick: 
	 */
	clearerr(f);
	if (dup2(tf, fileno(f))) {
		(void) close(tf);
		return (-1);
	}
	(void) close(tf);
	return (0);
}

/* suggested by Ken Jones instead of MIN for better compatibility */
int vmin( int x, int y)
{
  if ( x > y ) return(x);
  return(y);
}
