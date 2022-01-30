/*
 * $Id: seek.h 1014 2011-02-03 16:04:37Z volz0r $
 * Copyright (C) 2009 Inter7 Internet Technologies, Inc.
 *
 * Copyright (c) 1987 University of Maryland Computer Science Department.
 * All rights reserved.
 * Permission to copy for any purpose is hereby granted so long as this
 * copyright notice remains intact.
 */

/*
 * Seekable is a predicate which returns true iff a Unix fd is seekable.
 *
 * MakeSeekable forces an input stdio file to be seekable, by copying to
 * a temporary file if necessary.
 */

int Seekable(int fd);
int MakeSeekable(register FILE *f);
int vmin( int x, int y);
