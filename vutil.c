/*
 * $Id: vutil.c 1014 2011-02-03 16:04:37Z volz0r $
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


//////////////////////////////////////////////////////////////////////
//
//   map of function groups within this file
//
//   utility functions
//      str_replace, file_exists
//
//   isSomething functions
//      isValidMailingList, isExistingAlias, isExistingUser, isExistingAddress
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include "config.h"

#include <fcntl.h>
#include <signal.h>
#include "vpopmail.h"
#include "vauth.h"


//////////////////////////////////////////////////////////////////////
//
//   utility functions
//

 /*
  *  s t r _ r e p l a c e
  *
  *  replace all instances of orig with repl in s.
  */

void str_replace (char *s, char orig, char repl) {
    while (*s) {
        if (*s == orig) *s = repl; 
        s++;
    }
}


 /*
  * f i l e _ e x i s t s 
  *
  * return 1 if filename is an existing file
  *
  * Would this be better using stat?
  *
  */

int file_exists (char *filename) {
    FILE *fs;
    if( (fs=fopen(filename, "r")) !=NULL ) {
        fclose(fs);
        return 1;
    } else {
        return 0;
    }
}

//////////////////////////////////////////////////////////////////////
//
//   issomething functions
//

 /*
  *  i s V a l i d M a i l L i s t
  *
  *  See if the specified address is a mailing list
  */

int isValidMailList ( char *path, char *Name )
{
    FILE *fs = NULL;
    char FileName[MAX_BUFF];
    int result = 0;
    char TmpBuf2[MAX_BUFF];

    snprintf( FileName, MAX_BUFF, "%s/.qmail-%s", path, Name );
    if ( (fs=fopen(FileName,"r"))==NULL) {
//        printf( "   Unable to open list file: %s\n", Name );
    }

    else {
        fgets( TmpBuf2, sizeof(TmpBuf2), fs);
        if ( strstr( TmpBuf2, "ezmlm-reject") != 0 ||
             strstr( TmpBuf2, "ezmlm-send")   != 0 ) {
            result = 1;
        }
        fclose(fs);
    }

    return result;
}


 /*
  *  i s E x i s t i n g A l i a s
  *
  *  See if the specified address is an alias
  */

int isExistingAlias ( char *path, char *Name )
{
    FILE *fs = NULL;
    char FileName[MAX_BUFF];
    int result = 0;

    snprintf( FileName, MAX_BUFF, "%s/.qmail-%s", path, Name );
    if ( (fs=fopen(FileName,"r"))==NULL) {
    }   else  {
        result = 1;
        fclose(fs);
    }

//    printf( " result: %d\n", result );
    return result;
}


 /*
  *  i s E x i s t i n g U s e r
  *
  *  See if the specified address is a user
  */

int isExistingUser( char *Name, char *Domain )
{
    int result = 1;
    struct vqpasswd *mypw;

    if ( (mypw = vauth_getpw( Name, Domain )) == NULL ) {
        result = 0;
    }

    return result;
}


 /*
  *  i s E x i s t i n g A d d r e s s 
  *
  *  See if the specified address is a valid address of any kind.
  */

int isExistingAddress( char *Domain, char *Name, char *Path )
{
    //  Set it to false
    int result = 0;

    //  Try things that might make it true
         if( isExistingUser( Name, Domain )) result = 1;
    else if( isExistingAlias( Path, Name ))  result = 1;

    return result;
}
