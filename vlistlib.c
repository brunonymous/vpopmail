/*
 * $Id: vlistlib.c 1014 2011-02-03 16:04:37Z volz0r $
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
//   sort functions
//      sort_init, sort_add_entry, sort_get_entry, sort_cleanup, sort_compare, sort_dosort
//
//   private mail list functions
//      default_options, ezmlm_encode, ezmlm_decode, ezmlm_path, ezmlm_setReplyTo,
//      ezmlm_getArgs, ezmlm_make 
//      
//
//   Callable mail list functions
//      listSubsDescription, listSubsCount, listSubsList, listSubsAdd, listSubsDel,
//      listCount, listList, listGetOptions, listMake, listDelete, listInit, listClose 
//
//   Error functions
//      listGetErrorMessage
//
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
#include "vpopmail.h"
#include "config.h"

#include <fcntl.h>
#include <signal.h>
#include "vauth.h"
#include "vutil.h"

#define EZMLMDIR "/usr/local/bin/ezmlm"

//////////////////////////////////////////////////////////////////////
//
//    sort functions
//

/* pointer to array of pointers */
unsigned char **sort_list;

unsigned char *sort_block[MAX_SORT_BLOCKS];  /* memory blocks for sort data */
int memleft, memindex, sort_entry;
unsigned char *sort_ptr;


 /*
  *  s o r t _ i n i t
  *
  *  Initialize a sort operation
  */

int sort_init () {
    sort_entry = memindex = memleft = 0;
    sort_list = malloc(SORT_TABLE_ENTRIES * sizeof(char *));
    if( !sort_list )  return -1;             /* No memory available to start sort  */
    return 0;
}


 /*
  *  s o r t _ a d d _ e n t r y
  *
  * add entry to list for sorting, copies string until it gets to char 'end' 
  */

int sort_add_entry (char *entry, char end) {
    int len;

    if( sort_entry == SORT_TABLE_ENTRIES ) return -2;   /* table is full */ 
    if( memleft < 256 ) {
        /* allocate a 64K block of memory to store table entries */
        if( memindex == MAX_SORT_BLOCKS ) return -3;      /* Out of sort blocks */
        memleft = 65536;
        sort_ptr = sort_block[memindex++] = malloc(memleft);
    }

    if( !sort_ptr ) return -1;                          /*  out of memory  */

    sort_list[sort_entry++] = sort_ptr;
    len = 1;   /* at least a terminator */
    while (*entry && *entry != end) {
        *sort_ptr++ = *entry++;
        len++;
    }

    *sort_ptr++ = 0;  /* NULL terminator */
    memleft -= len;
    return 0;
}


 /*
  *  s o r t _ g e t _ e n t r y
  *
  *  Get an entry from the sorted buffer
  */

char *sort_get_entry(int index) {
    if ((index < 0) || (index >= sort_entry)) return NULL; 
    return (char *) sort_list[index];
}


 /*
  *  s o r t _ c l e a n u p
  *
  *  Clean up memory after a sort
  */

void sort_cleanup() {
    while (memindex) { free (sort_block[--memindex]); }
    if (sort_list) {
        free (sort_list);
        sort_list = NULL;
    }
}


 /*
  *  s o r t _ c o m p a r e
  *
  *  function to compare entries within a sort
  */

/* Comparison routine used in qsort for multiple functions */
static int sort_compare (const void *p1, const void *p2) {
    return strcasecmp (*(char **)p1, *(char **)p2);
} 


 /*
  *  s o r t _ d o S o r t
  *
  *
  */

void sort_dosort() {
    qsort (sort_list, sort_entry, sizeof(char *), sort_compare);
}


//////////////////////////////////////////////////////////////////////
//
//   private list functions
//

 /*
  *  d e f a u l t _ o p t i o n s
  *
  *  Setup as much of the list as needed to default values.  Address is the
  *  address of the list, or only the name of the domain if DomainOnly is
  *  non-zero.
  */

int default_options( listInfoType *LI, char *Address, int DomainOnly ) {
    int dotnum;
    char QmailName[MAX_FILE_NAME];

    /* These are currently set to defaults for a good, generic list.
     * Basically, make it safe/friendly and don't turn anything extra on.
     */

    LI->DomainOnly = DomainOnly;

    if( DomainOnly ) {    //   Have domain
        if ( strstr( Address, "@") != NULL ) return(4);
        snprintf( LI->Name,   sizeof(LI->Name), "%s", "" );
        snprintf( LI->Domain, sizeof(LI->Domain), "%s", Address );
    }

    else {                //   Have mail list
        if ( strstr( Address, "@") == NULL ) return(1);
        if ( parse_email( Address, LI->Name, LI->Domain, MAX_BUFF) != 0 )  return(2);
    }

//    printf( "before GetDomainEntries\n" );

    if(( LI->entry = get_domain_entries( LI->Domain )) == NULL ) return(3);

    snprintf( LI->OwnerEmail,   sizeof(LI->OwnerEmail), "postmaster@%s", LI->Domain ); 
    snprintf( LI->ReplyTo_Addr, sizeof(LI->ReplyTo_Addr), "%s", "" );
    snprintf( LI->SQLBase,      sizeof(LI->SQLBase), "ezmlm" );
    snprintf( LI->SQLHost,      sizeof(LI->SQLHost), "localhost" );
    snprintf( LI->SQLPass,      sizeof(LI->SQLPass), "dbpass" );
    snprintf( LI->SQLTable,     sizeof(LI->SQLTable), "ezmlm" );
    snprintf( LI->SQLUser,      sizeof(LI->SQLUser), "dbUser" );

//    printf( "before make name\n" );

    /* make dotqmail name */
    snprintf( QmailName, MAX_FILE_NAME, "%s", LI->Name);

//    printf( "before make name for\n" );

    for( dotnum=0; QmailName[dotnum] != '\0'; dotnum++ ) {
        if( QmailName[dotnum] == '.' ) QmailName[dotnum] = ':';
    }   
 
//    printf( "before Dir\n" );

    //   Build Dir Parm
    sprintf( LI->Dir, "%s/%s", LI->entry->path, QmailName );

//    printf( "before Dot\n" );

    //   Build Dot Parm
    sprintf( LI->Dot, "%s/.qmail-%s", LI->entry->path, QmailName );

    LI->ReplyTo = REPLYTO_SENDER;

    LI->Posting    = 1;    //  MOU
    LI->Access     = 0;    //  BG

    LI->SQLPort    = 3306; //  6

    /* for the options below, use 1 for "on" or "yes" */
    LI->Archive    = 1;    //  A
    LI->Digest     = 0;    //  D
    LI->Edit       = 1;    //  E
    LI->Prefix     = 0;    //  F
    LI->SubConf    = 1;    //  H
    LI->Indexed    = 0;    //  I
    LI->UnsubConf  = 1;    //  J
    LI->Kill       = 0;    //  K
    LI->RemoteSub  = 0;    //  L
    LI->RemoteText = 0;    //  N
    LI->Public     = 1;    //  P
    LI->Requests   = 1;    //  Q
    LI->Remote     = 0;    //  R
    LI->SubMod     = 0;    //  S
    LI->SQLSupport = 0;    //  6
    LI->Trailer    = 0;    //  T
    LI->Warn       = 0;    //  W
    LI->Extra      = 0;    //  X

    return(0);
}


 /*
  *   e z m l m _ g e t _ a r g s
  *
  *   Search a line for a value (program) and argument to see if
  *   an option is selected.
  */

int ezmlm_getArgs(char *line, char *program, char argument) {
    char *begin; 
    char *end;
    char *arg;


//    printf( "\nget_ezmlmidz_line_arguments\nline: %sprogram: %s\nargument: %c\n", line, program, argument );

    // does line contain program name?
    if ((strstr(line, program)) != NULL) {
        // find the options
        begin=strchr(line, ' ');
        begin++;
        if (*begin == '-') {
            end=strchr(begin, ' ');
            arg=strchr(begin, argument);
            // if arg is found && it's in the options (before the trailing space), return 1
            if (arg && (arg < end)) return 1;
        }       
    }       
    return 0;
}


 /*
  *  e z m l m _ e n c o d e 
  *
  *  Encode the state of LI into a list of program options needed to 
  *  set the list to the specified state.
  */

int ezmlm_encode( listInfoType *LI, char *Options, int MaxOptions )
{
    //  Temporary variables to break down combined option fields

    //  Posting Messages 
    int Moderation   = 0;    //  M
    int OtherReject  = 0;    //  O
    int UserPostOnly = 0;    //  U

    int BlockArchive = 0;    //  B
    int GuardArchive = 0;    //  G

    int Errors=0;

    //  Posting (0 Anyone, 1 SubPostOtherBounce, 2 SubPostOthersMod 3 ModPostOtherBounce 4 ModPostOtherMod)
    //  0 - MOU - Anyone  
    //  1 - MOu - Sub post others bounce 
    //  2 - mOu - Sub post others moderated
    //  3 - mOU - Mod post others bounce
    //  4 - moU - Mod post others moderated

    if( POSTING_ANYONE == LI->Posting ) {  // 0
       Moderation   = 0;
       OtherReject  = 0;
       UserPostOnly = 0;
       }

    else if( POSTING_SPOB == LI->Posting ) {  // 1
       Moderation   = 0;
       OtherReject  = 0;
       UserPostOnly = 1;
       }

    else if( POSTING_SPOM == LI->Posting ) {  //  2
       Moderation   = 1;
       OtherReject  = 0;
       UserPostOnly = 1;
       }

    else if( POSTING_MPOB == LI->Posting ) {  // 3
       Moderation   = 1;
       OtherReject  = 0;
       UserPostOnly = 0;
       }

    else if( POSTING_MPOM == LI->Posting ) {  // 4
       Moderation   = 1;
       OtherReject  = 1;
       UserPostOnly = 0;
       }

    else {
        Errors += 1;
        }


    //  Access (0 Anyone, 1 Subscribers, 2 Moderators)
    //  bg - Open to anyone 
    //  bG - Limited to subscribers
    //  Bg - Limited to moderators


    if( 0 == LI->Access ) {
       BlockArchive = 0;
       GuardArchive = 0;
       }

    else if( 1 == LI->Access ) {
       BlockArchive = 0;
       GuardArchive = 1;
       }

    else if( 2 == LI->Access ) {
       BlockArchive = 1;
       GuardArchive = 0;
       }

    else {
        Errors += 2;
        printf( "Invalid value for Access: %d\n", LI->Access );
        }

    Options[ 0] = '-';
    Options[ 1] = ( LI->Archive    ) ? 'A' : 'a';  // validated
    Options[ 2] = ( BlockArchive   ) ? 'B' : 'b';  // validated
    Options[ 3] = ( LI->Digest     ) ? 'D' : 'd';  // validated
    Options[ 4] = ( LI->Edit       ) ? 'E' : 'e';
    Options[ 5] = ( LI->Prefix     ) ? 'f' : 'F';  // validated
    Options[ 6] = ( GuardArchive   ) ? 'G' : 'g';  // validated
    Options[ 7] = ( LI->SubConf    ) ? 'H' : 'h';  // validated
    Options[ 8] = ( LI->Indexed    ) ? 'I' : 'i';  // validated
    Options[ 9] = ( LI->UnsubConf  ) ? 'J' : 'j';  // validated
    Options[10] = ( LI->Kill       ) ? 'K' : 'k';
    Options[11] = ( LI->RemoteSub  ) ? 'L' : 'l';  // validated
    Options[12] = ( Moderation     ) ? 'm' : 'M';  // validated
    Options[13] = ( LI->RemoteText ) ? 'N' : 'n';  // validated
    Options[14] = ( OtherReject    ) ? 'o' : 'O';  // validated
    Options[15] = ( LI->Public     ) ? 'P' : 'p';  // validated
    Options[16] = ( LI->Requests   ) ? 'Q' : 'q';  // validated
    Options[17] = ( LI->Remote     ) ? 'R' : 'r';  // validated
    Options[18] = ( LI->SubMod     ) ? 'S' : 's';  // validated
    Options[19] = ( LI->Trailer    ) ? 'T' : 't';  // validated
    Options[20] = ( UserPostOnly   ) ? 'u' : 'U';  // validated
    Options[21] = ( LI->Warn       ) ? 'W' : 'w';
    Options[22] = ( LI->Extra      ) ? 'X' : 'x';
    Options[23] = '\0';

    return( Errors );
}


 /*
  *    r e a d L i s O p t i o n s
  *
  *  Decode list options by reading its directory
  */

void ezmlm_decode( listInfoType *LI ) {
    FILE *fs;
    char *Tmp;
    char TmpBuf[MAX_BUFF];
    int  Moderation   = 0;
    int  OtherReject  = 0;
    int  UserPostOnly = 0;
    int  BlockArchive = 0;
    int  GuardArchive = 0;
    char TmpBuf2[MAX_BUFF];
    int  i;


    /*
     * Note that with ezmlm-idx it might be possible to replace most
     * of this code by reading the config file in the list's directory.
     */

    LI->Requests = LI->RemoteText = LI->RemoteSub = LI->UnsubConf = LI->SubConf = GuardArchive = 0;

    // figure out some options in the -default file
    sprintf(TmpBuf, "%s-default", LI->Dot);

    if( (fs=fopen(TmpBuf, "r")) !=NULL ) {
        while(fgets(TmpBuf2, sizeof(TmpBuf2), fs)) {
            if((ezmlm_getArgs(TmpBuf2, "ezmlm-get",    'P')) > 0) BlockArchive   = 1;
            if((ezmlm_getArgs(TmpBuf2, "ezmlm-get",    's')) > 0) GuardArchive   = 1;
            if((ezmlm_getArgs(TmpBuf2, "ezmlm-manage", 'S')) > 0) LI->SubConf    = 1;
            if((ezmlm_getArgs(TmpBuf2, "ezmlm-manage", 'U')) > 0) LI->UnsubConf  = 1;
            if((ezmlm_getArgs(TmpBuf2, "ezmlm-manage", 'l')) > 0) LI->RemoteSub  = 1;
            if((ezmlm_getArgs(TmpBuf2, "ezmlm-manage", 'e')) > 0) LI->RemoteText = 1;
            if((strstr(TmpBuf2, "ezmlm-request")) != NULL )                     LI->Requests   = 1;
        }  // while fgets
        fclose(fs);
    }  // if fopen


    LI->Indexed = OtherReject = UserPostOnly = LI->Indexed = 0;

    // figure out some options in the -accept-default file
    sprintf(TmpBuf, "%s-accept-default", LI->Dot );
    if( (fs=fopen(TmpBuf, "r")) !=NULL ) {
        while(fgets(TmpBuf2, sizeof(TmpBuf2), fs)) {
            if(strstr(TmpBuf2, "ezmlm-archive") !=0) LI->Indexed = 1;
        }  //  while
        fclose(fs);
    }   //  if fopen

    // figure out some options in the qmail file
    sprintf(TmpBuf, "%s", LI->Dot);
    if( (fs=fopen(TmpBuf, "r")) !=NULL ) {
        while(fgets(TmpBuf2, sizeof(TmpBuf2), fs)) {
            if((ezmlm_getArgs(TmpBuf2, "ezmlm-store", 'P')) > 0) OtherReject = 1;
            if((strstr(TmpBuf2, "ezmlm-gate")) != 0 || (strstr(TmpBuf2, "ezmlm-issubn")) != 0) UserPostOnly = 1;
            if(strstr(TmpBuf2, "ezmlm-archive") !=0) LI->Indexed = 1;
        }   //  while fgets
        fclose(fs);
    }  //  if fopen


    // figure out some options in the sql file
    sprintf(TmpBuf, "%s/sql", LI->Dir);
    if( file_exists( TmpBuf )) {
        LI->SQLSupport = 1;
        if( (fs=fopen(TmpBuf, "r")) !=NULL ) {
            if(fgets(TmpBuf2, sizeof(TmpBuf2), fs)) {
                Tmp = strtok( TmpBuf2, ":" );
                printf( "    First Token: %s Len: %d\n", Tmp, strlen( Tmp ));
                if( NULL != Tmp ) { 
                   for(i=0; i<strlen(Tmp); i++) LI->SQLHost[i] = Tmp[i];
                   LI->SQLHost[i] = (char) 0;
                   Tmp = strtok( NULL, ":" );
                }
                if( NULL != Tmp ) { 
//                  Grab port here
                   Tmp = strtok( NULL, ":" );
                }
                if( NULL != Tmp ) { 
                   for(i=0; i<strlen(Tmp); i++) LI->SQLUser[i] = Tmp[i];
                   LI->SQLUser[i] = (char) 0;
                   Tmp = strtok( NULL, ":" );
                }
                if( NULL != Tmp ) { 
                   for(i=0; i<strlen(Tmp); i++) LI->SQLPass[i] = Tmp[i];
                   LI->SQLPass[i] = (char) 0;
                   Tmp = strtok( NULL, ":" );
                }
                if( NULL != Tmp ) { 
                   for(i=0; i<strlen(Tmp); i++) LI->SQLBase[i] = Tmp[i];
                   LI->SQLBase[i] = (char) 0;
                   Tmp = strtok( NULL, ":\n" );
                }
                if( NULL != Tmp ) { 
                   for(i=0; i<strlen(Tmp); i++) LI->SQLTable[i] = Tmp[i];
                   LI->SQLTable[i] = (char) 0;
                }

            }
        }
    } else {
        LI->SQLSupport = 0;
    }


    //  figure out a number of options based on file_exists()
    sprintf(TmpBuf, "%s-accept-default", LI->Dot);
    Moderation = file_exists(TmpBuf);

    sprintf(TmpBuf, "%s/archived", LI->Dir);
    LI->Archive = file_exists(TmpBuf);
  
    sprintf(TmpBuf, "%s/digest/bouncer", LI->Dir);
    LI->Digest = file_exists(TmpBuf);
  
    sprintf(TmpBuf, "%s/prefix", LI->Dir);
    LI->Prefix = file_exists(TmpBuf);

    sprintf(TmpBuf, "%s/public", LI->Dir);
    LI->Public = file_exists(TmpBuf);
  
    sprintf(TmpBuf, "%s/remote", LI->Dir);
    LI->Remote = file_exists(TmpBuf);
  
    sprintf(TmpBuf, "%s/modsub", LI->Dir);
    LI->SubMod = file_exists(TmpBuf);
  
    sprintf(TmpBuf, "%s/text/trailer", LI->Dir);
    LI->Trailer = file_exists(TmpBuf);

   if( LI->Prefix ) {  //  get prefix value
      sprintf( TmpBuf, "%s/prefix", LI->Dir );
      fs=fopen( TmpBuf , "r" );
      if( fs ) {
         fgets( LI->PrefixText, sizeof(LI->PrefixText), fs );
         fclose(fs);
      }  //  if file
   }  //   if get prefix value


    // analyze Reply-To
    LI->ReplyTo = REPLYTO_SENDER;
    sprintf(TmpBuf, "%s/headeradd", LI->Dir);
    if( (fs=fopen(TmpBuf, "r")) !=NULL ) {
        while(fgets(TmpBuf2, sizeof(TmpBuf2), fs)) {
            if(strstr(TmpBuf2, "Reply-To:") !=0)  {
                if(strstr(TmpBuf2, "<#l#>@<#h#>") !=0)  {
                    LI->ReplyTo = REPLYTO_LIST;
                } else {
                    LI->ReplyTo = REPLYTO_ADDRESS;
                    //  Copy just email address
                    for( i=0; i<(strlen(TmpBuf2)-11); i++){
                        LI->ReplyTo_Addr[i] = TmpBuf2[i+10];
                    }
                    LI->ReplyTo_Addr[i] = (char) 0;
                }
            }
        }   //  while fgets
        fclose(fs);
    }  //  if fopen


//  printf( "Analyze Posting  M: %d  O: %d  U: %d\n", Moderation, OtherReject, UserPostOnly );
  //   Analyze Posting value
  if( Moderation == 1 ) {
    if( UserPostOnly == 1 ) { 
      LI->Posting = POSTING_SPOM;
    } else {
      if( OtherReject == 1 ) {
        LI->Posting = POSTING_MPOB;
      } else {
        LI->Posting = POSTING_MPOM;
      }
    } 
  } else {
    if( UserPostOnly == 1 ) {
      LI->Posting = POSTING_SPOB;
    } else {
      LI->Posting = POSTING_ANYONE;
    }
  }

  if( BlockArchive ) LI->Access = 2;
  else if( GuardArchive ) LI->Access = 1;
  else LI->Access = 0;
}


 /*
  *   l i s t s u b s P a t h 
  *
  *   mode = 0 for subscribers, 1 for moderators, 2 for digest users 
  */

int ezmlm_path( listInfoType *LI, int mode, int size, char *path ) {
  
    switch( mode ) {
        case 0 :  //    subscribers
            snprintf( path, size, "%s/%s/", LI->entry->path, LI->Name);
            break;

        case 1 :  //    moderators
            snprintf( path, size, "%s/%s/mod", LI->entry->path, LI->Name);
            break;

        case 2 :  //    digest subscribers
            snprintf( path, size, "%s/%s/digest", LI->entry->path, LI->Name);
            break;

        case 3 :  //    kill list
            snprintf( path, size, "%s/%s/deny", LI->entry->path, LI->Name);
            break;

        default :
            return( -1 );
            break;

    }
    return(0);
}


/*  e x m l m _ s e t R e p l y T o
 *
 *  sets the Reply-To header in header* files based on form fields
 *  designed to be called by listMake() (after calling ezmlm-make)
 *  Replaces the "Reply-To" line in <filename> with <newtext>.
 */

void ezmlm_setReplyTo ( listInfoType *LI, char *filename, char *newtext)
{
  FILE *headerfile, *tempfile;
  char realfn[256];
  char tempfn[256];
  char buf[256];

  sprintf (realfn, "%s/%s/%s", LI->entry->path, LI->Name, filename);
  sprintf (tempfn, "%s.tmp", realfn);

  headerfile = fopen(realfn, "r");
  if (!headerfile) return;
  tempfile = fopen(tempfn, "w");
  if (!tempfile) { fclose (headerfile); return; }

  /* copy contents to new file, except for Reply-To header */
  while (fgets (buf, sizeof(buf), headerfile) != NULL) {
    if (strncasecmp ("Reply-To", buf, 8) != 0) {
      fputs (buf, tempfile);
    }
  }

  fputs (newtext, tempfile);

  fclose (headerfile);
  fclose (tempfile);
  //  if this works without unlink, i think that is better because if you unlink
  //  then rename, there is an interval where the file does not exist.  If rename
  //  implies the delete since the old inode is no longer accessable, there is 
  //  never a time when the file does not exist to other processes.
  //unlink (realfn);
  rename (tempfn, realfn);
}


 /*
  *  e z m l m _ m a k e
  *
  *  Generate parameters, then run ezmlm_make to create/update a list
  */

int ezmlm_make ( listInfoType *LI )
{
//    FILE *file;
    int pid;
//    int I;
//    char TmpBuf[MAX_BUFF];
    char ProgramPath[MAX_BUFF];
    char SQLBuff[MAX_BUFF];

    char OwnerEmail[MAX_BUFF+5];  
    char *arguments[MAX_BUFF];
    int argc;
//    char tmp[64];
//    char *tmpstr;
    char Options[MAX_OPTIONS];


    if( isExistingAddress( LI->Domain, LI->Name, LI->entry->path )) {
       return( -1 );
       }

    //   Program path and name
    snprintf(ProgramPath, MAX_BUFF, "%s/ezmlm-make", EZMLMDIR);
    snprintf( OwnerEmail, MAX_BUFF, "-5 %s", LI->OwnerEmail );

    //  Start with owner email
    snprintf( OwnerEmail, MAX_BUFF, "-5 %s", LI->OwnerEmail );

    //  Get the list options in EZMLM terms
    ezmlm_encode( LI, Options, MAX_OPTIONS );

    //  If SQL selected, setup all the sql data into a single subfield
    if( LI->SQLSupport ) {
        snprintf( SQLBuff, MAX_BUFF, "-6 %s:%d:%s:%s:%s:%s", 
                  LI->SQLHost, LI->SQLPort, LI->SQLUser, 
                  LI->SQLPass, LI->SQLBase, LI->SQLTable );
        }
    else {
        snprintf( SQLBuff, MAX_BUFF, " " );
        }

    //   Now build the arguments list
    argc=0;
    arguments[argc++] = "ezmlm-make";
    arguments[argc++] = Options;
    arguments[argc++] = OwnerEmail;
    if( LI->SQLSupport ) {
        arguments[argc++] = SQLBuff;
        }
    arguments[argc++] = LI->Dir;
    arguments[argc++] = LI->Dot;
    arguments[argc++] = LI->Name;
    arguments[argc++] = LI->Domain;
    arguments[argc]   = NULL;

    pid=fork();
    if (pid==0) {
        execv(ProgramPath, arguments);
        exit(127);
    } else {
        wait(&pid);
    }

    return( 0 );
}


//////////////////////////////////////////////////////////////////////
//
//   Callable subscriber functions
//

 /*
  *   l i s t s u b s D e s c r i p t i o n 
  *
  *   Return the description for the subscriber mode flag.
  *
  *   mode = 0 for subscribers, 1 for moderators, 2 for digest users, 3 for kill list
  */

int listSubsDescription( listInfoType *LI, int mode, int size, char *description ) {
  
    switch( mode ) {
        case 0 :  //    subscribers
            snprintf( description, size, "subscribers" );
            break;

        case 1 :  //    moderators
            snprintf( description, size, "moderators" );
            break;

        case 2 :  //    digest subscribers
            snprintf( description, size, "digest subscribers" );
            break;

        case 3 :  //    kill list
            snprintf( description, size, "kill list" );
            break;

        default :
            return( -1 );
            break;

    }
    return(0);
}


 /*
  *   l i s t S u b s C o u n t  
  *
  *   Return number of subscribers for the list and mode specified
  *
  *   mode = 0 subscribers, 1 moderators, 2 digest users, 3 kill list 
  */

int listSubsCount( listInfoType *LI, int mode ) {
  
    FILE *fs;
    int handles[2],pid; 
    int count=0;
    char ProgramPath[MAX_BUFF];
    char ListPath[MAX_BUFF];
    char buf[256];
    int status;

    pipe(handles);

    sprintf(ProgramPath, "%s/ezmlm-list", EZMLMDIR );
    status = ezmlm_path( LI, mode, MAX_BUFF, ListPath );
    if( status < 0 ) return( status );
   
    pid=fork();
    if (pid==0) {
        close(handles[0]);
        dup2(handles[1],fileno(stdout));
        execl(ProgramPath, "ezmlm-list", "-n", ListPath, NULL);
        exit(127);
    } else {
        close(handles[1]);
        fs = fdopen(handles[0],"r");

        /* Load subscriber/moderator list */

        while( (fgets(buf, sizeof(buf), fs)!= NULL)) {
//            printf( "   loading entry: %s - %d\n", buf, count );
            count = atoi( buf );
        }
    }

    fclose(fs); close(handles[0]);
    wait(&pid);

//    printf( "after load of data\n" );

    return( count );
}


 /*
  *   l i s t S u b s L i s t  
  *
  *   Get list of subscribers by list, mode
  *
  *   mode = 0 for subscribers, 1 for moderators, 2 for digest users, 3 kill list
  *
  */

char **listSubsList( listInfoType *LI, int mode, int page, int perPage ) {
  
    FILE *fs;
    int handles[2],pid,z = 0,subuser_count = 0; 
    char ProgramPath[MAX_BUFF];
    char ListPath[MAX_BUFF];
    char buf[256];
    char *addr;

    printf( "SubscriberListList  mod: %d  page: %d  perPage: %d\n", mode, page, perPage );

    pipe(handles);

    sprintf(ProgramPath, "%s/ezmlm-list", EZMLMDIR);
    ezmlm_path( LI, mode, MAX_BUFF, ListPath );

    pid=fork();
    if (pid==0) {
        close(handles[0]);
        dup2(handles[1],fileno(stdout));

        execl(ProgramPath, "ezmlm-list", ListPath, NULL);
        exit(127);
    } else {
        close(handles[1]);
        fs = fdopen(handles[0],"r");

        /* Load subscriber/moderator list */

        sort_init();
        while( (fgets(buf, sizeof(buf), fs)!= NULL)) {
            sort_add_entry (buf, '\n');   /* don't copy newline */
            subuser_count++;
        }

    sort_dosort();

    for(z = 0; (addr = (char *)sort_get_entry(z)); ++z) {
      printf( "%s\n", addr );
      }
    }

    sort_cleanup();

    fclose(fs); close(handles[0]);
    wait(&pid);

return( 0 );
}


 /*
  *  l i s t S u b s A d d
  *
  *  Add a subscriber to a list.  Dir tells what list, email tells what address to add.
  *  Allowed dir values:  "" - subscribers, "mode" - moderators, 
  *
  *  returns 0 for success *
  */

int listSubsAdd( listInfoType *LI, int mode, char *email ){
    int pid;
    char ProgramPath[MAX_BUFF];
    char ListPath[MAX_BUFF];

    sprintf(ProgramPath, "%s/ezmlm-sub", EZMLMDIR);
    ezmlm_path( LI, mode, MAX_BUFF, ListPath );
//    printf( "  subscriberListPath %d  %s\n", mode, ListPath );
//    printf( "about to exec %s with parms %s\n", ProgramPath, ListPath );

    pid=fork();
    if (pid==0) {
        execl(ProgramPath, "ezmlm-sub", ListPath, email, NULL);
        exit(127);
    } else wait(&pid);

    /* need to check exit code for failure somehow */

    return(0);
}


 /*
  *   l i s t S u b s D e l
  *
  *   Search a line for a value (program) and argument to see if
  *   an option is selected.
  */

int listSubsDel( listInfoType *LI, int mode, char *email ){
    int pid;
    char ProgramPath[MAX_BUFF];
    char ListPath[MAX_BUFF];

    sprintf(ProgramPath, "%s/ezmlm-unsub", EZMLMDIR);
    ezmlm_path( LI, mode, MAX_BUFF, ListPath );
//    printf( "  subscriberListPath %d  %s  %s\n", mode, ListPath, TmpBuf );
//    printf( "about to exec %s with parms %s\n", ProgramPath, ListPath );

    pid=fork();
    if (pid==0) {
        execl(ProgramPath, "ezmlm-unsub", ListPath, email, NULL);
        exit(127);
    } else wait(&pid);

    /* need to check exit code for failure somehow */

    return(0);
}


//////////////////////////////////////////////////////////////////////
//
//   Callable list functions
//

 /*
  *   l i s t C o u n t
  *
  *   Return the number of lists within a domain
  *
  */

int listCount( listInfoType *LI )
{
    DIR *mydir;
    struct dirent *mydirent;
    int CurMailingLists = 0;

    if ( (mydir = opendir( LI->entry->path )) == NULL ) {
        printf ("   Unable to open count Directory: %s\n", LI->entry->path );
        return -1;
    }

    while( (mydirent=readdir(mydir)) != NULL ) {
        if( '.' == mydirent->d_name[0] ) continue;
        if( isValidMailList( LI->entry->path, mydirent->d_name )) {
            ++CurMailingLists;
        }
    }

    closedir(mydir);
    return CurMailingLists;
}


 /*
  *  m a i l i n g L i s t L i s t
  *
  *  List the mailing lists within a domain
  *
  *  NOTE: The caller is responsible for free()ing each entry then the
  *        array itself.  
  */

char **listList( listInfoType *LI, int page, int perPage ) {
    DIR *mydir;
    struct dirent *mydirent;
    FILE *fs;
    char FileName[MAX_BUFF];
    char TmpBuf2[MAX_BUFF];
    int buffSize;
    char **Buff = NULL;    

    char *addr;
//    char testfn[MAX_FILE_NAME];
    int i, J;

    if ( (mydir = opendir( LI->entry->path )) == NULL ) {
        printf ("   Unable to open list directory\n");
        return( NULL );
    }

    sort_init();

    /* Now, display each list */
    while( (mydirent=readdir(mydir)) != NULL ) {
        snprintf( FileName, MAX_BUFF, "%s/%s", LI->entry->path, mydirent->d_name );

        if ( strncmp(".qmail-", mydirent->d_name, 7) == 0 ) {
            if ( ( fs=fopen(FileName,"r"))==NULL) {
                continue;
            }

            fgets(TmpBuf2, sizeof(TmpBuf2), fs);
            fclose(fs);

            if ( strstr( TmpBuf2, "ezmlm-reject") != 0 ) {
               sort_add_entry (&mydirent->d_name[7], 0);
            }
        }
    }

    closedir(mydir);

    sort_dosort();

    buffSize = perPage * sizeof( *Buff );

    Buff = malloc( perPage * sizeof( *Buff ));

    for ( i = 0; i<perPage; ++i) {
        J = (( page - 1 ) * perPage ) + i;
        if( J >= sort_entry ) { 
            Buff[i] = NULL;
            break;
        }
        
        fflush( stdout );

        addr = (char *)sort_get_entry(J);
        str_replace (addr, ':', '.');
        buffSize = strlen( addr ) + 1;

        if( ( Buff[i] = malloc( buffSize ))) {
            fflush( stdout );
            strncpy( Buff[i], addr, buffSize );
        }
    }

    sort_cleanup();
    return( Buff );
}


 /*
  *  l i s t G e t O p t i o n s
  *
  *  Generate parameters, then run listMake to create/update a list
  */

int listGetOptions( listInfoType *LI, char *options, int maxOptions )
{
    return( ezmlm_encode( LI, options, maxOptions ));
}


 /*
  *  l i s t M a k e
  *
  *  Generate parameters, then run listMake to create/update a list
  */

int listMake( listInfoType *LI )
{
    int status;

    if(( status = isExistingAddress( LI->Domain, LI->Name, LI->entry->path ))) {
       return( status );
       }

    return( ezmlm_make( LI ));
}


 /*
  *  l i s t _ D e l e t e
  *
  *  Delete a mailing list
  */

int listDelete( listInfoType *LI ) {
    DIR *mydir;
    struct dirent *mydirent;
    char TargetName[MAX_FILE_NAME];
    char MainName[MAX_FILE_NAME];
    char SecondName[MAX_FILE_NAME];
    if ( (mydir = opendir(LI->entry->path)) == NULL ) {
        return(7);
    }
 
    sprintf( MainName,   ".qmail-%s",  LI->Dot );
    sprintf( SecondName, ".qmail-%s-", LI->Dot );
    while( (mydirent=readdir(mydir)) != NULL ) {

        /* delete the main .qmail-"list" file */
        if ( strcmp(MainName, mydirent->d_name) == 0 ) {
            snprintf( TargetName, MAX_FILE_NAME, "%s/%s", LI->entry->path, mydirent->d_name);
            if ( unlink(TargetName) != 0 ) {
                return(9);
            }

        /* delete secondary .qmail-"list"-* files */
        } else if ( strncmp(SecondName, mydirent->d_name, strlen(SecondName)) == 0 ) {
            snprintf( TargetName, MAX_FILE_NAME, "%s/%s", LI->entry->path, mydirent->d_name);
            if ( unlink(TargetName) != 0 ) {
                return(10);
            }
        }
    }
    closedir(mydir);

    sprintf(TargetName, "%s/%s", LI->entry->path, LI->Name);
    vdelfiles(TargetName);

    return(0);
}


//////////////////////////////////////////////////////////////////////
//
//   LI initialazation functions
//

 /*
  *            i n i t L i s t
  *
  *   Initilize LI, find out if named list exists or not, if so open it
  *   else set default values
  *
  *   isDomainOnly means just lookup domain, don't worry about an actual list.
  *
  *   isCreating   means we are creating a new list, it must not exist and we
  *                need to setup default values for all list settings.
  *
  */

int listInit( listInfoType *LI, char *Address, int isDomainOnly, int isCreating )  {
    int status = 0;

    //  Initialize LI 
    status = default_options( LI, Address, isDomainOnly );

    if( (status > 0 ) || isDomainOnly ) return(status);

    if( isExistingAddress( LI->Domain, LI->Name, LI->entry->path )) {
       //  If create command and address exists
       if( isCreating  )  return(5);
    } else {
       //  If not create and does not exist
       if( !isCreating )  return(6);
    }

    if( isCreating ) return(status);

    //  Read in existing list information   
    ezmlm_decode( LI );
  
    return(status);
}


/*
 *             C l o s e L i s t
 *
 *  Doesn't actually do anything, but it needs to be called by all users
 *  of the list functions just in case it is needed someday.
 *
 */
   
int listClose( listInfoType *LI ) {

   return( 0 );

}


 /*
  *  l i s t G e t E r r o r M e s s a g e
  *
  *  Decode and display an error returned by vlist functions
  */

void listGetError( char * buff, const int size, const int status ) {
    printf( "Error: %d - ", status );

    switch( abs( status ))  {

        case  1 : 
            printf( "expected name of a list in the form listname@example.com" );
        break;

        case  2 : 
            printf( "Can't parse email address" );
        break;

        case  3 : 
            if( 0 == verrori ) {
                printf( "Domain does not exist.\n" );
            } else {
                printf( "Can't get domain entries - %s\n", verror( verrori ));
            }    
        break;

        case  4 : 
            printf( "expected domain name in the form example.com\n" );
        break;

        case  5 : 
            printf( "address already exists\n" );
        break;

        case  6 : 
            printf( "mailing list does not exist\n" );
        break;

        case  7 : 
            printf( "Unable to open directory to delete\n" );
        break;

        case  8 : 
            printf( "Unable to open domain directory to delete list\n" );
        break;

        case  9 : 
            printf( "Unable to delete main file for list\n" );
        break;

        case 10 : 
            printf( "Unable to delete secondary file for list\n" );
        break;

        default : 
            printf( "unknown error\n" );
        break;
    }
}
