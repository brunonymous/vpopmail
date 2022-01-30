/* $Id: vlist.c 1014 2011-02-03 16:04:37Z volz0r $
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


 /*
  *  Map of sections:
  *
  *   utility - very low level, error handlers
  *       exitError, usage
  *
  *   worker  - functions that do some action
  *       subscriberListCount, subscriberListList, subscriberListAdd, subscriberListDel,
  *       mailingListCount, mailingListList, mailingListCreate, mailingListDelete,
  *       mailingListUpdate, mailingListShow, mailingListExplain, mailingListSubscribers
  *
  *   control - functions that determine what the user wants
  *       main
  *
  */


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


////////////////////////////////////////////////////////////////////////////////////
//
//  Start of utility functions
//

 /*
  *  e x i t E r r o r
  *
  *  Show error message, then exit
  */

void exitError( int status, char *message )   {

printf( "%s (%d)\n", message, status);
vclose();
exit(status);
}


 /*     u s a g e
  *
  *
  *  Show the parameters and die
  */

void usage( int status, char *Message ) {
    printf( "%s\n", Message );
    printf( "vlist:\n   usage: vlist list_name command \n");
    printf("\n");
    printf("Commands that affect the entire list\n");
    printf("   vlist count   domain \n");
    printf("   vlist list    domain \n");
    printf("   vlist create  list_name \n");
    printf("   vlist update  list_name \n");
    printf("   vlist delete  list_name \n");
    printf("   vlist show    list_name \n");
    printf("   vlist explain list_name \n");
    printf("\n");
    printf("      note: you can alter single options with update.\n");
    printf("\n");
    printf("Commands that affect subscribers\n");
    printf("   vlist subscriber list_name add address\n");
    printf("   vlist subscriber list_name count\n");
    printf("   vlist subscriber list_name delete address\n");
    printf("   vlist subscriber list_name list\n");
    printf("\n");
    printf("Commands that affect moderators\n");
    printf("   vlist moderator list_name add address\n");
    printf("   vlist moderator list_name count\n");
    printf("   vlist moderator list_name delete address\n");
    printf("   vlist moderator list_name list\n");
    printf("\n");
    printf("Commands that affect digests\n");
    printf("   vlist digest list_name add address\n");
    printf("   vlist digest list_name count\n");
    printf("   vlist digest list_name delete address\n");
    printf("   vlist digest list_name list\n");
    printf("\n");
    printf("Commands that affect kill file\n");
    printf("   vlist kill list_name add address\n");
    printf("   vlist kill list_name count\n");
    printf("   vlist kill list_name delete address\n");
    printf("   vlist kill list_name list\n");
    printf("\n");

    //  Since we always die after printing this, do it here...
    vexit( status );
}


////////////////////////////////////////////////////////////////////////////////////
//
//  Start of subscriber functions
//

 /*
  *  s u b s c r i b e r L i s t C o u n t 
  *
  *  Count subscribers/moderators/digest/kill for list
  */

int subscriberListCount ( listInfoType *LI, int mode ) {
    int Status;

    Status = listSubsCount( LI, mode );

    if( Status < 0 ) {  // error
        printf( "Error encountered getting subscriber list: %d\n", Status );
        return( Status );
    } else {
        printf( "%d\n", Status );
        return(0);
    }
}


 /*
  *  s u b s c r i b e r L i s t L i s t
  *
  *  List subscribers/moderators/digest/kill for list
  */

int subscriberListList ( listInfoType *LI, int mode ) {
//    printf( "   subscriberListList mode: %d  list: %s@%s\n", mode, LI->Name, LI->Domain ); 
    listSubsList( LI, mode, 1, 100 );
    return( 0 );
}


 /*
  *  s u b s c r i b e r L i s t A d d
  *
  *  Add subscribers/moderators/digest/kill to list
  */

void subscriberListAdd( listInfoType *LI, int mode, char *target )  {

    int status;

    status = listSubsAdd( LI, mode, target );
    if( status ) {
        printf( "Unable to add entry: %d\n", status );
    }
}


 /*
  *  s u b s c r i b e r L i s t D e l
  *
  *  Del subscribers/moderators/digest/kill from list
  */

void subscriberListDel( listInfoType *LI, int mode, char *target )  {

    int status;

    status = listSubsDel( LI, mode, target );
    if( status ) {
        printf( "Unable to add entry: %d\n", status );
    }
}


////////////////////////////////////////////////////////////////////////////////////
//
//  Start of list functions
//

 /*
  *  m a i l i n g L i s t C o u n t
  *
  *  Display the number of mailing lists within a domain
  *
  */

void mailingListCount( listInfoType *LI ) {
    printf( "%d\n", listCount( LI ));
}


 /*
  *  m a i l i n g L i s t L i s t
  *
  *  List all mailing lists within the domain
  */

void mailingListList( listInfoType *LI )            {
    char **Buffer = NULL;
    int I=0;

    Buffer = listList( LI, 1, 100 );
    if( NULL != Buffer ) {
        while( Buffer[I] != NULL ) {
            printf( "%s\n", Buffer[I] );
            free( Buffer[I] );
            I++;
        }

        free( Buffer );
    }   
}


 /*
  *  m a i l i n g L i s t C r e a t e
  *
  *  Create a new mailing list
  */

void mailingListCreate( listInfoType *LI )            {
    int status;

    status = listMake( LI );
    if( status ) {  //   already exists 
        exitError( status, "address already exists\n");
    }
}


 /*
  *  m a i l i n g L i s t D e l e t e
  *
  *  Delete a mailing list
  */

void mailingListDelete( listInfoType *LI )            {
    int status;

    status = listDelete( LI );
    if( status ) exitError( status, "Can't delete list" );
}


 /*
  *  m a i l i n g L i s t U p d a t e
  *
  *  Update an existing mailing list
  */

void mailingListUpdate( listInfoType *LI )            {

    exitError(0, "update list\n" );
}


 /*
  *  m a i l i n g L i s t D u m p
  *
  *  Dump the status of a mailing list in compatc terms
  */

void mailingListShow( listInfoType *LI ) {
    char Options[MAX_OPTIONS];
    int status;

    if(( status = listGetOptions( LI, Options, MAX_OPTIONS )) > 0 ) {  //  error(s) found:
        if( 1 && status ) printf( "Invalid value for posting %d\n", LI->Posting );
        if( 2 && status ) printf( "Invalid value for access %d\n", LI->Access );
        }


    printf( "Mailing List:  %s@%s\n", LI->Name, LI->Domain );
    printf( "   OwnerEmail: %s\n", LI->OwnerEmail );
    printf( "   Prefix:     %s\n", LI->PrefixText );

    switch( LI->ReplyTo ) {
       case 1 :
           printf( "   Reply to:   Sender.\n" );
           break;

       case 2 :
           printf( "   Reply to:   List.\n" );
           break;

       case 3 :
           printf( "   Reply to:   %s\n", LI->ReplyTo_Addr );
           break;

       default :
           printf( "   ??? Unknown Replyto Option\n" );
           break;
       }

    printf( "\n" );

    printf( "   Flags:      %s\n", Options );
    printf( "\n" );

    printf( "   Path:       %s\n", LI->entry->path );
    printf( "   Dot:        %s\n", LI->Dot );
    printf( "   Dir:        %s\n", LI->Dir );
    printf( "\n" );

    if( LI->SQLSupport ) {
        printf( "   Host:       %s\n", LI->SQLHost );
        printf( "   Port:       %d\n", LI->SQLPort );
        printf( "   User:       %s\n", LI->SQLUser );
        printf( "   Pass:       %s\n", LI->SQLPass );
        printf( "   Base:       %s\n", LI->SQLBase );
        printf( "   Table:      %s\n", LI->SQLTable );
    }
}

 /*
  *  m a i l i n g L i s t E x p l a i n
  *
  *  Dump the status of a mailing list in verbose terms
  */

void mailingListExplain( listInfoType *LI ) {

    printf( "Mailing List:  %s@%s\n", LI->Name, LI->Domain );
    printf( "   OwnerEmail: %s\n", LI->OwnerEmail );
    printf( "   Prefix:     %s\n", LI->PrefixText );

    printf( "   Path:       %s\n", LI->entry->path );
    printf( "   Dir:        %s\n", LI->Dir );
    printf( "   Dot:        %s\n", LI->Dot );
    printf( "   Flags:\n" );



    printf( "\n" );
    printf( "   Posting Messages\n" );
    switch( LI->Posting ) {
       case 0 :
           printf( "        MOU Anyone can post\n" );
          break;

       case 1 :
           printf( "        MOu Only Subscribers can post, all others bounce.\n" );
          break;

       case 2 :
           printf( "        mOu Only Subscribers can post, all others go to moderators for approval.\n" );
          break;

       case 3 :
           printf( "        moU Only Moderaters can post, all others bounce.\n" );
          break;

       case 4 :
           printf( "        mOU Only Moderaters can post, all others go to moderators for approval.\n" );
          break;

       default :
           printf( "        ??? Unknown Posting Option\n" );
           break;
       }



    printf( "\n   List Options\n" );
    switch( LI->ReplyTo ) {
       case 1 :
           printf( "             Reply to: Sender.\n" );
          break;

       case 2 :
           printf( "             Reply to: List.\n" );
          break;

       case 3 :
           printf( "             Reply to: %s\n", LI->ReplyTo_Addr );
          break;

       default :
           printf( "             ??? Unknown Replyto Option\n" );
           break;
       }


    if( LI->Trailer ) {
        printf( "        t    trailer - Include a trailer at the end of each message\n" );
    } else {
        printf( "        T    trailer - Do not Include a trailer at the end of each message\n" );
    }

    if( LI->Digest ) {
        printf( "        d    digest - Set up a digest version of the list\n" );
    } else {
        printf( "        D    digest - Do not set up a digest version of the list\n" );
    }
 
    if( LI->Requests ) {
        printf( "        q    requests - Service requests sent to listname-request\n" );
    } else {
        printf( "        Q    requests - Do not service requests sent to listname-request\n" );
    }



    printf( "\n   Remote Administration\n" );

    if( LI->Remote ) {
        printf( "        r    Allow remote administration by moderators\n" );
     } else {
        printf( "        R    Do not allow remote administration by moderators\n" );
     }

    if( LI->Public ) {
        printf( "        P    Make this a private list\n" );
    } else {
        printf( "        p    Do not make this a private list\n" );
    } 

    if( LI->RemoteSub ) {
        printf( "        l    Admins can administer subscribers\n" );
    } else {
        printf( "        L    Admins can not administer subscribers\n" );
    }

    if( LI->RemoteText ) {
        printf( "        n    Admins can edit text files.\n" );
    } else {
        printf( "        N    Admins can not edit text files\n" );
    }



    printf( "\n   Subscription Requests\n" );

    if( LI->SubConf ) {
        printf( "        h    Do not require confirmation message for subscription\n" );
    } else {
        printf( "        H    Require confirmation message for subscription\n" );
    }

    if( LI->SubMod ) {
        printf( "        s    Subscriptions are moderated\n" );
    } else {
        printf( "        S    Subscriptions are not moderated\n" );
    }

    if( LI->UnsubConf ) {
        printf( "        j    Do not require confirmation to unsubscribe\n" );
    } else {
        printf( "        J    Require confirmation to subscribe\n" );
    }


    printf( "\n   Message Archive\n" );

    if( LI->Archive ) {
        printf( "        a    Archive this list\n" );
    } else {
        printf( "        A    Do not archive this list\n" );
    }

    switch( LI->Access ) {
        case 0 :
            printf( "        bg   Open to anyone\n" );
            break;

        case 1 :
            printf( "        bG   Limited to subscribers\n" );
            break;

        case 2 :
            printf( "        Bg   Limited to moderators\n" );
            break;

        default :
            printf( "        ??   Unknown Posting Option\n" );
            break;
    }


    if( LI->Indexed ) {
        printf( "        i    Index the archive for httpd access\n" );
    }
    else {
        printf( "        I    Do not index the archive for http access\n" );
    }


    if( LI->SQLSupport ) {
        printf( "\nSQL Options\n" );
        printf( "    Host:  %s\n", LI->SQLHost );
        printf( "    Port:  %d\n", LI->SQLPort );
        printf( "    User:  %s\n", LI->SQLUser );
        printf( "    Pass:  %s\n", LI->SQLPass );
        printf( "    Table: %s\n", LI->SQLTable );
        printf( "    Base:  %s\n", LI->SQLBase );
    }
    printf( "\n" );
}



 /*
  *  m a i l i n g L i s t S u b s c r i b e r s
  *
  *  Select subscriber list commands, then process specified list
  *
  */


void mailingListSubscribers( listInfoType *LI, int command1, int command2, char *target ) {
    int mode = 0;

//    printf( "   Subscriber functions: command1: %d  command2: %d\n", command1, command2 );

    //  find out what kind of list to process
    switch( command1 ) {
        case  8 :    //  Subscribers
            mode = 0;
            break;

        case  9 :    //  Moderators
            mode = 1;
            break;

        case 10 :    //  Digest
            mode = 2;
            break;

        case 11 :    //  Kill
            mode = 3;
            break;

        default :
            printf( "Invalid command1 in mailingListSubscribers\n" );
            break;

    }


    switch( command2 ) {
        case 1 :    //  Count
            subscriberListCount( LI, mode );
            break;

        case 2 :    //  List
            subscriberListList( LI, mode );
            break;

        case 3 :    //  Add
            subscriberListAdd( LI, mode, target );
            break;

        case 4 :    //  Delete
            subscriberListDel( LI, mode, target );
            break;

        default :
            printf( "Invalid command2 in mailingListSubscribers\n" );
            break;
    }


}


////////////////////////////////////////////////////////////////////////////////////
//
//  Start of main
//

 /*
  *                                m a i n
  *
  *  Parse the parameters, and decide what to do.
  */

int main(int argc, char *argv[] ) {
    int status;
    int command1=0, command2=0, isDomainOnly=0, isCreating=0;
    listInfoType LI;
    char Buff[MAX_BUFF];

    //  Open the vpopmail library
    if( vauth_open( 1 )) {
        exitError( 0, "Unable to open authentication back end." );
    }

    //  Easy thing to check for invalid usage
    if( argc < 3 ) usage( 101, "At least two parameters are required\n");


    //  Parse the first command   
    //    Note that the strncmp does not check all of the words. 1 or 2 chars is all that is needed.
         if( 0 == strncmp( argv[1], "count",      2 )) command1 =  1;  
    else if( 0 == strncmp( argv[1], "list",       1 )) command1 =  2;  
    else if( 0 == strncmp( argv[1], "create",     2 )) command1 =  3;
    else if( 0 == strncmp( argv[1], "delete",     2 )) command1 =  4;
    else if( 0 == strncmp( argv[1], "update",     2 )) command1 =  5;
    else if( 0 == strncmp( argv[1], "show",       2 )) command1 =  6;
    else if( 0 == strncmp( argv[1], "explain",    1 )) command1 =  7;
    else if( 0 == strncmp( argv[1], "subscriber", 2 )) command1 =  8;
    else if( 0 == strncmp( argv[1], "moderator",  1 )) command1 =  9;
    else if( 0 == strncmp( argv[1], "digest",     2 )) command1 = 10;
    else if( 0 == strncmp( argv[1], "kill",       1 )) command1 = 11;
    else usage( 102, "Unknown command 1" );

    //  Parse the second command   
    //    Note that the strncmp does not check all of the words. 1 or 2 chars is all that is needed.
    if( command1 > 7 ) {
             if( 0 == strncmp( argv[3], "count",  2 )) command2 = 1;  
        else if( 0 == strncmp( argv[3], "list",   1 )) command2 = 2;  
        else if( 0 == strncmp( argv[3], "add",    2 )) command2 = 3;
        else if( 0 == strncmp( argv[3], "delete", 2 )) command2 = 4;
        else usage( 103, "Unknown command 2" );
        }

    //  Decide how to manage opening the list
    //  I know I could just put the expressions in the call below, 
    //  but then you would not know what they mean...
    isDomainOnly = ( command1 <  3 );  //  command is count, list so just lookup domain 
    isCreating   = ( command1 == 3 );  //  command is create, don't expect list to exist.

    if(( status = listInit( &LI, argv[2], isDomainOnly, isCreating ))) { 
        listGetError( Buff, MAX_BUFF, status );
        return(status);
    }

    //  Execute commands
    switch( command1 )  {
        case  1 :      //    count
            mailingListCount( &LI );
            break;

        case  2 :      //    list
            mailingListList( &LI );
            break;

        case  3 :      //    create
            mailingListCreate( &LI );            
            break;

        case  4 :      //    delete
            mailingListDelete( &LI );            
            break;

        case  5 :      //    update
            mailingListUpdate( &LI );            
            break;

        case  6 :      //     dump
            mailingListShow( &LI );
            break;

        case  7 :      //     explain
            mailingListExplain( &LI );
            break;

        case  8 :      //     subscribers
        case  9 :      //     moderators
        case 10 :      //     digest
        case 11 :      //     kill
            mailingListSubscribers( &LI, command1, command2, argv[4] );
            break;

        default :
            exitError( 0, "INVALID command 1\n" );
            break;
        }

    listClose( &LI );
    vclose();
    return(0);
}
