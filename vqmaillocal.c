/* This program, intended as a Maildir++-aware replacement for qmail-local
 * has not been maintained and may never have worked properly.  It
 * should not be used.
 */

/*
 * Copyright (C) 2002-2009 Inter7 Internet Technologies, Inc.
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

/* include files */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include "config.h"
#include "vpopmail.h"
#include "vauth.h"

/* Globals */
#define AUTH_SIZE 300
char TheUser[AUTH_SIZE];
char TheHomeDir[AUTH_SIZE];
char TheLocal[AUTH_SIZE];
char TheDash[AUTH_SIZE];
char TheExt[AUTH_SIZE];
char TheSender[AUTH_SIZE];
char TheDefaultDelivery[AUTH_SIZE];
char TheUserFull[AUTH_SIZE];
char TheDomain[AUTH_SIZE];
char TheDir[AUTH_SIZE];
char CurrentDir[AUTH_SIZE];
char DeliveredTo[AUTH_SIZE];
struct vqpasswd *vpw;
off_t message_size = 0;
char bounce[AUTH_SIZE];
int CurrentQuotaSizeFd;

#ifdef QMAIL_EXT
char TheUserExt[AUTH_SIZE]; /* the User with '-' and following chars out if any */
#endif

#define FILE_SIZE 156
char hostname[FILE_SIZE];
char loop_buf[FILE_SIZE];

#define MSG_BUF_SIZE 5000
char msgbuf[MSG_BUF_SIZE];

#define BUFF_SIZE 300
int fdm;
static char *binqqargs[4];

/* Forward declarations */
int process_valias(void);
int is_delete(char *deliverto);
int is_bounce(char *deliverto);
void get_arguments(int argc, char **argv);
off_t get_message_size();
int deliver_mail(char *address, char *quota);
int user_over_quota(char *address, char *quota);
int check_forward_deliver(char *dir);
off_t count_dir(char *dir_name);
int is_looping( char *address );
void run_command(char *prog);
void checkuser(void);
void usernotfound(void);

static char local_file[156];
static char local_file_new[156];

/* 
 * The email message comes in on file descriptor 0 - stanard in
 * The user to deliver the email to is in the EXT environment variable
 * The domain to deliver the email to is in the HOST environment variable
 */
int main(int argc, char **argv)
{
    /* get the arguments to the program and setup things */
    get_arguments(argc, argv);

#ifdef VALIAS
    /* process valiases if configured */
    if ( process_valias() == 1 ) {
        printf("vdelivermail: valiases processed\n");
        vexit(0);
    }
#endif

    /* get the user from vpopmail database */
    if ((vpw=vauth_getpw(TheUser, TheDomain)) != NULL ) {
        checkuser();
    } 
#ifdef QMAIL_EXT
    /* try and find user that matches the QmailEXT address if: no user found, */
    /* and the QmailEXT address is different, meaning there was an extension */
    else if ( strncmp(TheUser, TheUserExt, AUTH_SIZE) != 0 ) {
        /* get the user from vpopmail database */
        if ((vpw=vauth_getpw(TheUserExt, TheDomain)) != NULL ) {
	    checkuser();
        }
	else {
	    usernotfound();
	}
    }
#endif
    else {
        if ( verrori != 0 ) {
            vexit(111);
        }
        usernotfound();
    } 

    /* exit successfully and have qmail delete the email */
    return(vexit(0));
            
}

/* 
 * Get the command line arguments and the environment variables.
 * Force addresses to be lower case and set the default domain
 */
void get_arguments(int argc, char **argv)
{
#ifdef QMAIL_EXT 
 int i;
#endif

    if (argc != 10) {
        printf("vqmaillocal: wrong number of parameters\n"); 
        vexit(0);
    }


    strncpy(TheHomeDir, argv[3], sizeof(TheHomeDir)); 
    strncpy(TheUser, argv[6], sizeof(TheHomeDir)); 
    strncpy(TheDomain, argv[7], sizeof(TheHomeDir)); 

    printf("%s,%s,%s\n", TheHomeDir, TheUser, TheDomain);

    chdir(TheHomeDir);

    lowerit(TheUser);
    lowerit(TheDomain);

    strncpy(TheUserFull, TheUser, AUTH_SIZE);
#ifdef QMAIL_EXT 
    /* delete the '-' and following chars if any and store in TheUserExt */
    for(i = 0; TheUser[i] != 0; i++) {
        if (TheUser[i] == '-' ) {
            break;
        }

        TheUserExt[i] = TheUser[i];
    }

    TheUserExt[i] = 0;
#endif

}

#ifdef VALIAS
/* 
 * Process any valiases for this user@domain
 * 
 * This will look up any valiases in vpopmail and
 * deliver the email to the entries
 *
 * Return 1 if aliases found
 * Return 0 if no aliases found 
 */
int process_valias(void)
{
 int found = 0;
 char *tmpstr;

    /* Get the first alias for this user@domain */
    tmpstr = valias_select( TheUser, TheDomain );

    /* tmpstr will be NULL if there are no more aliases */
    while (tmpstr != NULL ) {

        /* We found one */
        found = 1;

        /* deliver the mail */
        deliver_mail(tmpstr, "NOQUOTA");

        /* Get the next alias for this user@domain */
        tmpstr = valias_select_next();
    }

#ifdef QMAIL_EXT 
    /* try and find alias that matches the QmailEXT address 
     * if: no alias found, 
     * and the QmailEXT address is different, meaning there was an extension 
     */
    if ( (!found) && ( strncmp(TheUser, TheUserExt, AUTH_SIZE) != 0 )  ) {
        /* Get the first alias for this user@domain */
        tmpstr = valias_select( TheUserExt, TheDomain );

        /* tmpstr will be NULL if there are no more aliases */
        while (tmpstr != NULL ) {

            /* We found one */
            found = 1;

            /* deliver the mail */
            deliver_mail(tmpstr, "NOQUOTA");

            /* Get the next alias for this user@domain */
            tmpstr = valias_select_next();
        } 
    }	
#endif

    /* Return whether we found an alias or not */
    return(found);
}
#endif

/* If the .qmail-default file has bounce all in it
 * Then return 1
 * otherwise return 0
 */
int is_bounce(char *deliverto)
{
    if ( strcmp( deliverto, BOUNCE_ALL ) == 0 ) return(1);
    return(0);
}

/* If the .qmail-default file has delete all in it
 * Then return 1
 * otherwise return 0
 */
int is_delete(char *deliverto)
{
    if ( strcmp( deliverto, DELETE_ALL ) == 0 ) return(1);
    return(0);
}



/*
 * Assumes the current working directory is user/Maildir
 *
 * We go off to look at cur and tmp dirs
 * 
 * return size of files
 *
 */
ssize_t check_quota(char *maildir)
{
 ssize_t mail_size = 0;
 char tmpbuf[156];

    snprintf(tmpbuf, 156, "%s.current_size", maildir);
    if ((CurrentQuotaSizeFd=open(tmpbuf,O_CREAT|O_RDWR,S_IWUSR|S_IRUSR))==-1){
       return(mail_size);
    }
    read(CurrentQuotaSizeFd, tmpbuf, 100);
    mail_size = (off_t)atoi(tmpbuf);
    return(mail_size);
}

off_t recalc_quota(char *dir_name)
{
 off_t mail_size = 0;
 char tmpbuf[100];

        getcwd(CurrentDir, AUTH_SIZE);
	mail_size = count_dir(dir_name);
        chdir(CurrentDir);
	snprintf(tmpbuf, 100, "%d\n", (int)mail_size);
	lseek(CurrentQuotaSizeFd, 0L, SEEK_SET);
	write(CurrentQuotaSizeFd, tmpbuf, strlen(tmpbuf));
	return(mail_size);
}

void update_quota(off_t new_size)
{
 char tmpbuf[100];

	snprintf(tmpbuf, 100, "%d\n", (int)new_size);
	lseek(CurrentQuotaSizeFd, 0L, SEEK_SET);
	write(CurrentQuotaSizeFd, tmpbuf, strlen(tmpbuf));
	close(CurrentQuotaSizeFd);
}

off_t count_dir(char *dir_name)
{
 DIR *mydir;
 struct dirent *mydirent;
 struct stat statbuf;
 off_t file_size = 0;
 char *tmpstr;

    if ( dir_name == NULL ) return(0);
    if (chdir(dir_name) == -1) {
        return(0);
    }

	if ( (mydir = opendir(".")) == NULL )  {
            return(0);
        }

	while( (mydirent=readdir(mydir)) != NULL ) {
		if ( strcmp( mydirent->d_name, "..") == 0 ) continue;
		if ( strcmp( mydirent->d_name, ".") == 0 ) continue;
		if ( (tmpstr=strstr(mydirent->d_name, ",S="))!=NULL) {
			tmpstr += 3;
			file_size += atoi(tmpstr);
		} else if (stat(mydirent->d_name,&statbuf)==0 && 
		           (statbuf.st_mode & S_IFDIR) ) {
			file_size +=  count_dir(mydirent->d_name);
		}
	}
	closedir(mydir);
	if ( dir_name != NULL && strcmp(dir_name, ".." )!=0 && 
	                         strcmp(dir_name, "." )!=0) {
		chdir("..");
	}
	return(file_size);
}

long unsigned qmail_inject_open(char *address)
{
 int pim[2];
 long unsigned pid;
 static char *in_address;

        in_address = malloc(strlen(address)+1);
        strcpy( in_address, address);
 
        /* skip over an & sign if there */
        if (*in_address == '&') ++in_address;

        if ( pipe(pim) == -1) return(-1);

        switch(pid=fork()){
        case -1:
                close(pim[0]);
                close(pim[1]);
                return(-1);
        case 0:
                close(pim[1]);
                if (vfd_move(0,pim[0]) == -1 ) _exit(-1);
                binqqargs[0] = QMAILINJECT;
                binqqargs[1] = in_address;
                execv(*binqqargs, binqqargs);
        }
        fdm = pim[1];
        close(pim[0]);
        free(in_address);
        return(pid);
}



/* 
 * Deliver an email to an address
 * Return 0 on success
 * Return less than zero on failure
 * 
 * -1 = user is over quota
 * -2 and below are system failures
 * -3 mail is looping 
 */
int deliver_mail(char *address, char *quota)
{
 time_t tm;
 off_t file_count;
 long unsigned pid;
 int write_fd;
 int inject = 0;

    /* check if the email is looping to this user */
    if ( is_looping( address ) == 1 ) {
        printf("message is looping %s\n", address );
        return(-3);
    }

    /* This is a directory/Maildir location */
    if ( *address == '/' ) {

        /* if the user has a quota set */
        if ( strncmp(quota, "NOQUOTA", 2) != 0 ) {

            /* If the message is greater than 1000 bytes and
             * the user is over thier quota, return it back
             * to the sender. We allow messages less than 1000 bytes
             * to go through. This is so system admins can send a
             * user over quota message 
             */
            if (user_over_quota(address, quota)==1 && message_size>1000 ) {
                printf("user is over quota\n");
                return(-1);
            }
        }

        /* Format the email file name */
        gethostname(hostname,sizeof(hostname));
        pid=getpid();
        time (&tm);
        snprintf(local_file, 156, "%stmp/%lu.%lu.%s,S=%lu",
            address,(long unsigned)tm,(long unsigned)pid,
            hostname, (long unsigned)message_size);
        snprintf(local_file_new, 156, "%snew/%lu.%lu.%s,S=%lu",
            address,(long unsigned)tm,(long unsigned)pid,hostname, 
		(long unsigned)message_size);

        /* open the new email file */
        if ((write_fd=open(local_file,O_CREAT|O_RDWR,S_IRUSR|S_IWUSR))== -1) {
            printf("can not open new email file errno=%d file=%s\n", 
                errno, local_file);
            return(-2);
        }
        if ( strcmp( address, bounce) == 0 ) {
            snprintf(DeliveredTo, AUTH_SIZE, 
                "%s%s", getenv("RPLINE"), getenv("DTLINE"));
        } else {
            snprintf(DeliveredTo, AUTH_SIZE, 
                "%sDelivered-To: %s\n", getenv("RPLINE"), 
                maildir_to_email(address));
        }

    /* This is an command */
    } else if ( *address == '|' ) { 

	/* run the command */ 
	run_command(address);
	return(0);

    /* must be an email address */
    } else {
       char *dtline;
       char *tstr;

	qmail_inject_open(address);
	write_fd = fdm;
        inject = 1;

	/* use the DTLINE variable, but skip past the dash in 
         * domain-user@domain 
         */
	if ( (dtline = getenv("DTLINE")) != NULL ) {
		while (*dtline!=0 && *dtline!=':' ) ++dtline;
		while (*dtline!=0 && *dtline!='-' ) ++dtline;
		if ( *dtline != 0 ) ++dtline;
                for(tstr=dtline;*tstr!=0;++tstr) if (*tstr=='\n') *tstr=0;
	} else {
	        if (*address=='&') ++address;
		dtline = address;
	}
        snprintf(DeliveredTo, AUTH_SIZE, 
            "%sDelivered-To: %s\n", getenv("RPLINE"), dtline);
    }

    if ( lseek(0, 0L, SEEK_SET) < 0 ) {
        printf("lseek errno=%d\n", errno);
        return(errno);
    }

    /* write the Return-Path: and Delivered-To: headers */
    if (write(write_fd,DeliveredTo,strlen(DeliveredTo))!= strlen(DeliveredTo)) {
        close(write_fd);
        /* Check if the user is over quota */
        if ( errno == EDQUOT ) {
            return(-1);
        } else {
            printf("failed to write delivered to line errno=%d\n",errno);
           return(errno);
        }
    }


    /* read it in chunks and write it to the new file */
    while((file_count=read(0,msgbuf,MSG_BUF_SIZE))>0) {
        if ( write(write_fd,msgbuf,file_count) == -1 ) {
            close(write_fd);

            /* if the write fails and we are writing to a Maildir
             * then unlink the file
             */
	    if ( unlink(local_file) != 0 ) {
                printf("unlink failed %s errno = %d\n", local_file, errno);
	        return(errno);
            }

            /* Check if the user is over quota */
            if ( errno == EDQUOT ) {
                return(-1);
            } else {
                printf("write failed errno = %d\n", errno);
                return(errno);
            }
        }
    }
    if ( inject == 1 ) {
	close(write_fd);
	return(0);
    }

    /* if we are writing to a Maildir, move it
     * into the new directory
     */

    /* sync the data to disk and close the file */
    errno = 0;
    if ( 
#ifdef FILE_SYNC
#ifdef HAVE_FDATASYNC
    fdatasync(write_fd) == 0 &&
#else
    fsync(write_fd) == 0 &&
#endif
#endif
         close(write_fd) == 0 ) {

        /* if this succeeds link the file to the new directory */
        if ( link( local_file, local_file_new ) == 0 ) {
	    if ( unlink(local_file) != 0 ) {
                printf("unlink failed %s errno = %d\n", local_file, errno);
            }
        } else {

            /* coda fs has problems with link, check for that error */
            if ( errno==EXDEV ) {

                /* try to rename the file instead */
                if (rename(local_file, local_file_new)!=0) {

                    /* even rename failed, time to give up */
                    printf("rename failed %s %s errno = %d\n", 
                        local_file, local_file_new, errno);
			return(errno);

                /* rename worked, so we are okay now */
                } else {
                    errno = 0;
                }

            /* link failed and we are not on coda */
            } else {
                printf("link failed %s %s errno = %d\n", 
                    local_file, local_file_new, errno);
            }
        }
    }

    /* return success */
    return(0);
}

/* Check if the vpopmail user has a .qmail file in thier directory
 * and foward to each email address, Maildir or program 
 *  that is found there in that file
 *
 * Return: 1 if we found and delivered email
 *       : 0 if not found
 *       : -1 if no user .qmail file 
 *
 */
int check_forward_deliver(char *dir)
{
 static char qmail_line[500];
 char tmpbuf[500];
 FILE *fs;
 int i;
 int return_value = 0;

    /* format the file name */
    snprintf(tmpbuf, 500, "%s/.qmail", dir);
    if ( (fs = fopen(tmpbuf,"r")) == NULL ) {

        /* no file, so just return */
        return(-1);
    }

    /* format a simple loop checker name */
    snprintf(tmpbuf, 500, "%s@%s", TheUser, TheDomain);

    /* read the file, line by line */
    while ( fgets(qmail_line, 500, fs ) != NULL ) {

        /* remove the trailing new line */
        for(i=0;qmail_line[i]!=0;++i) {
            if (qmail_line[i] == '\n') qmail_line[i] = 0;
        }

        /* simple loop check, if they are sending it to themselves
         * then skip this line
         */
        if ( strcmp( qmail_line, tmpbuf) == 0 ) continue;

        deliver_mail(qmail_line, "NOQUOTA");
        return_value = 1;
    }

    /* close the file */
    fclose(fs);

    /* return if we found one or not */
    return(return_value);
}

void sig_catch(sig,f)
int sig;
void (*f)();
{
#ifdef HAVE_SIGACTION
  struct sigaction sa;
  sa.sa_handler = f;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);
  sigaction(sig,&sa,(struct sigaction *) 0);
#else
  signal(sig,f); /* won't work under System V, even nowadays---dorks */
#endif
}


/* open a pipe to a command 
 * return the pid or -1 if error
 */
void run_command(char *prog)
{
 int child;
 char *(args[4]);
 int wstat;

 while ((*prog == ' ') || (*prog == '|')) ++prog;

    if ( lseek(0, 0L, SEEK_SET) < 0 ) {
        printf("lseek errno=%d\n", errno);
        return;
    }

 switch(child = fork())
  {
   case -1:
     printf("unable to fork\n"); 
     exit(0);
   case 0:
     args[0] = "/bin/sh"; args[1] = "-c"; args[2] = prog; args[3] = 0;
     sig_catch(SIGPIPE,SIG_DFL);
     execv(*args,args);
     printf("Unable to run /bin/sh: ");
     exit(-1);
  }

  waitpid(child,&wstat,0);

}

/* Check for a looping message
 * This is done by checking for a matching line
 * in the email headers for Delivered-To: which
 * we put in each email
 * 
 * Return 1 if looping
 * Return 0 if not looping
 * Return -1 on error 
 */
int is_looping( char *address ) 
{
 int i;
 int found;
 char *dtline;

    /* if we don't know the message size then get it */
    if ( message_size == 0 ) {
        /* read the message to get the size */
        message_size = get_message_size();
    }
    if (*address=='&') ++address;

    /* check the DTLINE */
    dtline = getenv("DTLINE");
    if ( dtline != NULL && strstr(dtline, address) != NULL ) {
	return(1);
    }

    lseek(0,0L,SEEK_SET);
    while(fgets(loop_buf,sizeof(loop_buf),stdin)!=NULL){

        /* if we find the line, return error (looping) */
        if (strstr(loop_buf, "Delivered-To")!= 0 && 
            strstr(loop_buf, address)!=0 ) {

            /* return the loop found */
            return(1);

            /* check for the start of the body, we only need
            * to check the headers. 
            */
        } else {

            /* walk through the charaters in the body */
            for(i=0,found=0;loop_buf[i]!=0&&found==0;++i){
                switch(loop_buf[i]){

                    /* skip blank spaces and new lines */
                    case ' ':
                    case '\n':
                    case '\t':
                    case '\r':
                    break;

                    /* found a non blank, so we are still
                    * in the headers
                    */
                    default:
	
                        /* set the found non blank char flag */
                        found = 1;
                        break;
                }
            }

            /* if the line only had blanks, then it is the
             * delimiting line between the headers and the
             * body. We don't need to check the body for
             * the duplicate Delivered-To: line. Hence, we
             * are done with our search and can return the
             * looping not found value
            */
            if ( found == 0 ) {
                /* return not found looping message value */
                return(0);
            }
        }
    }

    /* if we get here then the there is either no body 
     * or the logic above failed and we scanned
     * the whole email, headers and body. 
     */
    return(0);
}

/* 
 * Get the size of the email message 
 * return the size 
 */
off_t get_message_size()
{
 ssize_t message_size;
 ssize_t bytes;

    if ( lseek(0, 0L,SEEK_SET) < 0 ) {
        printf("lseek error %d\n", errno);
        return(-1);
    }

    message_size = 0;
    while((bytes=read(0,msgbuf,MSG_BUF_SIZE))>0) {
        message_size += bytes;
    }
    return(message_size);
}

/* 
 * Check if the user is over quota
 *
 * Do all quota recalculation needed
 *
 * Return 1 if user is over quota
 * Return 0 if user is not over quota
 */
int user_over_quota(char *maildir, char *quota)
{
 ssize_t per_user_limit;
 off_t cur_msg_bytes;
 int i;
 int ret_value = 0;
 off_t new_size;

    /* translate the quota to a number */
    per_user_limit = atol(quota);
    for(i=0;quota[i]!=0;++i){
        if ( quota[i] == 'k' || 
            quota[i] == 'K' ) {
            per_user_limit = per_user_limit * 1000;
            break;
        }
        if ( quota[i] == 'm' || quota[i] == 'M' ) {
            per_user_limit = per_user_limit * 1000000;
            break;
        }
    }

    /* Get thier current total */
    cur_msg_bytes = check_quota(maildir);

    /* Check if this email would bring them over quota */
    if ( cur_msg_bytes + message_size > per_user_limit ) {

        /* recalculate thier quota since they might have
         * deleted email 
         */
        cur_msg_bytes = recalc_quota(maildir);
        if ( cur_msg_bytes + message_size > per_user_limit ) {
            ret_value = 1;
        }
    }

    /* If we are going to deliver it, then add in the size */
    if ( ret_value == 0 ) {
        new_size = message_size + cur_msg_bytes;
        update_quota(new_size);
    } 
    close(CurrentQuotaSizeFd);
    return(ret_value);
}


/*
 * check for locked account
 * deliver to .qmail file if any
 * deliver to user if no .qmail file
 */
void checkuser() 
{
    if (vpw->pw_gid & BOUNCE_MAIL ) {
        printf("vdelivermail: account is locked email bounced %s@%s\n",
            TheUser, TheDomain);
        vexit(100);
    }

    /* If thier directory path is empty make them a new one */
    if ( vpw->pw_dir == NULL || vpw->pw_dir[0]==0 ) {
      uid_t pw_uid;
      gid_t pw_gid;

	vget_assign(TheDomain,NULL,0,&pw_uid,&pw_gid);
        if ( make_user_dir(vpw->pw_name, TheDomain, pw_uid, pw_gid)==NULL){
            printf("Auto creation of maildir failed. vpopmail (#5.9.8)\n");
            vexit(100);
        }
    }

    /* check for a .qmail file in thier Maildir
     * If it exists, then deliver to the contents and exit
     */
    if ( check_forward_deliver(vpw->pw_dir) == 1 ) {
        vexit(0);
    }

    snprintf(TheDir, AUTH_SIZE, "%s/Maildir/", vpw->pw_dir);
    if ( deliver_mail(TheDir, vpw->pw_shell) != 0 ) {
        vexit(100);
    }
}


/*
 * the vpopmail user does not exist. Follow the rest of
 * the directions in the .qmail-default file
 */
void usernotfound() 
{
 int ret;

    /* If they want to delete email for non existant users
     * then just exit 0. Qmail will delete the email for us
     */
    if ( strcmp(bounce, DELETE_ALL) == 0 ) {
        /* just exit 0 and qmail will delete the email from the system */
        vexit(0);

    /* If they want to bounce the email back then
     * print a message and exit 100
     */
    } else if ( strcmp(bounce, BOUNCE_ALL) == 0 ) {
        printf("Sorry, no mailbox here by that name. vpopmail (#5.1.1)\n");

        /* exit 100 causes the email to be bounced back */
        vexit(100);

    }

    /* check if it is a path add the /Maildir/ for delivery */
    if ( strstr( bounce, VPOPMAILDIR ) != 0 ) {
        strcat( bounce, "/Maildir/");
    }

    ret = deliver_mail(bounce, "NOQUOTA" );

    /* Send the email out, if we get a -1 then the user is over quota */
    if ( ret == -1 ) {
        printf("user is over quota, mail bounced\n");
        vexit(100);
    } else if ( ret == -2 ) {
        printf("system error\n");
        vexit(100);
    } else if ( ret != 0 ) {
        printf("mail is looping\n");
        vexit(100);
    }

}
