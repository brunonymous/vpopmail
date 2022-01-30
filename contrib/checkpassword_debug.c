/*
 * checkpasssword_debug
 *
 * Aids debugging checkpassword.
 *
 * Shares no code with vpopmail or any other checkpassword util. This is on
 * purpose to keep us from falling into the "check the implementation with the
 * implementation" syndrome :)
 *
 * Copyright (C) 2004 Anders Brander <anders@brander.dk>
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

#define DEFAULT_CHECKPASSWORD "/home/vpopmail/bin/vchkpw"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

extern char **environ; /* should be more portable than main(.. char **envp) */
char ret[1024]; /* used as static buffer for usrnam() and grpnam() */

/* make gid/groupname strings */
char *
grpnam(gid_t gid)
{
	struct group *gr;

	gr = getgrgid(gid);
	if (gr != NULL)
		sprintf(ret, "%d (%s)", gid, gr->gr_name);
	else
		sprintf(ret, "%d", gid);
	return(ret);
}

/* make uid/username strings */
char *
usrnam(gid_t uid)
{
	struct passwd *pw;

	pw = getpwuid(uid);
	if (pw != NULL)
		sprintf(ret, "%d (%s)", uid, pw->pw_name);
	else
		sprintf(ret, "%d", uid);
	return(ret);
}

/* get a single line from stdin */
char *
readline(char *text)
{
	char *buf;
	
	buf = (char *) malloc(4096); /* yep, this is intended, maybe someone would like to overflow vchkpw */
	printf("%s: ", text);
	memset(buf, 0, 4096);
	scanf("%s", buf);
	buf[4095]='\0';
	return(buf);
}

int
main(int argc, char **argv)
{
	int verbosity = 0;
	int do_not_exit = 0;
	char *login=NULL, *password=NULL, *checkpassword=DEFAULT_CHECKPASSWORD;
	char *remote_ip=NULL, *local_port=NULL;
	int fd[2], status;
	pid_t child;
	char c;
	gid_t gid = -1; /* libc5 trouble */
	uid_t uid = -1; /* libc5 trouble */

	if (argv[0][0]=='.')
	{
		/* we need to be able to call ourself back! */
		printf("We _MUST_ be called with full path or placed in $PATH!\n");
		exit(1);
	}
	
	while((c = getopt(argc, argv, "vu:g:l:p:dCc:R:L:h?")) >= 0)
	{
		switch(c)
		{
			case 'v': /* verbosity */
				verbosity++;
				break;
			case 'u': /* username/uid */
				if (optarg)
				{
					if (isalpha(optarg[0])) /* username */
					{
						struct passwd *pwd;
						pwd = getpwnam(optarg);
						if (pwd == NULL)
							perror("getpwnam");
						else
							uid = pwd->pw_uid;
					}
					else if (isdigit(optarg[0])) /* uid */
						uid = (uid_t) atoi(optarg);
				}
				break;
			case 'g': /* group/gid */
				if (optarg)
				{
					if (isalpha(optarg[0])) /* groupname */
					{
						struct group *grp;
						grp = getgrnam(optarg);
						if (grp == NULL)
							perror("getgrnam");
						else
							gid = grp->gr_gid;
					}
					else if (isdigit(optarg[0])) /* gid */
						gid = (gid_t) atoi(optarg);
				}
				break;
			case 'l': /* login */
				if (optarg)
					login = optarg;
				break;
			case 'p': /* password */
				if (optarg)
					password = optarg;
				break;
			case 'd': /* stay in infinite loop */
				do_not_exit = 1;
				break;
			case 'C': /* callback */
				{
					struct stat st;
					int n=0;
					mode_t ourperm=0;
					char buf[16384];

					printf("\033[32m"); /* green tty-color */
					printf("*** CALLBACK FROM PID %d\n", getpid());
					if (getcwd(buf, 16384) != NULL)
					{
						int ret;
						printf("workdir path: [%s]\n", buf);
						ret = stat(buf, &st);
						if (ret != -1)
						{
							/* calculate our permissions */
							if (getuid() == st.st_uid)
								ourperm |= S_IRWXU&st.st_mode;
							if (getgid() == st.st_gid)
								ourperm |= S_IRWXG&st.st_mode;
							ourperm |= S_IRWXO&st.st_mode;

							printf("workdir owner: [%s]\n", usrnam(st.st_uid));
							printf("workdir group: [%s]\n", grpnam(st.st_gid));
							printf("workdir perms: [owner: %c%c%c] [group: %c%c%c] [world: %c%c%c] [me: %c%c%c]\n",
								S_IRUSR&st.st_mode ? 'r': '-',
								S_IWUSR&st.st_mode ? 'w': '-',
								S_IXUSR&st.st_mode ? 'x': '-',
								S_IRGRP&st.st_mode ? 'r': '-',
								S_IWGRP&st.st_mode ? 'w': '-',
								S_IXGRP&st.st_mode ? 'x': '-',
								S_IROTH&st.st_mode ? 'r': '-',
								S_IWOTH&st.st_mode ? 'w': '-',
								S_IXOTH&st.st_mode ? 'x': '-',
								(S_IRUSR|S_IRGRP|S_IROTH)&ourperm ? 'r': '-',
								(S_IWUSR|S_IWGRP|S_IWOTH)&ourperm ? 'w': '-',
								(S_IXUSR|S_IXGRP|S_IXOTH)&ourperm ? 'x': '-');
						}
						else
							perror("stat()");
					}
					else
						printf("Something is REALLY wrong with the current directory!\n");
					printf("uid: [%s]\n", usrnam(getuid()));
					printf("gid: [%s]\n", grpnam(getgid()));
					while(environ[n]!=NULL)
						printf("env: [%s]\n", environ[n++]);
					printf("*** CALLBACK EXITING\n");
					printf("\033[0m"); /* reset tty-color */
					exit(0);
				}
				break;
			case 'c': /* checkpassword path */
				if (optarg)
					checkpassword = optarg;
				break;
			case 'L': /* local port */
				if (optarg)
					local_port = optarg;
				break;
			case 'R': /* remote ip */
				if (optarg)
					remote_ip = optarg;
				break;
			case 'h': /* help */
			case '?':
			default:
				printf("Usage %s [options]\n", argv[0]);
				printf("            -v (increase verbosity)\n");
				printf("            -u uid/user (switch to other user before calling checkpassword)\n");
				printf("            -g gid/group (switch to group before calling checkpassword)\n");
				printf("            -l login (sets the login used for checkpassword)\n");
				printf("            -p passwd (sets the password user for checkpassword)\n");
				printf("            -L port (sets TCPLOCALPORT to port for checkpassword)\n");
				printf("            -R ip (sets TCPREMOTEIP to ip for checkpassword)\n");
				printf("            -d (do not exit - enter infinite loop)\n");
				printf("            -c checkpassword (sets the path to checkpassword, defaults to %s)\n", checkpassword);
				printf("            -h (this message)\n");
				printf("            -C (callback from checkpassword)\n");
				exit(0);
				break;
		}
	}

	if (gid != -1)
	{
		if (verbosity>0)
			printf("switching from gid %d to %s\n", getgid(), grpnam(gid));
		if (setgid(gid)!=0)
			perror("setgid");
	}

	if (uid != -1)
	{
		if (verbosity>0)
			printf("switching from uid %d to %s\n", getuid(), usrnam(uid));
		if (setuid(uid)!=0)
			perror("setuid");
	}

	pipe(fd);
	
	if (login == NULL)
		login = readline("Please enter login");
	if (password == NULL)
		password = readline("Please enter password");

	child = fork();
	
	if (child == -1) /* fork() failed?! */
	{
		perror("fork()");
		close(fd[0]);
		close(fd[1]);
		exit(1);
	}
	else if (child == 0)
	{	/* child process */
		int n=0;
		char *child_argv[5] = {checkpassword, argv[0], "-C", NULL};
		char *child_envp[3];

		if(remote_ip!=NULL)
		{
			child_envp[n] = (char *) malloc(strlen("TCPREMOTEIP=")+strlen(remote_ip)+1);
			sprintf(child_envp[n++], "TCPREMOTEIP=%s", remote_ip);
		}
		if(local_port!=NULL)
		{
			child_envp[n] = (char *) malloc(strlen("TCPLOCALPORT=")+strlen(local_port)+1);
			sprintf(child_envp[n++], "TCPLOCALPORT=%s", local_port);
		}
		child_envp[n] = NULL;
		dup2(fd[0], 3);
		close(fd[1]);
		execve(child_argv[0], child_argv, child_envp);
	}
	else
	{	/* parent */
		close(fd[0]);
		if (verbosity>0)
		{
			printf("\"%s\" started with pid %d\n", checkpassword, child);
			printf("sending \"%sNULL%sNULL0NULL\" (%d bytes) to checkpassword "
				"with uid/gid: %d/%d\n",
				login, password, (strlen(login)+strlen(password)+4),
				getuid(), getgid());
		}
		write(fd[1], login, strlen(login)); /* write to checkpassword */
		write(fd[1], "\0", 1);
		write(fd[1], password, strlen(password));
		write(fd[1], "\0", 1);
		write(fd[1], "0", 2); /* dummy timestamp */
		close(fd[1]);
		if (!do_not_exit)
		{
			if (verbosity>0) printf("waiting...\n");
			waitpid(child, &status, 0);
			if (verbosity>0) printf("done\n");
			if (WIFEXITED(status))
			{
				if (verbosity>1)
					printf("normal exit from checkpassword\n");
				printf("checkpassword exit value: %d\n", WEXITSTATUS(status));
			}
			else if (WIFSIGNALED(status))
			{
				if (verbosity>1)
					printf("checkpassword exited from signal\n");
				printf("checkpassword exit signal: %d\n", WTERMSIG(status));
			}
			exit(0);
		}
		else
			while(1);
	}
}
