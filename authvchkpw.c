/*
 * $Id: authvchkpw.c 1014 2011-02-03 16:04:37Z volz0r $
 * Copyright (C) 1999-2009 Inter7 Internet Technologies, Inc.
 *
 * Revision 2.2  2008-08-24 17:43:44+05:30  Cprogrammer
 * added code to return error for password changes
 *
 * Revision 2.1  2008-08-24 14:44:56+05:30  Cprogrammer
 * courier-imap authmodule for IndiMail
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The GNU General Public License does not permit incorporating your program
 * into proprietary programs.  If your program is a subroutine library, you
 * may consider it more useful to permit linking proprietary applications with
 * the library.  If this is what you want to do, use the GNU Lesser General
 * Public License instead of this License.  But first, please read
 * <http://www.gnu.org/philosophy/why-not-lgpl.html>.
 *
 */
#include "config.h"
#include "vpopmail.h"
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <pwd.h>
#include <string.h>
#include "md5.h"
#include "hmac_md5.h"
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "vauth.h"

#ifndef lint
static char     sccsid[] = "$Id: authvchkpw.c 1014 2011-02-03 16:04:37Z volz0r $";
#endif
#ifdef AUTH_SIZE
#undef AUTH_SIZE
#define AUTH_SIZE 512
#else
#define AUTH_SIZE 512
#endif

int             authlen = AUTH_SIZE;
static int      exec_local(char **, char *, char *, struct vqpasswd *, char *);
static char     hextab[] = "0123456789abcdef";

void
close_connection()
{
#ifdef PASSWD_CACHE
	if (!getenv("PASSWD_CACHE"))
		vclose();
#else /*- Not PASSWD_CACHE */
	vclose();
#endif
}

int
pw_comp(char *testlogin, char *password, char *challenge, char *response)
{
	unsigned char   digest[16];
	unsigned char   digascii[33];
	char           *crypt_pass;
	unsigned char   h;
	int             j;

	if(!response || (response && !*response))
	{
		if (!(crypt_pass = crypt((char *) challenge, (char *) password)))
		{
			printf("454-%s (#4.3.0)\r\n", strerror(errno));
			fflush(stdout);
			_exit (111);
		}
		return(strncmp((const char *) crypt_pass, (const char *) password, (size_t) 14));
	}
	hmac_md5((unsigned char *) challenge, (int) strlen((const char *) challenge), (unsigned char *) password,
		(int) strlen((const char *) password), digest);
	digascii[32] = 0;
	for (j = 0; j < 16; j++)
	{
		h = digest[j] >> 4;
		digascii[2 * j] = hextab[h];
		h = digest[j] & 0x0f;
		digascii[(2 * j) + 1] = hextab[h];
	}
	return (strcmp((const char *) digascii, (const char *) response) && strcmp((const char *) password, (const char *) challenge));
}

/*
 * getEnvConfigStr
 */
void
getEnvConfigStr(char **source, char *envname, char *defaultValue)
{
	if (!(*source = getenv(envname)))
		*source = defaultValue;
	return;
}

int
Login_Tasks(pw, user, ServiceType)
	struct passwd  *pw;
	const char     *user;
	char           *ServiceType;
{
	char           *domain, *ptr;
	char            fqemail[MAX_BUFF];
#ifdef ENABLE_AUTH_LOGGING
#ifdef MIN_LOGIN_INTERVAL
	time_t          min_login_interval, last_time;
#endif
#ifdef USE_MAILDIRQUOTA	
	mdir_t          size_limit, count_limit;
#endif
#endif

	if (!pw)
		return(1);
	lowerit((char *) user);
	lowerit(pw->pw_name);
	if (!(ptr = strchr(user, '@')))
	{
		getEnvConfigStr(&domain, "DEFAULT_DOMAIN", DEFAULT_DOMAIN);
		lowerit(domain);
		snprintf(fqemail, MAX_BUFF, "%s@%s", user, domain);
	} else
	{
		domain = ptr + 1;
		strncpy(fqemail, user, MAX_BUFF);
		*ptr = 0;
	}
	if (access(pw->pw_dir, F_OK))
		vmake_maildir(domain, pw->pw_dir);
#ifdef POP_AUTH_OPEN_RELAY
	/*- open the relay to pop3/imap users */
	if (!getenv("NORELAY") && (pw->pw_gid & NO_RELAY) == 0)
		open_smtp_relay(pw->pw_name, domain);
#endif
#ifdef ENABLE_AUTH_LOGGING
#ifdef MIN_LOGIN_INTERVAL
	last_time = vget_lastauth(pw, domain);
#endif
	if (!(ptr = getenv("TCPERMOTEIP")))
		ptr = "0.0.0.0";
	vset_lastauth(pw->pw_name, domain, ptr);
#ifdef MIN_LOGIN_INTERVAL
  if(( vget_lastauth(vpw,TheDomain ) - last_time ) < MIN_LOGIN_INTERVAL ) { 
    vchkpw_exit(1);
  }
#endif
#endif /*- ENABLE_AUTH_LOGGING */
	return(0);
}

int
pipe_exec(char **argv, char *tmpbuf, int len)
{
	int             pipe_fd[2];
	void            (*pstat) ();

	if ((pstat = signal(SIGPIPE, SIG_IGN)) == SIG_ERR)
	{
		fprintf(stderr, "pipe_exec: signal: %s\n", strerror(errno));
		return (-1);
	}
	if(pipe(pipe_fd) == -1)
	{
		fprintf(stderr, "pipe_exec: pipe: %s\n", strerror(errno));
		signal(SIGPIPE, pstat);
		return(-1);
	}
	if(dup2(pipe_fd[0], 3) == -1 || dup2(pipe_fd[1], 4) == -1)
	{
		fprintf(stderr, "pipe_exec: dup2: %s\n", strerror(errno));
		signal(SIGPIPE, pstat);
		return(-1);
	}
	if(pipe_fd[0] != 3 && pipe_fd[0] != 4)
		close(pipe_fd[0]);
	if(pipe_fd[1] != 3 && pipe_fd[1] != 4)
		close(pipe_fd[1]);
	if(write(4, tmpbuf, len) != len)
	{
		fprintf(stderr, "pipe_exec: %s: %s\n", argv[1], strerror(errno));
		signal(SIGPIPE, pstat);
		return(-1);
	}
	close(4);
	signal(SIGPIPE, pstat);
	execvp(argv[1], argv + 1);
	fprintf(stderr, "pipe_exec: %s: %s\n", argv[1], strerror(errno));
	return(-1);
}

int
main(int argc, char **argv)
{
	char           *buf, *tmpbuf, *login, *challenge, *crypt_pass,
				   *prog_name, *service, *service_type;
	char            user[AUTH_SIZE], domain[AUTH_SIZE], Email[MAX_BUFF];
	int             count, offset;
	uid_t           uid;
	gid_t           gid;
	struct vqpasswd  *pw;
	char           *(indiargs[]) = { VPOPMAILDIR"/sbin/imaplogin", VPOPMAILDIR"/libexec/authlib/authvchkpw",
					VPOPMAILDIR"/bin/imapd", "Maildir", 0 };

	if ((prog_name = strrchr(argv[0], '/')))
		prog_name++;
	else
		prog_name = argv[0];
	if (argc < 3)
	{
		fprintf(stderr, "%s: no more modules will be tried\n", prog_name);
		return(1);
	}
	if (!(tmpbuf = calloc(1, (authlen + 1) * sizeof(char))))
	{
		fprintf(stderr, "%s: malloc-%d: %s\n", prog_name, authlen + 1, strerror(errno));
		return(1);
	}
	/*
	 * Courier-IMAP authmodules Protocol
	 * imap\n
	 * login\n
	 * postmaster@test.com\n
	 * pass\n
	 * newpass\n
	 * argv[0]=/var/indimail/libexec/authlib/try
	 * argv[1]=/var/indimail/libexec/authlib/authpam
	 * argv[2]=/var/indimail/bin/imapd
	 * argv[3]=Maildir
	*/
	for (offset = 0;;)
	{
		do
		{
			count = read(3, tmpbuf + offset, authlen + 1 - offset);
#ifdef ERESTART
		} while (count == -1 && (errno == EINTR || errno == ERESTART));
#else
		} while (count == -1 && errno == EINTR);
#endif
		if (count == -1)
		{
			fprintf(stderr, "read: %s\n", strerror(errno));
			return(1);
		} else
		if (!count)
			break;
		offset += count;
		if (offset >= (authlen + 1))
		{
			fprintf(stderr, "%s: auth data too long\n", prog_name);
			return(2);
		}
	}
	if (!(buf = calloc(1, (offset + 1) * sizeof(char))))
	{
		fprintf(stderr, "%s: malloc-%d: %s\n", prog_name, authlen + 1, strerror(errno));
		return(1);
	}
	memcpy(buf, tmpbuf, offset);
	count = 0;
	service = tmpbuf + count; /*- service */
	for (;tmpbuf[count] != '\n' && count < offset;count++);
	if (count == offset || (count + 1) == offset)
	{
		fprintf(stderr, "%s: auth data too short\n", prog_name);
		return(2);
	}
	tmpbuf[count++] = 0;

	service_type = tmpbuf + count; /* type (login or pass) */
	for (;tmpbuf[count] != '\n' && count < offset;count++);
	if (count == offset || (count + 1) == offset)
	{
		fprintf(stderr, "%s: auth data too short\n", prog_name);
		return(2);
	}
	tmpbuf[count++] = 0;

	login = tmpbuf + count; /*- username */
	for (;tmpbuf[count] != '\n' && count < offset;count++);
	if (count == offset || (count + 1) == offset)
	{
		fprintf(stderr, "%s: auth data too short\n", prog_name);
		return(2);
	}
	tmpbuf[count++] = 0;

	challenge = tmpbuf + count; /*- challenge (plain text) */
	for (;tmpbuf[count] != '\n' && count < offset;count++);
	tmpbuf[count++] = 0;
	if (!strncmp(service_type, "pass", 5))
	{
		fprintf(stderr, "%s: Password Change not supported\n", prog_name);
		pipe_exec(argv, buf, offset);
		return(1);
	}
	if (parse_email(login, user, domain, MAX_BUFF))
	{
		fprintf(stderr, "%s: could not parse email [%s]\n", prog_name, login);
		pipe_exec(argv, buf, offset);
		return (1);
	}
	if (!vget_assign(domain, 0, 0, &uid, &gid)) 
	{
		fprintf(stderr, "%s: domain %s does not exist\n", prog_name, domain);
		pipe_exec(argv, buf, offset);
		return (1);
	}
	snprintf(Email, MAX_BUFF, "%s@%s", user, domain);
    if (vauth_open(0))
	{
		fprintf(stderr, "%s: inquery: %s\n", prog_name, strerror(errno));
		pipe_exec(argv, buf, offset);
		return (1);
	}
	pw = vauth_getpw(user, domain);
	if (!pw)
	{
		fprintf(stderr, "%s: inquery: %s\n", prog_name, strerror(errno));
		pipe_exec(argv, buf, offset);
		close_connection();
		return (1);
	}
	/*
	 * Look at what type of connection we are trying to auth.
	 * And then see if the user is permitted to make this type
	 * of connection
	 */
	if (strcmp("webmail", service) == 0)
	{
		if (pw->pw_gid & NO_WEBMAIL)
		{
			fprintf(stderr, "%s: webmail disabled for this account", prog_name);
			write(2, "AUTHFAILURE\n", 12);
			close_connection();
			execv(*indiargs, argv);
			fprintf(stderr, "execv %s: %s", *indiargs, strerror(errno));
			return (1);
		}
	} else
	if (strcmp("pop3", service) == 0)
	{
		if (pw->pw_gid & NO_POP)
		{
			fprintf(stderr, "%s: pop3 disabled for this account", prog_name);
			write(2, "AUTHFAILURE\n", 12);
			close_connection();
			execv(*indiargs, argv);
			fprintf(stderr, "execv %s: %s", *indiargs, strerror(errno));
			return (1);
		}
	} else
	if (strcmp("imap", service) == 0)
	{
		if (pw->pw_gid & NO_IMAP)
		{
			fprintf(stderr, "%s: imap disabled for this account", prog_name);
			write(2, "AUTHFAILURE\n", 12);
			close_connection();
			execv(*indiargs, argv);
			fprintf(stderr, "execv %s: %s", *indiargs, strerror(errno));
			return (1);
		}
	}
	crypt_pass = pw->pw_passwd;
	if (getenv("DEBUG_LOGIN"))
	{
		fprintf(stderr, "%s: service[%s] type [%s] login [%s] challenge [%s] pw_passwd [%s]\n", 
			prog_name, service, service_type, login, challenge, crypt_pass);
	}
	if (pw_comp(login, crypt_pass, challenge, 0))
	{
		if (argc == 3)
		{
			fprintf(stderr, "%s: no more modules will be tried\n", prog_name);
			write(2, "AUTHFAILURE\n", 12);
			close_connection();
			execv(*indiargs, indiargs);
			fprintf(stderr, "execv %s: %s", *indiargs, strerror(errno));
			return (1);
		}
		close_connection();
		pipe_exec(argv, buf, offset);
		return (1);
	}
	exec_local(argv + argc - 2, login, domain, pw, service);
	return(0);
}

static int
exec_local(char **argv, char *userid, char *TheDomain, struct vqpasswd *pw, char *service)
{
	char            Maildir[MAX_BUFF], authenv1[MAX_BUFF], authenv2[MAX_BUFF], authenv3[MAX_BUFF],
	                authenv4[MAX_BUFF], authenv5[MAX_BUFF], TheUser[MAX_BUFF], TmpBuf[MAX_BUFF];
	char           *ptr, *cptr;
	int             status;
#ifdef USE_MAILDIRQUOTA
	mdir_t          size_limit, count_limit;
#endif
	for (cptr = TheUser, ptr = userid;*ptr && *ptr != '@';*cptr++ = *ptr++);
	*cptr = 0;
	strncpy(TmpBuf, service, MAX_BUFF);
	if ((ptr = strrchr(TmpBuf, ':')))
		*ptr = 0;
	status = Login_Tasks(pw, userid, TmpBuf);
	if (status == 2 && !strncasecmp(service, "imap", 4))
	{
		close_connection();
		return(1);
	}
	close_connection();
	snprintf(Maildir, MAX_BUFF, "%s/Maildir", status == 2 ? "/mail/tmp" : pw->pw_dir);
	if (access(pw->pw_dir, F_OK) || access(Maildir, F_OK) || chdir(pw->pw_dir))
	{
		fprintf(stderr, "chdir: %s: %s\n", pw->pw_dir, strerror(errno));
		return(1);
	}
	snprintf(authenv1, MAX_BUFF, "AUTHENTICATED=%s", userid);
	snprintf(authenv2, MAX_BUFF, "AUTHADDR=%s@%s", TheUser, TheDomain);
	snprintf(authenv3, MAX_BUFF, "AUTHFULLNAME=%s", pw->pw_gecos);
#ifdef USE_MAILDIRQUOTA	
	size_limit = parse_quota(pw->pw_shell, &count_limit);
	snprintf(authenv4, MAX_BUFF, "MAILDIRQUOTA=%"PRIu64"S,%"PRIu64"C", size_limit, count_limit);
#else
	snprintf(authenv4, MAX_BUFF, "MAILDIRQUOTA=%sS", pw->pw_shell);
#endif
	snprintf(authenv5, MAX_BUFF, "MAILDIR=%s", Maildir);
	putenv(authenv1);
	putenv(authenv2);
	putenv(authenv3);
	putenv(authenv4);
	putenv(authenv5);
	close_connection();
	execv(argv[0], argv);
	return(1);
}

void
getversion_authvchkpw_c()
{
	printf("%s\n", sccsid);
}
