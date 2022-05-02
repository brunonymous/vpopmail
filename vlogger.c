/*
 * Copyright (C) 2022 TLK Games
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

#include "vlogger.h"
#include "config.h"
#include "vpopmail.h"

#include <stdio.h>
#include <string.h>

#ifdef ENABLE_LOGGER_SYSLOG
#include <syslog.h>
#endif

#ifdef ENABLE_LOGGER_SQLITE
#include <sqlite3.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif

int createTableLog(sqlite3 *sqlite_log) {
  char *err_msg = NULL;
  int rc;

  rc = sqlite3_exec(sqlite_log,
                    "create table log ("
                    "id integer PRIMARY KEY, "
                    "timestamp integer default 0 NOT NULL, "
                    "command text, arg1 text, arg2 text)",
                    0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "error creating log table : %s\n", err_msg);
  }
  return rc;
}

/* log message to syslog or sqlite database */
int logmessage(const char *cmd, const char *arg1, const char *arg2) {
#ifdef ENABLE_LOGGER_SYSLOG
  syslog(LOG_NOTICE, "%s %s %s", cmd, arg1, arg2);
#endif

#ifdef ENABLE_LOGGER_SQLITE
  char SqlBuf[2048];
  char filedb[MAX_BUFF];
  sqlite3 *sqlite_log = NULL;
  mode_t oldmask;
  int rc;
  time_t mytime;
  char *err_msg = NULL;

  mytime = time(NULL);

  snprintf(filedb, MAX_BUFF, "%s/%s", VPOPMAILDIR, "_vpopmail_log.sqlite");

  if (access(filedb, F_OK) != 0) {
    oldmask = umask(VPOPMAIL_UMASK);
    rc = sqlite3_open_v2(filedb, &sqlite_log,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    umask(oldmask);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Cannot create log database : %s\n",
              sqlite3_errmsg(sqlite_log));
      sqlite3_close(sqlite_log);
      return 1;
    }

    sqlite3_close(sqlite_log);
    chown(filedb, VPOPMAILUID, VPOPMAILGID);
  }

  rc = sqlite3_open_v2(filedb, &sqlite_log, SQLITE_OPEN_READWRITE, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot open database : %s\n", sqlite3_errmsg(sqlite_log));
    sqlite3_close(sqlite_log);
    return 1;
  }

  snprintf(SqlBuf, 2048,
           "insert into log (timestamp, command, arg1, arg2) values "
           "('%d', '%s', '%s', '%s')",
           (int)mytime, cmd, arg1, arg2);
  if (sqlite3_exec(sqlite_log, SqlBuf, 0, 0, &err_msg) != SQLITE_OK) {
    if (createTableLog(sqlite_log) != SQLITE_OK) {
      sqlite3_close(sqlite_log);
      return 1;
    }

    if (sqlite3_exec(sqlite_log, SqlBuf, 0, 0, &err_msg) != SQLITE_OK) {
      fprintf(stderr, "error inserting into log table : %s\n", err_msg);
      sqlite3_close(sqlite_log);
      return 1;
    }
  }

  sqlite3_close(sqlite_log);
#endif
  return 0;
}
