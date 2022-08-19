#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "vauth.h"
#include "vlimits.h"
#include "vpopmail.h"
#include "vsqlite.h"

#define SQL_BUF_SIZE 2048
static char SqlBufRead[SQL_BUF_SIZE];
static char SqlBufUpdate[SQL_BUF_SIZE];

#define SMALL_BUFF 200
char IUser[SMALL_BUFF];
char IPass[SMALL_BUFF];
char IGecos[SMALL_BUFF];
char IDir[SMALL_BUFF];
char IShell[SMALL_BUFF];
char IClearPass[SMALL_BUFF];

static sqlite3 *sqlite_update = NULL;
static sqlite3 *sqlite_read = NULL;

static sqlite3_stmt *stmt_read = NULL;
static sqlite3_stmt *stmt_getall = NULL;

static int read_open = 0;
static int update_open = 0;

void vcreate_dir_control(char *domain);
void vcreate_vlog_table();

#ifdef VALIAS
void vcreate_valias_table();
#endif

#ifdef ENABLE_AUTH_LOGGING
void vcreate_lastauth_table();
#endif

/************************************************************************/
/*
 * Open a connection to mysql for updates
 */
int vauth_open_update() {
  int rc;
  mode_t oldmask;
  char filedb[MAX_BUFF];

  /* if the database is already open, just return */
  if (update_open) return (0);
  update_open = 1;

  snprintf(filedb, MAX_BUFF, "%s/domains/%s", VPOPMAILDIR, "_vpopmail.sqlite");

  /* create database for vpopmail user */
  if (access(filedb, F_OK) != 0) {
    oldmask = umask(VPOPMAIL_UMASK);
    rc = sqlite3_open_v2(filedb, &sqlite_update,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    umask(oldmask);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Cannot create database : %s\n",
              sqlite3_errmsg(sqlite_update));
      sqlite3_close(sqlite_update);
      verrori = VA_NO_AUTH_CONNECTION;
      return (VA_NO_AUTH_CONNECTION);
    }
    sqlite3_close(sqlite_update);

    chown(filedb, VPOPMAILUID, VPOPMAILGID);
  }

  /* open sqlite3 database for read & write */
  rc = sqlite3_open_v2(filedb, &sqlite_update, SQLITE_OPEN_READWRITE, NULL);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "Cannot open database : %s\n",
            sqlite3_errmsg(sqlite_update));
    sqlite3_close(sqlite_update);
    verrori = VA_NO_AUTH_CONNECTION;
    return (VA_NO_AUTH_CONNECTION);
  }

  /* return success */
  return (0);
}

/************************************************************************/
/*
 * Open a connection to the database for read-only queries
 */
int vauth_open_read() {
  int rc;
  mode_t oldmask;
  char filedb[MAX_BUFF];

  /* if the database is already open, just return */
  if (read_open) return (0);
  read_open = 1;

  snprintf(filedb, MAX_BUFF, "%s/domains/%s", VPOPMAILDIR, "_vpopmail.sqlite");

  /* create database for vpopmail user */
  if (access(filedb, F_OK) != 0) {
    oldmask = umask(VPOPMAIL_UMASK);
    rc = sqlite3_open_v2(filedb, &sqlite_read,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    umask(oldmask);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Cannot create database : %s\n",
              sqlite3_errmsg(sqlite_read));
      sqlite3_close(sqlite_read);
      verrori = VA_NO_AUTH_CONNECTION;
      return (VA_NO_AUTH_CONNECTION);
    }
    sqlite3_close(sqlite_read);

    chown(filedb, VPOPMAILUID, VPOPMAILGID);
  }

  /* open sqlite3 database for reading */
  rc = sqlite3_open_v2(filedb, &sqlite_read, SQLITE_OPEN_READONLY, NULL);

  if (rc != SQLITE_OK) {
    rc = sqlite3_open_v2(filedb, &sqlite_read, SQLITE_OPEN_READWRITE, NULL);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Cannot open database : %s\n",
              sqlite3_errmsg(sqlite_read));
      sqlite3_close(sqlite_read);
      verrori = VA_NO_AUTH_CONNECTION;
      return (VA_NO_AUTH_CONNECTION);
    }
  }

  /* return success */
  return (0);
}

int vauth_open(int will_update) {
  if (will_update) {
    return (vauth_open_update());
  } else {
    return (vauth_open_read());
  }

  /* return success */
  return (0);
}

void vclose() {
  if (read_open) {
    sqlite3_close(sqlite_read);
    read_open = 0;
  }
  if (update_open) {
    sqlite3_close(sqlite_update);
    update_open = 0;
  }
}

/************************************************************************/
int vauth_create_table(char *table, char *layout, int showerror) {
  int err;
  char *err_msg = NULL;
  char SqlBufCreate[SQL_BUF_SIZE];

  if ((err = vauth_open_update()) != 0) return (err);
  snprintf(SqlBufCreate, SQL_BUF_SIZE, "CREATE TABLE %s ( %s )", table, layout);
  if (sqlite3_exec(sqlite_update, SqlBufCreate, 0, 0, &err_msg) != SQLITE_OK) {
    if (showerror)
      fprintf(stderr, "vsqlite: error creating table '%s': %s\n", table,
              err_msg);
    sqlite3_free(err_msg);
    return -1;
  } else {
    return 0;
  }
}

int vauth_adddomain(char *domain) {
#ifndef MANY_DOMAINS
  vset_default_domain(domain);
  return (vauth_create_table(vauth_munch_domain(domain), TABLE_LAYOUT, 1));
#else
  /* if creation fails, don't show an error */
  vauth_create_table(SQLITE_DEFAULT_TABLE, TABLE_LAYOUT, 0);
#endif
  return (0);
}

int vauth_deldomain(char *domain) {
  int err;
  char *err_msg = NULL;
  char *tmpstr;

  if ((err = vauth_open_update()) != 0) return (err);
  vset_default_domain(domain);

#ifndef MANY_DOMAINS
  /* convert the domain name to the table name (eg convert . to _ ) */
  tmpstr = vauth_munch_domain(domain);
  snprintf(SqlBufUpdate, SQL_BUF_SIZE, "drop table %s", tmpstr);
#else
  tmpstr = SQLITE_DEFAULT_TABLE;
  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, "delete from %s where pw_domain = '%s'",
           tmpstr, domain);
#endif

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[1]: %s\n", err_msg);
    return (-1);
  }

#ifdef VALIAS
  valias_delete_domain(domain);
#endif

#ifdef ENABLE_AUTH_LOGGING
  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "delete from lastauth where domain = '%s'", domain);
  err = sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg);
  if (err != SQLITE_OK) {
    if (err != SQLITE_ERROR)
      fprintf(stderr, "vauth_deldomain: warning: mysql_query(%s) failed: %s\n",
              SqlBufUpdate, err_msg);
  }
#endif

#ifdef ENABLE_SQL_LOGGING
#ifdef ENABLE_SQL_REMOVE_DELETED
  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, "delete from vlog where domain = '%s'",
           domain);
  err = sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg);
  if (err != SQLITE_OK) {
    if (err != SQLITE_ERROR)
      fprintf(stderr, "vauth_deldomain: warning: mysql_query(%s) failed: %s\n",
              SqlBufUpdate, err_msg);
  }
#endif
#endif

  vdel_limits(domain);

  return (0);
}

int vauth_adduser(char *user, char *domain, char *pass, char *gecos, char *dir,
                  int apop) {
  char *domstr;
  char dom_dir[156];
  uid_t uid;
  gid_t gid;
  char dirbuf[200];
  char quota[30];
  char Crypted[100];
  int err;
  char *err_msg = NULL;

  if ((err = vauth_open_update()) != 0) return (err);
  vset_default_domain(domain);

  strncpy(quota, "NOQUOTA", 30);

#ifndef MANY_DOMAINS
  domstr = vauth_munch_domain(domain);
#else
  domstr = SQLITE_DEFAULT_TABLE;
#endif
  if (domain == NULL || domain[0] == 0) {
    domstr = SQLITE_LARGE_USERS_TABLE;
  }

  if (strlen(domain) <= 0) {
    if (strlen(dir) > 0) {
      snprintf(dirbuf, sizeof(dirbuf), "%s/users/%s/%s", VPOPMAILDIR, dir,
               user);
    } else {
      snprintf(dirbuf, sizeof(dirbuf), "%s/users/%s", VPOPMAILDIR, user);
    }
  } else {
    vget_assign(domain, dom_dir, sizeof(dom_dir), &uid, &gid);
    if (strlen(dir) > 0) {
      snprintf(dirbuf, sizeof(dirbuf), "%s/%s/%s", dom_dir, dir, user);
    } else {
      snprintf(dirbuf, sizeof(dirbuf), "%s/%s", dom_dir, user);
    }
  }

  if (pass[0] != 0) {
    mkpasswd3(pass, Crypted, 100);
  } else {
    Crypted[0] = 0;
  }

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, INSERT, domstr, user,
#ifdef MANY_DOMAINS
           domain,
#endif
           Crypted, apop, gecos, dirbuf, quota
#ifdef CLEAR_PASS
           ,
           pass
#endif
  );

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[2]: %s\n", err_msg);
    return (-1);
  }

  return (0);
}

int vauth_deluser(char *user, char *domain) {
  char *tmpstr;
  char *err_msg = NULL;
  int err = 0;
  int rc;

  if ((err = vauth_open_update()) != 0) return (err);
  vset_default_domain(domain);

#ifndef MANY_DOMAINS
  if (domain == NULL || domain[0] == 0) {
    tmpstr = SQLITE_LARGE_USERS_TABLE;
  } else {
    tmpstr = vauth_munch_domain(domain);
  }
#else
  tmpstr = SQLITE_DEFAULT_TABLE;
#endif

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, DELETE_USER, tmpstr, user
#ifdef MANY_DOMAINS
           ,
           domain
#endif
  );
  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    err = -1;
  }

#ifdef ENABLE_AUTH_LOGGING
  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "delete from lastauth where user = '%s' and domain = '%s'", user,
           domain);
  rc = sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    if (rc != SQLITE_ERROR) {
      err = -1;
    } else {
      err = 0;
    }
  }
#endif

#ifdef ENABLE_SQL_LOGGING
#ifdef ENABLE_SQL_REMOVE_DELETED
  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "delete from vlog where domain = '%s' and user = '%s'", domain,
           user);
  rc = sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg);
  if (rc != SQLITE_OK) {
    if (rc != SQLITE_ERROR) {
      err = -1;
    } else {
      err = 0;
    }
  }
#endif
#endif
  return (err);
}

int vauth_setquota(char *username, char *domain, char *quota) {
  char *tmpstr;
  char *err_msg = NULL;
  int err;

  if (strlen(username) > MAX_PW_NAME) return (VA_USER_NAME_TOO_LONG);
#ifdef USERS_BIG_DIR
  if (strlen(username) == 1) return (VA_ILLEGAL_USERNAME);
#endif
  if (strlen(domain) > MAX_PW_DOMAIN) return (VA_DOMAIN_NAME_TOO_LONG);
  if (strlen(quota) > MAX_PW_QUOTA) return (VA_QUOTA_TOO_LONG);

  if ((err = vauth_open_update()) != 0) return (err);
  vset_default_domain(domain);

#ifndef MANY_DOMAINS
  tmpstr = vauth_munch_domain(domain);
#else
  tmpstr = SQLITE_DEFAULT_TABLE;
#endif

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, SETQUOTA, tmpstr, quota, username
#ifdef MANY_DOMAINS
           ,
           domain
#endif
  );

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    fprintf(stderr, "vmysql: sql error[3]: %s\n", err_msg);
    return (-1);
  }
  return (0);
}

int vauth_setpw(struct vqpasswd *inpw, char *domain) {
  char *tmpstr;
  char *err_msg = NULL;
  uid_t myuid;
  uid_t uid;
  gid_t gid;
  int err;

#ifdef USE_ONCHANGE
  char user_domain[MAX_BUFF];
#endif

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", inpw->pw_name, domain);
  on_change("mod_user", user_domain, "-", 0, 0);
#endif

  err = vcheck_vqpw(inpw, domain);
  if (err != 0) return (err);

  vget_assign(domain, NULL, 0, &uid, &gid);
  myuid = geteuid();
  if (myuid != 0 && myuid != uid) {
    return (VA_BAD_UID);
  }

  if ((err = vauth_open_update()) != 0) return (err);
  vset_default_domain(domain);

#ifndef MANY_DOMAINS
  tmpstr = vauth_munch_domain(domain);
#else
  tmpstr = SQLITE_DEFAULT_TABLE;
#endif

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, SETPW, tmpstr, inpw->pw_passwd,
           inpw->pw_uid, inpw->pw_gid, inpw->pw_gecos, inpw->pw_dir,
           inpw->pw_shell,
#ifdef CLEAR_PASS
           inpw->pw_clear_passwd,
#endif
           inpw->pw_name
#ifdef MANY_DOMAINS
           ,
           domain
#endif
  );

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    fprintf(stderr, "vmysql: sql error[4]: %s\n", err_msg);
    return (-1);
  }

#ifdef SQWEBMAIL_PASS
  vsqwebmail_pass(inpw->pw_dir, inpw->pw_passwd, uid, gid);
#endif

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", inpw->pw_name, domain);
  on_change("mod_user", user_domain, "-", 1, 1);
#endif

  return (0);
}

struct vqpasswd *vauth_getpw(char *user, char *domain) {
  char *domstr;
  static struct vqpasswd vpw;
  static char in_domain[156];
  int err;
  int rc;
  uid_t myuid;
  uid_t uid;
  gid_t gid;

  vget_assign(domain, NULL, 0, &uid, &gid);

  myuid = geteuid();
  if (myuid != 0 && myuid != uid) return (NULL);

  verrori = 0;
  if ((err = vauth_open_read()) != 0) {
    verrori = err;
    return (NULL);
  }

  lowerit(user);
  lowerit(domain);

  snprintf(in_domain, sizeof(in_domain), "%s", domain);

  vset_default_domain(in_domain);

#ifndef MANY_DOMAINS
  domstr = vauth_munch_domain(in_domain);
#else
  domstr = SQLITE_DEFAULT_TABLE;
#endif

  if (domstr == NULL || domstr[0] == 0) domstr = SQLITE_LARGE_USERS_TABLE;

  qnprintf(SqlBufRead, SQL_BUF_SIZE, USER_SELECT, domstr, user
#ifdef MANY_DOMAINS
           ,
           in_domain
#endif
  );
  rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[5]: %s\n", sqlite3_errmsg(sqlite_read));
    return (NULL);
  }

  rc = sqlite3_step(stmt_read);
  if (rc != SQLITE_ROW) {
    sqlite3_finalize(stmt_read);
    return (NULL);
  } else {
    memset(IUser, 0, sizeof(IUser));
    memset(IPass, 0, sizeof(IPass));
    memset(IGecos, 0, sizeof(IGecos));
    memset(IDir, 0, sizeof(IDir));
    memset(IShell, 0, sizeof(IShell));
    memset(IClearPass, 0, sizeof(IClearPass));

    vpw.pw_name = IUser;
    vpw.pw_passwd = IPass;
    vpw.pw_gecos = IGecos;
    vpw.pw_dir = IDir;
    vpw.pw_shell = IShell;
    vpw.pw_clear_passwd = IClearPass;

    strncpy(vpw.pw_name, sqlite3_column_text(stmt_read, 0), SMALL_BUFF);
    if (sqlite3_column_text(stmt_read, 1) != 0) {
      strncpy(vpw.pw_passwd, sqlite3_column_text(stmt_read, 1), SMALL_BUFF);
    }
    if (sqlite3_column_text(stmt_read, 2) != 0) {
      vpw.pw_uid = atoi(sqlite3_column_text(stmt_read, 2));
    }
    if (sqlite3_column_text(stmt_read, 3) != 0) {
      vpw.pw_gid = atoi(sqlite3_column_text(stmt_read, 3));
    }
    if (sqlite3_column_text(stmt_read, 4) != 0) {
      strncpy(vpw.pw_gecos, sqlite3_column_text(stmt_read, 4), SMALL_BUFF);
    }
    if (sqlite3_column_text(stmt_read, 5) != 0) {
      strncpy(vpw.pw_dir, sqlite3_column_text(stmt_read, 5), SMALL_BUFF);
    }
    if (sqlite3_column_text(stmt_read, 6) != 0) {
      strncpy(vpw.pw_shell, sqlite3_column_text(stmt_read, 6), SMALL_BUFF);
    }
#ifdef CLEAR_PASS
    if (sqlite3_column_text(stmt_read, 7) != 0) {
      strncpy(vpw.pw_clear_passwd, sqlite3_column_text(stmt_read, 7),
              SMALL_BUFF);
    }
#endif
  }

  sqlite3_finalize(stmt_read);

  vlimits_setflags(&vpw, in_domain);

  return (&vpw);
}

struct vqpasswd *vauth_getall(char *domain, int first, int sortit) {
  char *domstr = NULL;
  static struct vqpasswd vpw;
  static int more = 0;
  int err;
  int rc;

  vset_default_domain(domain);

#ifdef MANY_DOMAINS
  domstr = SQLITE_DEFAULT_TABLE;
#else
  domstr = vauth_munch_domain(domain);
#endif

  if (first == 1) {
    if ((err = vauth_open_read()) != 0) return (NULL);

    qnprintf(SqlBufRead, SQL_BUF_SIZE, GETALL, domstr
#ifdef MANY_DOMAINS
             ,
             domain
#endif
    );

    if (sortit == 1) {
      strncat(SqlBufRead, " order by pw_name",
              SQL_BUF_SIZE - strlen(SqlBufRead) - 1);
    }

    if (stmt_read != NULL) sqlite3_finalize(stmt_read);
    stmt_read = NULL;

    rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_getall, NULL);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[6]: %s\n",
              sqlite3_errmsg(sqlite_read));
      return (NULL);
    }

  } else if (more == 0) {
    return (NULL);
  }

  memset(IUser, 0, sizeof(IUser));
  memset(IPass, 0, sizeof(IPass));
  memset(IGecos, 0, sizeof(IGecos));
  memset(IDir, 0, sizeof(IDir));
  memset(IShell, 0, sizeof(IShell));
  memset(IClearPass, 0, sizeof(IClearPass));

  vpw.pw_name = IUser;
  vpw.pw_passwd = IPass;
  vpw.pw_gecos = IGecos;
  vpw.pw_dir = IDir;
  vpw.pw_shell = IShell;
  vpw.pw_clear_passwd = IClearPass;

  rc = sqlite3_step(stmt_getall);
  if ((rc != SQLITE_ROW) && (rc != SQLITE_DONE)) {
    fprintf(stderr, "vsqlite: sql error[7]: %s\n", sqlite3_errmsg(sqlite_read));
    return (NULL);
  }

  if (rc == SQLITE_ROW) {
    strncpy(vpw.pw_name, sqlite3_column_text(stmt_getall, 0), SMALL_BUFF);
    if (sqlite3_column_text(stmt_getall, 1) != 0) {
      strncpy(vpw.pw_passwd, sqlite3_column_text(stmt_getall, 1), SMALL_BUFF);
    }
    if (sqlite3_column_text(stmt_getall, 2) != 0) {
      vpw.pw_uid = atoi(sqlite3_column_text(stmt_getall, 2));
    }
    if (sqlite3_column_text(stmt_getall, 3) != 0) {
      vpw.pw_gid = atoi(sqlite3_column_text(stmt_getall, 3));
    }
    if (sqlite3_column_text(stmt_getall, 4) != 0) {
      strncpy(vpw.pw_gecos, sqlite3_column_text(stmt_getall, 4), SMALL_BUFF);
    }
    if (sqlite3_column_text(stmt_getall, 5) != 0) {
      strncpy(vpw.pw_dir, sqlite3_column_text(stmt_getall, 5), SMALL_BUFF);
    }
    if (sqlite3_column_text(stmt_getall, 6) != 0) {
      strncpy(vpw.pw_shell, sqlite3_column_text(stmt_getall, 6), SMALL_BUFF);
    }
#ifdef CLEAR_PASS
    if (sqlite3_column_text(stmt_getall, 7) != 0) {
      strncpy(vpw.pw_clear_passwd, sqlite3_column_text(stmt_getall, 7),
              SMALL_BUFF);
    }
#endif
    more = 1;
    vlimits_setflags(&vpw, domain);
    return (&vpw);
  }
  more = 0;
  sqlite3_finalize(stmt_getall);
  stmt_getall = NULL;
  return (NULL);
}

void vauth_end_getall() {
  if (stmt_getall != NULL) {
    sqlite3_finalize(stmt_getall);
  }
  stmt_getall = NULL;
}

/************************************************************************/
char *vauth_munch_domain(char *domain) {
  int i;
  static char tmpbuf[512];

  if (domain == NULL || domain[0] == 0) return (domain);

  for (i = 0; ((domain[i] != 0) && (i < (sizeof(tmpbuf) - 1))); ++i) {
    tmpbuf[i] = domain[i];
    if (domain[i] == '.' || domain[i] == '-') {
      tmpbuf[i] = SQLITE_DOT_CHAR;
    }
  }
  tmpbuf[i] = 0;
  return (tmpbuf);
}

#ifdef IP_ALIAS_DOMAINS
void vcreate_ip_map_table() {
  vauth_create_table("ip_alias_map", IP_ALIAS_TABLE_LAYOUT, 1);
  return;
}

int vget_ip_map(char *ip, char *domain, int domain_size) {
  int ret = -1;
  int rc;

  if (ip == NULL || strlen(ip) <= 0) return (-1);
  if (domain == NULL) return (-2);
  if (vauth_open_read() != 0) return (-3);

  qnprintf(SqlBufRead, SQL_BUF_SIZE,
           "select domain from ip_alias_map where ip_addr = '%s'", ip);

  rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);

  if (rc != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[8]: %s\n", sqlite3_errmsg(sqlite_read));
    return (-1);
  }

  rc = sqlite3_step(stmt_read);
  if ((rc != SQLITE_ROW) && (rc != SQLITE_DONE)) {
    fprintf(stderr, "vsqlite: sql error[9]: %s\n", sqlite3_errmsg(sqlite_read));
    return (-4);
  }

  while (rc == SQLITE_ROW) {
    ret = 0;
    strncpy(domain, sqlite3_column_text(stmt_read, 0), domain_size);
    rc = sqlite3_step(stmt_read);
  }
  sqlite3_finalize(stmt_read);
  return (ret);
}

/*
 * Add an ip to domain mapping
 * It will remove any duplicate entry before adding it
 *
 */
int vadd_ip_map(char *ip, char *domain) {
  char *err_msg = NULL;
  if (ip == NULL || strlen(ip) <= 0) return (-1);
  if (domain == NULL || strlen(domain) <= 0) return (-1);
  if (vauth_open_update() != 0) return (-1);

  qnprintf(
      SqlBufUpdate, SQL_BUF_SIZE,
      "replace into ip_alias_map ( ip_addr, domain ) values ( '%s', '%s' )", ip,
      domain);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    vcreate_ip_map_table();
    if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) !=
        SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[10]: %s\n", err_msg);
      return (-1);
    }
  }
  return (0);
}

int vdel_ip_map(char *ip, char *domain) {
  char *err_msg = NULL;
  if (ip == NULL || strlen(ip) <= 0) return (-1);
  if (domain == NULL || strlen(domain) <= 0) return (-1);
  if (vauth_open_update() != 0) return (-1);

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "delete from ip_alias_map where ip_addr = '%s' and domain = '%s'",
           ip, domain);
  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    return (0);
  }
  return (0);
}

int vshow_ip_map(int first, char *ip, char *domain) {
  static int more = 0;
  int rc;

  if (ip == NULL) return (-1);
  if (domain == NULL) return (-1);
  if (vauth_open_read() != 0) return (-1);

  if (first == 1) {
    snprintf(SqlBufRead, SQL_BUF_SIZE,
             "select ip_addr, domain from ip_alias_map");

    if (stmt_read != NULL) sqlite3_finalize(stmt_read);
    stmt_read = NULL;

    rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[11]: %s\n",
              sqlite3_errmsg(sqlite_read));
      return (0);
    }

  } else if (more == 0) {
    return (0);
  }

  rc = sqlite3_step(stmt_read);
  if ((rc != SQLITE_ROW) && (rc != SQLITE_DONE)) {
    vcreate_ip_map_table();
    rc = sqlite3_step(stmt_read);
    if ((rc != SQLITE_ROW) && (rc != SQLITE_DONE)) {
      fprintf(stderr, "vsqlite: sql error[12]: %s\n",
              sqlite3_errmsg(sqlite_read));
      return (0);
    }
  }

  if (rc == SQLITE_ROW) {
    strncpy(ip, sqlite3_column_text(stmt_read, 0), 18);
    strncpy(domain, sqlite3_column_text(stmt_read, 1), 156);
    more = 1;
    return (1);
  }
  more = 0;
  sqlite3_finalize(stmt_read);
  stmt_read = NULL;
  return (0);
}
#endif /* IP_ALIAS_DOMAINS */

int vread_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid) {
  int found = 0;
  int rc;

  if (vauth_open_read() != 0) return (-1);
  qnprintf(SqlBufRead, SQL_BUF_SIZE,
           "select %s from dir_control where domain = '%s'", DIR_CONTROL_SELECT,
           domain);

  rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);
  if (rc != SQLITE_OK) {
    vcreate_dir_control(domain);
    rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[13]: %s\n",
              sqlite3_errmsg(sqlite_read));
      return (-1);
    }
  }

  rc = sqlite3_step(stmt_read);
  if ((rc != SQLITE_OK) && (rc != SQLITE_DONE)) {
    rc = sqlite3_step(stmt_read);
    if ((rc != SQLITE_OK) && (rc != SQLITE_DONE)) {
      sqlite3_finalize(stmt_read);
      fprintf(stderr, "vsqlite: sql error[14]: %s\n",
              sqlite3_errmsg(sqlite_read));
      return (-1);
    }
  }

  if (rc == SQLITE_ROW) {
    found = 1;
    vdir->cur_users = atol(sqlite3_column_text(stmt_read, 0));
    vdir->level_cur = atoi(sqlite3_column_text(stmt_read, 1));
    vdir->level_max = atoi(sqlite3_column_text(stmt_read, 2));

    vdir->level_start[0] = atoi(sqlite3_column_text(stmt_read, 3));
    vdir->level_start[1] = atoi(sqlite3_column_text(stmt_read, 4));
    vdir->level_start[2] = atoi(sqlite3_column_text(stmt_read, 5));

    vdir->level_end[0] = atoi(sqlite3_column_text(stmt_read, 6));
    vdir->level_end[1] = atoi(sqlite3_column_text(stmt_read, 7));
    vdir->level_end[2] = atoi(sqlite3_column_text(stmt_read, 8));

    vdir->level_mod[0] = atoi(sqlite3_column_text(stmt_read, 9));
    vdir->level_mod[1] = atoi(sqlite3_column_text(stmt_read, 10));
    vdir->level_mod[2] = atoi(sqlite3_column_text(stmt_read, 11));

    vdir->level_index[0] = atoi(sqlite3_column_text(stmt_read, 12));
    vdir->level_index[1] = atoi(sqlite3_column_text(stmt_read, 13));
    vdir->level_index[2] = atoi(sqlite3_column_text(stmt_read, 14));

    strncpy(vdir->the_dir, sqlite3_column_text(stmt_read, 15), MAX_DIR_NAME);
  }
  sqlite3_finalize(stmt_read);

  if (found == 0) {
    int i;

    vdir->cur_users = 0;
    for (i = 0; i < MAX_DIR_LEVELS; ++i) {
      vdir->level_start[i] = 0;
      vdir->level_end[i] = MAX_DIR_LIST - 1;
      vdir->level_index[i] = 0;
    }
    vdir->level_mod[0] = 0;
    vdir->level_mod[1] = 2;
    vdir->level_mod[2] = 4;
    vdir->level_cur = 0;
    vdir->level_max = MAX_DIR_LEVELS;
    vdir->the_dir[0] = 0;
  }
  return (0);
}

int vwrite_dir_control(vdir_type *vdir, char *domain, uid_t uid, gid_t gid) {
  char *err_msg = NULL;
  if (vauth_open_update() != 0) return (-1);

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "replace into dir_control ( \
domain, cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir ) values ( \
'%s', %lu, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
%d, %d, %d, \
'%s')\n",
           domain, vdir->cur_users, vdir->level_cur, vdir->level_max,
           vdir->level_start[0], vdir->level_start[1], vdir->level_start[2],
           vdir->level_end[0], vdir->level_end[1], vdir->level_end[2],
           vdir->level_mod[0], vdir->level_mod[1], vdir->level_mod[2],
           vdir->level_index[0], vdir->level_index[1], vdir->level_index[2],
           vdir->the_dir);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    vcreate_dir_control(domain);
    if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) !=
        SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[15]: %s\n", err_msg);
      return -1;
    }
  }

  return (0);
}

/************************************************************************/
void vcreate_dir_control(char *domain) {
  char *err_msg = NULL;
  if (vauth_create_table("dir_control", DIR_CONTROL_TABLE_LAYOUT, 1)) return;

  /* this next bit should be replaced with a call to vwrite_dir_control */
  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "replace into dir_control ( \
domain, cur_users, \
level_cur, level_max, \
level_start0, level_start1, level_start2, \
level_end0, level_end1, level_end2, \
level_mod0, level_mod1, level_mod2, \
level_index0, level_index1, level_index2, the_dir ) values ( \
'%s', 0, \
0, %d, \
0, 0, 0, \
%d, %d, %d, \
0, 2, 4, \
0, 0, 0, \
'')\n",
           domain, MAX_DIR_LEVELS, MAX_DIR_LIST - 1, MAX_DIR_LIST - 1,
           MAX_DIR_LIST - 1);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    fprintf(stderr, "vmysql: sql error[16]: %s\n", err_msg);
    return;
  }
}

int vdel_dir_control(char *domain) {
  int err;
  char *err_msg = NULL;

  if ((err = vauth_open_update()) != 0) return (err);

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "delete from dir_control where domain = '%s'", domain);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    vcreate_dir_control(domain);
    if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) !=
        SQLITE_OK) {
      fprintf(stderr, "vmysql: sql error[e]: %s\n", err_msg);
      return (-1);
    }
  }

  return (0);
}

/************************************************************************/
#ifdef ENABLE_AUTH_LOGGING
int vset_lastauth(char *user, char *domain, char *remoteip) {
  int err;
  char *err_msg = NULL;

  if ((err = vauth_open_update()) != 0) return (err);

  /* replace into or update ? */
  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "replace into lastauth (user, domain, remote_ip, timestamp) \
        values ('%s', '%s', '%s', %lu)",
           user, domain, remoteip, time(NULL));

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    vcreate_lastauth_table();
    if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) !=
        SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[18]: %s\n", err_msg);
    }
  }
  return (0);
}

/************************************************************************/
time_t vget_lastauth(struct vqpasswd *pw, char *domain) {
  int rc;
  int err;
  time_t mytime;

  if ((err = vauth_open_read()) != 0) return (err);

  qnprintf(SqlBufRead, SQL_BUF_SIZE,
           "select timestamp from lastauth where user='%s' and domain='%s'",
           pw->pw_name, domain);

  rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[19]: %s\n",
            sqlite3_errmsg(sqlite_read));
    return (-1);
  }

  mytime = 0;
  while (1) {
    rc = sqlite3_step(stmt_read);

    if (rc != SQLITE_ROW) {
      mytime = atol(sqlite3_column_text(stmt_read, 0));
    } else if (rc != SQLITE_DONE) {
      break;
    } else {
      sqlite3_finalize(stmt_read);
      fprintf(stderr, "vsqlite: sql error[20]: %s\n",
              sqlite3_errmsg(sqlite_read));
      return (-1);
    }
  }

  sqlite3_finalize(stmt_read);

  return (mytime);
}

/************************************************************************/
char *vget_lastauthip(struct vqpasswd *pw, char *domain) {
  int rc;
  static char tmpbuf[100];

  if (vauth_open_read() != 0) return (NULL);

  qnprintf(SqlBufRead, SQL_BUF_SIZE,
           "select remote_ip from lastauth where user='%s' and domain='%s'",
           pw->pw_name, domain);

  rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[21]: %s\n",
            sqlite3_errmsg(sqlite_read));
    return (NULL);
  }

  rc = sqlite3_step(stmt_read);
  if ((rc != SQLITE_ROW) && (rc != SQLITE_DONE)) {
    vcreate_lastauth_table();
    rc = sqlite3_step(stmt_read);
    if ((rc != SQLITE_ROW) && (rc != SQLITE_DONE)) {
      fprintf(stderr, "vmysql: sql error[22]: %s\n",
              sqlite3_errmsg(sqlite_read));
      return (NULL);
    }
  }

  while (rc == SQLITE_ROW) {
    strncpy(tmpbuf, sqlite3_column_text(stmt_read, 0), 100);
    rc = sqlite3_step(stmt_read);
  }
  sqlite3_finalize(stmt_read);
  return (tmpbuf);
}

/************************************************************************/
void vcreate_lastauth_table() {
  vauth_create_table("lastauth", LASTAUTH_TABLE_LAYOUT, 1);
  return;
}
#endif /* ENABLE_AUTH_LOGGING */

#ifdef VALIAS
struct linklist *valias_current = NULL;

/************************************************************************/
char *valias_select(char *alias, char *domain) {
  int err;
  struct linklist *temp_entry = NULL;
  int rc;

  /* remove old entries as necessary */
  while (valias_current != NULL) valias_current = linklist_del(valias_current);

  /* if we can not connect, set the verrori value */
  if ((err = vauth_open_read()) != 0) {
    return (NULL);
  }

  qnprintf(SqlBufRead, SQL_BUF_SIZE,
           "select valias_line from valias \
where alias = '%s' and domain = '%s'",
           alias, domain);

  rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[24]: %s\n",
            sqlite3_errmsg(sqlite_read));
    return (NULL);
  }

  rc = sqlite3_step(stmt_read);
  if ((rc != SQLITE_OK) && (rc != SQLITE_DONE)) {
    vcreate_valias_table();
    rc = sqlite3_step(stmt_read);
    if ((rc != SQLITE_OK) && (rc != SQLITE_DONE)) {
      sqlite3_finalize(stmt_read);
      fprintf(stderr, "vsqlite: sql error[25]: %s\n",
              sqlite3_errmsg(sqlite_read));
      return (NULL);
    }
  }

  while (rc == SQLITE_OK) {
    fprintf(stderr, "%s\n", sqlite3_column_text(stmt_read, 0));
    temp_entry =
        linklist_add(temp_entry, sqlite3_column_text(stmt_read, 0), "");
    if (valias_current == NULL) valias_current = temp_entry;
    rc = sqlite3_step(stmt_read);
  }
  sqlite3_finalize(stmt_read);

  if (valias_current == NULL)
    return NULL; /* no results */
  else
    return (valias_current->data);
}

/************************************************************************/
char *valias_select_next() {
  if (valias_current == NULL) return NULL;

  valias_current = linklist_del(valias_current);

  if (valias_current == NULL)
    return NULL;
  else
    return valias_current->data;
}

/************************************************************************/
int valias_insert(char *alias, char *domain, char *alias_line) {
  int err;
  char *err_msg = NULL;

#ifdef USE_ONCHANGE
  char user_domain[MAX_BUFF];
#endif

  if ((err = vauth_open_update()) != 0) return (err);

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_insert", user_domain, alias_line, 0, 0);
#endif

  while (*alias_line == ' ' && *alias_line != 0) ++alias_line;

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "insert into valias \
( alias, domain, valias_line ) values ( '%s', '%s', '%s')",
           alias, domain, alias_line);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    vcreate_valias_table();
    if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) !=
        SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[26]: %s\n", err_msg);
      return (-1);
    }
  }

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_insert", user_domain, alias_line, 1, 1);
#endif

  return (0);
}

/************************************************************************/
int valias_remove(char *alias, char *domain, char *alias_line) {
  int err;
  char *err_msg = NULL;

#ifdef USE_ONCHANGE
  char user_domain[MAX_BUFF];
#endif

  if ((err = vauth_open_update()) != 0) return (err);

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_remove", user_domain, alias_line, 1, 0);
#endif

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "delete from valias where alias = '%s' \
and valias_line = '%s' and domain = '%s'",
           alias, alias_line, domain);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    vcreate_valias_table();
    if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) !=
        SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[27]: %s\n", err_msg);
      return (-1);
    }
  }

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_remove", user_domain, alias_line, 0, 1);
#endif

  return (0);
}

/************************************************************************/
int valias_delete(char *alias, char *domain) {
  int err;
  char *err_msg = NULL;

#ifdef USE_ONCHANGE
  char user_domain[MAX_BUFF];
#endif

  if ((err = vauth_open_update()) != 0) return (err);

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_delete", user_domain, "-", 1, 0);
#endif

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "delete from valias where alias = '%s' \
and domain = '%s'",
           alias, domain);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    vcreate_valias_table();
    if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) !=
        SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[28]: %s\n", err_msg);
      return (-1);
    }
  }

#ifdef USE_ONCHANGE
  snprintf(user_domain, MAX_BUFF, "%s@%s", alias, domain);
  on_change("valias_delete", user_domain, "-", 0, 1);
#endif

  return (0);
}

/************************************************************************/
int valias_delete_domain(char *domain) {
  int err;
  char *err_msg = NULL;

  if ((err = vauth_open_update()) != 0) return (err);

#ifdef USE_ONCHANGE
  on_change("valias_delete_domain", domain, "-", 1, 0);
#endif

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, "delete from valias where domain = '%s'",
           domain);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    vcreate_valias_table();
    if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) !=
        SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[29]: %s\n", err_msg);
      return (-1);
    }
  }

#ifdef USE_ONCHANGE
  on_change("valias_delete_domain", domain, "-", 0, 1);
#endif

  return (0);
}

/************************************************************************/
void vcreate_valias_table() {
  int err;
  char *err_msg = NULL;

  vauth_create_table("valias", VALIAS_TABLE_LAYOUT, 1);

  if ((err = vauth_open_update()) != 0) return;

  snprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "create index valias_idx on valias ( %s )", VALIAS_INDEX_LAYOUT);
  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[37]: %s\n", err_msg);
    return;
  }
}

/************************************************************************/
char *valias_select_all(char *alias, char *domain) {
  int err;
  int rc;
  struct linklist *temp_entry = NULL;

  /* remove old entries as necessary */
  while (valias_current != NULL) valias_current = linklist_del(valias_current);

  if ((err = vauth_open_read()) != 0) return (NULL);

  qnprintf(SqlBufRead, SQL_BUF_SIZE,
           "select alias, valias_line from valias where domain = '%s' order by "
           "alias",
           domain);

  rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[30]: %s\n",
            sqlite3_errmsg(sqlite_read));
    return (NULL);
  }

  rc = sqlite3_step(stmt_read);
  if ((rc != SQLITE_OK) && (rc != SQLITE_DONE)) {
    vcreate_valias_table();
    rc = sqlite3_step(stmt_read);
    if ((rc != SQLITE_OK) && (rc != SQLITE_DONE)) {
      sqlite3_finalize(stmt_read);
      fprintf(stderr, "vsqlite: sql error[31]: %s\n",
              sqlite3_errmsg(sqlite_read));
      return (NULL);
    }
  }

  while (rc == SQLITE_ROW) {
    temp_entry = linklist_add(temp_entry, sqlite3_column_text(stmt_read, 1),
                              sqlite3_column_text(stmt_read, 0));
    if (valias_current == NULL) valias_current = temp_entry;
    rc = sqlite3_step(stmt_read);
  }
  sqlite3_finalize(stmt_read);

  if (valias_current == NULL)
    return NULL; /* no results */
  else {
    strcpy(alias, valias_current->d2);
    return (valias_current->data);
  }
  return NULL;
}

/************************************************************************/
char *valias_select_all_next(char *alias) {
  if (valias_current == NULL) return NULL;
  valias_current = linklist_del(valias_current);

  if (valias_current == NULL)
    return NULL; /* no results */
  else {
    strcpy(alias, valias_current->d2);
    return (valias_current->data);
  }
}

/************************************************************************
 *
 *  valias_select_names
 */

char *valias_select_names(char *domain) {
  int rc;
  struct linklist *temp_entry = NULL;

  /* remove old entries as necessary */
  while (valias_current != NULL) valias_current = linklist_del(valias_current);

  if (vauth_open_read()) return (NULL);

  qnprintf(
      SqlBufRead, SQL_BUF_SIZE,
      "select distinct alias from valias where domain = '%s' order by alias",
      domain);

  rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[32]: %s\n",
            sqlite3_errmsg(sqlite_read));
    return (NULL);
  }

  rc = sqlite3_step(stmt_read);
  if ((rc != SQLITE_OK) && (rc != SQLITE_DONE)) {
    vcreate_valias_table();
    rc = sqlite3_step(stmt_read);
    if ((rc != SQLITE_OK) && (rc != SQLITE_DONE)) {
      sqlite3_finalize(stmt_read);
      fprintf(stderr, "vsqlite: sql error[33]: %s\n",
              sqlite3_errmsg(sqlite_read));
      return (NULL);
    }
  }

  while (rc == SQLITE_ROW) {
    temp_entry =
        linklist_add(temp_entry, sqlite3_column_text(stmt_read, 0), "");
    if (valias_current == NULL) valias_current = temp_entry;
    rc = sqlite3_step(stmt_read);
  }
  sqlite3_finalize(stmt_read);

  if (valias_current == NULL)
    return NULL; /* no results */
  else
    return (valias_current->data);
}

/************************************************************************
 *
 *  valias_select_names_next
 */

char *valias_select_names_next() {
  if (valias_current == NULL) return NULL;
  valias_current = linklist_del(valias_current);

  if (valias_current == NULL)
    return NULL; /* no results */
  else
    return (valias_current->data);
}

/************************************************************************
 *
 *  valias_select_names_end
 */

void valias_select_names_end() {
  //  not needed by sqlite ?
}

#endif

/************************************************************************/
#ifdef ENABLE_SQL_LOGGING
int logsql(int verror, char *TheUser, char *TheDomain, char *ThePass,
           char *TheName, char *IpAddr, char *LogLine) {
  int err;
  time_t mytime;
  char *err_msg = NULL;

  mytime = time(NULL);
  if ((err = vauth_open_update()) != 0) return (err);

  qnprintf(SqlBufUpdate, SQL_BUF_SIZE,
           "INSERT INTO vlog set user='%s', passwd='%s', \
        domain='%s', logon='%s', remoteip='%s', message='%s', \
        error=%i, timestamp=%d",
           TheUser, ThePass, TheDomain, TheName, IpAddr, LogLine, verror,
           (int)mytime);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    vcreate_vlog_table();
    if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) !=
        SQLITE_OK) {
      fprintf(stderr, "error inserting into vlog table\n");
    }
  }

  return (0);
}

/************************************************************************/
void vcreate_vlog_table() { vauth_create_table("vlog", VLOG_TABLE_LAYOUT, 1); }
#endif

#ifdef ENABLE_MYSQL_LIMITS
void vcreate_limits_table() {
  vauth_create_table("limits", LIMITS_TABLE_LAYOUT, 1);
}

int vget_limits(const char *domain, struct vlimits *limits) {
  vdefault_limits(limits);
  int rc;

  if (vauth_open_read() != 0) return (-1);

  qnprintf(SqlBufRead, SQL_BUF_SIZE,
           "SELECT maxpopaccounts, maxaliases, "
           "maxforwards, maxautoresponders, maxmailinglists, diskquota, "
           "maxmsgcount, defaultquota, defaultmaxmsgcount, "
           "disable_pop, disable_imap, disable_dialup, "
           "disable_passwordchanging, disable_webmail, disable_relay, "
           "disable_smtp, disable_spamassassin, delete_spam, disable_maildrop, "
           "perm_account, "
           "perm_alias, perm_forward, perm_autoresponder, perm_maillist, "
           "perm_quota, perm_defaultquota \n"
           "FROM limits \n"
           "WHERE domain = '%s'",
           domain);

  rc = sqlite3_prepare_v2(sqlite_read, SqlBufRead, -1, &stmt_read, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "vsqlite: sql error[34]: %s\n",
            sqlite3_errmsg(sqlite_read));
    return (-1);
  }

  rc = sqlite3_step(stmt_read);
  if (rc == SQLITE_ROW) {
    int perm = atol(sqlite3_column_text(stmt_read, 22));

    limits->maxpopaccounts = atoi(sqlite3_column_text(stmt_read, 0));
    limits->maxaliases = atoi(sqlite3_column_text(stmt_read, 1));
    limits->maxforwards = atoi(sqlite3_column_text(stmt_read, 2));
    limits->maxautoresponders = atoi(sqlite3_column_text(stmt_read, 3));
    limits->maxmailinglists = atoi(sqlite3_column_text(stmt_read, 4));
    limits->diskquota = strtoll(sqlite3_column_text(stmt_read, 5), NULL, 10);
    limits->maxmsgcount = strtoll(sqlite3_column_text(stmt_read, 6), NULL, 10);
    limits->defaultquota = strtoll(sqlite3_column_text(stmt_read, 7), NULL, 10);
    limits->defaultmaxmsgcount =
        strtoll(sqlite3_column_text(stmt_read, 8), NULL, 10);
    limits->disable_pop = atoi(sqlite3_column_text(stmt_read, 9));
    limits->disable_imap = atoi(sqlite3_column_text(stmt_read, 10));
    limits->disable_dialup = atoi(sqlite3_column_text(stmt_read, 11));
    limits->disable_passwordchanging = atoi(sqlite3_column_text(stmt_read, 12));
    limits->disable_webmail = atoi(sqlite3_column_text(stmt_read, 13));
    limits->disable_relay = atoi(sqlite3_column_text(stmt_read, 14));
    limits->disable_smtp = atoi(sqlite3_column_text(stmt_read, 15));
    limits->disable_spamassassin = atoi(sqlite3_column_text(stmt_read, 16));
    limits->delete_spam = atoi(sqlite3_column_text(stmt_read, 17));
    limits->disable_maildrop = atoi(sqlite3_column_text(stmt_read, 18));
    limits->perm_account = atoi(sqlite3_column_text(stmt_read, 19));
    limits->perm_alias = atoi(sqlite3_column_text(stmt_read, 20));
    limits->perm_forward = atoi(sqlite3_column_text(stmt_read, 21));
    limits->perm_autoresponder = atoi(sqlite3_column_text(stmt_read, 22));
    limits->perm_maillist = perm & VLIMIT_DISABLE_ALL;
    perm >>= VLIMIT_DISABLE_BITS;
    limits->perm_maillist_users = perm & VLIMIT_DISABLE_ALL;
    perm >>= VLIMIT_DISABLE_BITS;
    limits->perm_maillist_moderators = perm & VLIMIT_DISABLE_ALL;
    limits->perm_quota = strtoll(sqlite3_column_text(stmt_read, 23), NULL, 10);
    limits->perm_defaultquota =
        strtoll(sqlite3_column_text(stmt_read, 24), NULL, 10);
  } else if (rc == SQLITE_DONE) {
    sqlite3_finalize(stmt_read);
    return vlimits_read_limits_file(VLIMITS_DEFAULT_FILE, limits);
  } else {
    fprintf(stderr, "vsqlite: sql error[35]: %s\n",
            sqlite3_errmsg(sqlite_read));
    return (-1);
  }

  return 0;
}

/************************************************************************/
int vset_limits(const char *domain, const struct vlimits *limits) {
  char *err_msg = NULL;

  if (vauth_open_update() != 0) return (-1);

  qnprintf(
      SqlBufUpdate, SQL_BUF_SIZE,
      "REPLACE INTO limits ("
      "domain, maxpopaccounts, maxaliases, "
      "maxforwards, maxautoresponders, maxmailinglists, "
      "diskquota, maxmsgcount, defaultquota, defaultmaxmsgcount, "
      "disable_pop, disable_imap, disable_dialup, "
      "disable_passwordchanging, disable_webmail, disable_relay, "
      "disable_smtp, disable_spamassassin, delete_spam, disable_maildrop, "
      "perm_account, "
      "perm_alias, perm_forward, perm_autoresponder, perm_maillist, "
      "perm_quota, perm_defaultquota) \n"
      "VALUES \n"
      "('%s', %d, %d, %d, %d, %d, %S, %S, %S, %S, %d, %d, %d, %d, %d, %d, %d, "
      "%d, %d, %d, %d, %d, %d, %d, %d, %d, %d)",
      domain, limits->maxpopaccounts, limits->maxaliases, limits->maxforwards,
      limits->maxautoresponders, limits->maxmailinglists, limits->diskquota,
      limits->maxmsgcount, limits->defaultquota, limits->defaultmaxmsgcount,
      limits->disable_pop, limits->disable_imap, limits->disable_dialup,
      limits->disable_passwordchanging, limits->disable_webmail,
      limits->disable_relay, limits->disable_smtp, limits->disable_spamassassin,
      limits->delete_spam, limits->disable_maildrop, limits->perm_account,
      limits->perm_alias, limits->perm_forward, limits->perm_autoresponder,
      (limits->perm_maillist |
       (limits->perm_maillist_users << VLIMIT_DISABLE_BITS) |
       (limits->perm_maillist_moderators << (VLIMIT_DISABLE_BITS * 2))),
      limits->perm_quota, limits->perm_defaultquota);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    vcreate_limits_table();
    if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) !=
        SQLITE_OK) {
      fprintf(stderr, "vsqlite: sql error[36]: %s\n", err_msg);
      return (-1);
    }
  }

  return 0;
}

/************************************************************************/
int vdel_limits(const char *domain) {
  char *err_msg = NULL;
  qnprintf(SqlBufUpdate, SQL_BUF_SIZE, "DELETE FROM limits WHERE domain = '%s'",
           domain);

  if (sqlite3_exec(sqlite_update, SqlBufUpdate, 0, 0, &err_msg) != SQLITE_OK) {
    /* fprintf(stderr, "vsqlite: sql error: %s\n", err_msg); */
    return (-1);
  }
  return 0;
}

#endif

int vauth_crypt(char *user, char *domain, char *clear_pass,
                struct vqpasswd *vpw) {
  const char *c;
	const char *p;
  if ( vpw == NULL ) return(-1);
	p = vpw->pw_passwd;
	
  /* if needed remove {XXX-CRYPT}$ */
	if (p[0] == '{') {
		const char *k = strchr(p, '}');
		if (k != NULL) p = k + 1;
	}
	
  c = crypt(clear_pass, p);
  if (c == NULL) return (-1);
  return(strcmp(c, p));
}
