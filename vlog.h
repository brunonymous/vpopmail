/*
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
 */

/* Definitions Of vpopmail error types*/
#define VLOG_ERROR_INTERNAL     0  /* logs an internal error these messages only go to syslog if option is on */
#define VLOG_ERROR_LOGON        1  /* bad logon, user does not exist */
#define VLOG_AUTH               2  /* logs a successful authentication */
#define VLOG_ERROR_PASSWD       3  /* password is incorrect or empty*/
#define VLOG_ERROR_ACCESS       4  /* access is denied by 2 in gid */

