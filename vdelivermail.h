/*
 * $Id: vdelivermail.h 1014 2011-02-03 16:04:37Z volz0r $
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
#ifndef VPOPMAIL_VDELIVERMAIL_H
#define VPOPMAIL_VDELIVERMAIL_H

void delete_tmp();
int failtemp(char *,...);
int failperm(char *,...);
struct vqpasswd* pop_user_exist(char *, char *, char *, char *);
void sig_handler(int);
void deliver_mail(char *, struct vqpasswd *);
int is_bounce(char *);
off_t check_quota();
off_t count_dir(char *dir);
off_t recalc_quota(char *dir_name);
void update_quota(off_t new_size);
int is_email_addr(char *);
int email_it(char *address);
int email_file(char *, char *);
int check_forward_deliver(char *);
int bounce_it_back(char *);
int is_delete(char *);

#endif
