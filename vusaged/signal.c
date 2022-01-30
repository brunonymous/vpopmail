/*
   $Id: signal.c 1014 2011-02-03 16:04:37Z volz0r $

   * Copyright (C) 2009 Inter7 Internet Technologies, Inc.
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

#include <stdio.h>
#include <signal.h>
#include "conf.h"
#include "queue.h"
#include "signal.h"
#include "shutdown.h"

extern char shutdown_flag;

static void signal_shutdown(int);

int signal_init(config_t *config)
{
   signal(SIGPIPE, SIG_IGN);
   signal(SIGHUP, SIG_IGN);
   signal(SIGTERM, signal_shutdown);
   signal(SIGUSR1, SIG_IGN);
   signal(SIGUSR2, SIG_IGN);
   signal(SIGINT, signal_shutdown);

   return 1;
}

static void signal_shutdown(int signal)
{
   if (shutdown_flag)
	  return;

   shutdown_trigger();
}
