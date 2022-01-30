/*
   $Id: storage.h 1014 2011-02-03 16:04:37Z volz0r $

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

#ifndef __STORAGE_H_
   #define __STORAGE_H_

#include "config.h"
#include <stdint.h>
#include <stdlib.h>

/*
   htonll() and ntohll()
*/

#ifdef HAVE_ENDIAN_H
	#include <endian.h>
#endif

#ifdef HAVE_BYTESWAP_H
	#include <byteswap.h>
#endif

#ifdef HAVE_SYS_ENDIAN_H
	#include <sys/endian.h>
#endif

#ifdef HAVE_MACHINE_ENDIAN_H
	#include <machine/endian.h>
#endif

#include <sys/types.h>
#include <netinet/in.h>

#ifdef HAVE_INTTYPES_H
	#include <inttypes.h>
#endif

#if !defined(LLONG_MAX)
	#define LLONG_MAX 9223372036854775807LL
#endif

#if !defined(HAVE_HTONLL) || !defined(HAVE_NTOHLL)
#if defined(__LITTLE_ENDIAN) || defined(_LITTLE_ENDIAN) || defined(__LITTLE_ENDIAN__)
# ifndef ntohll
# if defined(__DARWIN__)
# define ntohll(_x_) NXSwapBigLongLongToHost(_x_)
# else
  #ifdef HAVE_BSWAP64
	#define ntohll(_x_) bswap64(_x_)
  #else
	# define ntohll(_x_) __bswap_64(_x_)
  #endif
# endif
# endif
# ifndef htonll
# if defined(__DARWIN__)
# define htonll(_x_) NXSwapHostLongLongToBig(_x_)
# else
  #ifdef HAVE_BSWAP64
	#define htonll(_x_) bswap64(_x_)
  #else
	# define htonll(_x_) __bswap_64(_x_)
  #endif
# endif
# endif
#elif defined(__BIG_ENDIAN) || defined(_BIG_ENDIAN) || defined(__BIG_ENDIAN__)
# ifndef ntohll
# define ntohll(_x_) _x_
# endif
# ifndef htonll
# define htonll(_x_) _x_
# endif
#else /* No Endian selected */
# error A byte order must be selected
#endif

/*
   Define htonll() and ntohll() if not already defined
*/

#ifndef ntohll
	#ifdef HAVE_BSWAP64
		#define ntohll(x) bswap64(x)
	#else
		#define ntohll(x) __bswap_64(x)
	#endif
#endif

#ifndef htonll
   #ifdef HAVE_BSWAP64
   		#define htonll(x) bswap64(x)
   #else
		#define htonll(x) __bswap_64(x)
   #endif
#endif
#endif

/*
   Arbitrary storage counts
*/

typedef uint64_t storage_t;

#endif
