/*
   Copyright (c) 2006-2009 LW, Inc. <http://www.lw.com>
   This file is part of LWFS.

   LWFS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published
   by the Free Software Foundation; either version 3 of the License,
   or (at your option) any later version.

   LWFS is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see
   <http://www.gnu.org/licenses/>.
*/


#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/time.h>

#include "xlator.h"

typedef struct{
	lwfs_fop_t fop;
	fd_t* fd;
	loc_t* loc;
	loc_t* newloc;
	int32_t flags;
	int32_t wbflags;

	off_t offset;
	size_t size;

	int32_t op_ret;
	int32_t op_error;

	dict_t* dict;
	char* name;
	int set_local;

	//测试专用
	struct timeval start_time;
	struct timeval end_time;

}ac_local_t;

#define AC_BASE_PATH(this) (((struct ac_private *)this->private)->base_path)

#define AC_BASE_PATH_LEN(this) (((struct ac_private *)this->private)->base_path_length)

#define MAKE_REAL_PATH(var, this, path) do {                            \
		var = alloca (strlen (path) + AC_BASE_PATH_LEN(this) + 2); \
                strcpy (var, AC_BASE_PATH(this));			\
                strcpy (&var[AC_BASE_PATH_LEN(this)], path);		\
        } while (0)

#define LENGEST_ATTR_LENGTH 50
#define LONGEST_POLICY_LENGTH 256
#define POLICY_XATTR "user.policy"

