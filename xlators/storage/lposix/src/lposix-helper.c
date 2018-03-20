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

#define __XOPEN_SOURCE 500

#include <stdint.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <ftw.h>


#include "xlator.h"
#include "logging.h"
#include "lposix.h"


struct quota_entry {
	uid_t uid;
	gid_t gid;
	/* 
	 * 0 : no quota overflow;
	 * 1 : user or group space overflow
	 * 2 : user or group inode overflow
	*/
	int status;
	struct list_head list;
};

/* global variable */
struct quota_all {
	struct list_head quota_list;
	int count;
	gf_lock_t lock;
} quota_pool;
char *mnt = NULL;

/*
  hexb@20120309
  lwfs make a directory for every connected client, so
  client could be separated from other.
 */
char *make_real_path_from_frame (call_frame_t *frame, xlator_t *this, char *loc_path)
{
	struct lposix_connection *conn = NULL;
	char	*id = NULL, *tk = NULL, *path = NULL;
	struct stat	st;

	if (frame && frame->root)
		conn = (struct lposix_connection *)frame->root->trans;
	else
		return NULL ;

	id = strdup (conn->id);
	tk = strtok (id, "-");
	if (tk == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Impossible [%s]",
			strerror (errno));
		free (id);
		goto err;
	} 


	path = calloc (strlen (loc_path) + POSIX_BASE_PATH_LEN(this) + strlen (tk) + strlen (loc_path) + 2,
		sizeof(char));
	if (path == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of Memory");
		goto err;
	}
	strcat (path, POSIX_BASE_PATH(this));
	strcat (path, "/");
	strcat (path, tk);

	gf_log (this->name, GF_LOG_TRACE, "base_name %s, path name %s, tk %s resolve %s",
			POSIX_BASE_PATH(this), loc_path, tk, path);

	if(stat (path, &st) && (errno == ENOENT)) {
		gf_log (this->name, GF_LOG_NORMAL, "stat %s failed", path);
		if (mkdir (path, 777) < 0) {
			gf_log (this->name, GF_LOG_ERROR, "failed to make hostname directory[%s]",
				path);
			goto err;
		}
		if (chmod (path, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH) < 0) {
			gf_log (this->name, GF_LOG_ERROR, "failed to chmod directory[%s]",
				path);
			goto err;
		}
	} else {
		if (!S_ISDIR(st.st_mode)){
			gf_log (this->name, GF_LOG_ERROR, "A hostname file[%s] exist",
				path);
			goto err;

		} 
	}
	strcat (path, "/");
	strcat (path, loc_path);
	gf_log (this->name, GF_LOG_TRACE, "path %s, %s", path, loc_path);
	return path;
err:
	if (id != NULL)
		free (id);
	if (path != NULL)
		free (path);
	return NULL;
}

