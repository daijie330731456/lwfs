/*
   Copyright (c) 2008-2009 LW, Inc. <http://www.lw.com>
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

#include "lwfs.h"
#include "xlator.h"
#include "defaults.h"
#include "combine.h"

#include <sys/time.h>
#include <libgen.h>


#define EXT3_HTREE_EOF        0x7fffffff

int
combine_statfs_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno, struct statvfs *statvfs)
{
	combine_local_t *local = NULL;
	int this_call_cnt = 0;


	local = frame->local;
	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			goto unlock;
		}
		local->op_ret = 0;

		local->statvfs.f_bsize    = statvfs->f_bsize;
		local->statvfs.f_frsize   = statvfs->f_frsize;

		local->statvfs.f_blocks  += statvfs->f_blocks;
		local->statvfs.f_bfree   += statvfs->f_bfree;
		local->statvfs.f_bavail  += statvfs->f_bavail;
		local->statvfs.f_files   += statvfs->f_files;
		local->statvfs.f_ffree   += statvfs->f_ffree;
		local->statvfs.f_favail  += statvfs->f_favail;
		local->statvfs.f_fsid     = statvfs->f_fsid;
		local->statvfs.f_flag     = statvfs->f_flag;
		local->statvfs.f_namemax  = statvfs->f_namemax;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		if (!local->op_ret)
			gf_log (this->name, GF_LOG_TRACE,
                                "%"PRId64": ({f_bsize=%lu, f_frsize=%lu, f_blocks=%"GF_PRI_FSBLK
                                ", f_bfree=%"GF_PRI_FSBLK", f_bavail=%"GF_PRI_FSBLK", "
                                "f_files=%"GF_PRI_FSBLK", f_ffree=%"GF_PRI_FSBLK", f_favail=%"
                                GF_PRI_FSBLK", f_fsid=%lu, f_flag=%lu, f_namemax=%lu}) => ret=%d",
                                frame->root->unique, statvfs->f_bsize, statvfs->f_frsize, statvfs->f_blocks,
                                statvfs->f_bfree, statvfs->f_bavail, statvfs->f_files, statvfs->f_ffree,
                                statvfs->f_favail, statvfs->f_fsid, statvfs->f_flag, statvfs->f_namemax, op_ret);
		else
                        gf_log (this->name, GF_LOG_ERROR,
                                "statfs return %"PRId64": (op_ret=%d, op_errno=%d)",
                                frame->root->unique, op_ret, op_errno);

		COMBINE_STACK_UNWIND (statfs, frame, local->op_ret, local->op_errno,
				  &local->statvfs);
	}

        return 0;
}
int
combine_lookup_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int op_ret, int op_errno,
                    inode_t *inode, struct stat *stbuf, dict_t *xattr,
                    struct stat *postparent)
{
        call_frame_t *prev             = NULL;
	combine_conf_t   *conf         = NULL;
        combine_local_t  *local        = NULL;
	loc_t 		 *loc 	       = NULL;
	int	      is_dir           = 0;
        int           this_call_cnt    = 0;

	conf  = this->private;
        local = frame->local;
        prev  = cookie;
	loc = &(local->loc);

	
	
	LOCK (&frame->lock);
        {
		if (op_ret == -1) {
			local->op_ret = op_ret;
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
					"lookup of %s on %s returned error (%s)",
					local->loc.path, prev->this->name,
					strerror (op_errno));
			set_subvol_inode_ctx (this,local,prev->this, 0x0);
			goto unlock;
		} else
			local->op_ret = op_ret;

		is_dir = check_is_dir (inode, stbuf, xattr);
		if (!is_dir) {
			local->file_count ++;
			if (local->inode->ino == 1) {
				gf_log (this->name, GF_LOG_DEBUG,
						"lookup of %s on %s returned non dir 0%o",
						local->loc.path, prev->this->name,
						stbuf->st_mode);
				goto unlock;
			}
			combine_itransform (this, prev->this, stbuf->st_ino,
				&stbuf->st_ino);
			combine_stat_merge (this, &local->stbuf, stbuf, prev->this);
			local->st_ino = local->stbuf.st_ino;
			local->st_dev = local->stbuf.st_dev;
		} else {
			local->dir_count ++;
			combine_itransform (this, prev->this, stbuf->st_ino,
				&stbuf->st_ino);
			combine_stat_merge (this, &local->stbuf, stbuf, prev->this);
			combine_stat_merge (this, &local->postparent, postparent,
		       		prev->this);
			gf_log (this->name, GF_LOG_DEBUG,
					"JJH lookup of %s on %s returned ino (%lu)",
					local->loc.path, prev->this->name,
					local->stbuf.st_ino);
			local->st_ino = local->stbuf.st_ino;
			local->st_dev = local->stbuf.st_dev;
			if(local->inode->ino == 1)
				local->stbuf.st_ino = 1;
		}
		/* after set stat, then set position */
		set_subvol_inode_ctx (this,local,prev->this, 0x1);
		if (loc->parent)
			postparent->st_ino = loc->parent->ino;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		if ( ( local->file_count + local->dir_count ) > 0){
			/* have someone success */
			/* if error, don't know is_dir */
			COMBINE_STACK_UNWIND (lookup, frame, 0, 0,
				 local->inode, &local->stbuf, xattr, postparent);

		} else {
			/* equal 0 is have error */
			COMBINE_STACK_UNWIND (lookup, frame, local->op_ret, local->op_errno,
				 local->inode, &local->stbuf, xattr, postparent);
		}
	}
	return 0;
}

int
combine_attr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno, struct stat *stbuf)
{
	combine_local_t *local = NULL;
	call_frame_t *prev = NULL;
	int this_call_cnt = 0;

	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"Subvolume %s returnd -1(%s)",
				prev->this->name, strerror(op_errno));
			goto unlock;
		}
		combine_stat_merge (this, &local->stbuf, stbuf, prev->this);
		if (local->inode)
			local->stbuf.st_ino = local->inode->ino;
		local->op_ret = 0;
		
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt))

		COMBINE_STACK_UNWIND (stat, frame, 
			local->op_ret, local->op_errno, &local->stbuf);
	return 0;
}
int
combine_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno, struct stat *prebuf,
		struct stat *postbuf)
{
	combine_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;


	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}
		combine_stat_merge (this, &local->prebuf, prebuf, prev->this);
		combine_stat_merge (this, &local->stbuf, postbuf, prev->this);
		if (local->inode) {
			local->stbuf.st_ino = local->inode->ino;
			local->prebuf.st_ino = local->inode->ino;
		}

		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt))
		COMBINE_STACK_UNWIND (truncate, frame, local->op_ret, local->op_errno,
			prebuf, &local->stbuf);
	return 0;
}

int
combine_lookup (call_frame_t *frame, xlator_t *this,
		loc_t *loc, dict_t *xattr_req)
{
        xlator_t     *subvol = NULL;
        combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
        int           ret    = -1;
        int           op_errno = -1;
	int           i = 0;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;

	local = combine_local_init (frame);
	if (!local) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->inode = inode_ref (loc->inode);
	ret = loc_dup (loc, &local->loc); 
	if (ret == -1) {
		op_errno = -errno;
		gf_log (this->name, GF_LOG_DEBUG,
			"copying location failed for path %s",
			loc->path);
		goto err;
	}

	subvol = get_subvol_from_inode_ctx(this, loc);
	if (subvol == NULL) {
		/* lookup everywhere */
		local->call_cnt = conf->subvolume_cnt;

		/* don't use local->call_cnt, it will be dec in cbk */
		for (i = 0; i < conf->subvolume_cnt; i++) {
gf_log (this->name, GF_LOG_DEBUG, "Lookup count[%d] sub[%s]",i,conf->subvolumes[i]->name);
			STACK_WIND (frame, combine_lookup_cbk,
			    conf->subvolumes[i],
			    conf->subvolumes[i]->fops->lookup,
			    loc, xattr_req);
		}
	} else {
		local->call_cnt = 1;
        	STACK_WIND (frame, combine_lookup_cbk,
                     	subvol,
	    		subvol->fops->lookup,
                     	loc, xattr_req);
	}

	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (lookup, frame, -1, op_errno, NULL, NULL, NULL, NULL);
	return 0;
}

int
combine_opendir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	      int op_ret, int op_errno, fd_t *fd)
{
	combine_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;

	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}

		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		COMBINE_STACK_UNWIND (opendir, frame, local->op_ret, local->op_errno,
				  local->fd);
	}
        return 0;
}

int
combine_fsyncdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno)
{
	combine_local_t  *local = NULL;
	int           this_call_cnt = 0;


	local = frame->local;

	LOCK (&frame->lock);
	{
		if (op_ret == -1)
			local->op_errno = op_errno;

		if (op_ret == 0)
			local->op_ret = 0;
	}
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt))
		COMBINE_STACK_UNWIND (fsyncdir, frame, local->op_ret, local->op_errno);

	return 0;
}

int
combine_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno,
		fd_t *fd, inode_t *inode, struct stat *stbuf,
		struct stat *preparent, struct stat *postparent)
{
	call_frame_t *prev = NULL;
	combine_local_t  *local = NULL;
	int this_call_cnt;

	if (op_ret == -1)
		goto out;

	local = frame->local;
	prev = cookie;
	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
					"subvolume %s returned -1 (%s)",
					prev->this->name, strerror (op_errno));
			goto unlock;
		}
		local->op_ret = 0;
		combine_itransform (this, prev->this, stbuf->st_ino, &stbuf->st_ino);
		if (local->loc.parent) {
			preparent->st_ino = local->loc.parent->ino;
			postparent->st_ino = local->loc.parent->ino;
		}
	}
unlock:
	UNLOCK (&frame->lock);

out:
	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		COMBINE_STACK_UNWIND (create, frame, local->op_ret, local->op_errno,
				fd, inode, stbuf, preparent,
			        postparent);
	}
	return 0;
}

int
combine_fd_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
	      int op_ret, int op_errno, fd_t *fd)
{
	combine_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;

	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_ret = op_ret;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}
		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		COMBINE_STACK_UNWIND (open, frame, local->op_ret, local->op_errno,
				  local->fd);
	}
        return 0;
}

int
combine_access_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		 int op_ret, int op_errno)
{
	combine_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;

	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			if ( op_errno != ENOENT )
				local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
					"subvolume %s returned -1 (%s)",
					prev->this->name, strerror (op_errno));
			goto unlock;
		}

		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		COMBINE_STACK_UNWIND (access, frame, local->op_ret, local->op_errno);
	}

	return 0;
}
int
combine_readlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno, const char *path, struct stat *sbuf)
{
	combine_local_t *local = NULL;

	local = frame->local;
	if (op_ret == -1)
		goto err;

	if (local) {
		sbuf->st_ino = local->st_ino;
	} else {
		op_ret = -1;
		op_errno = EINVAL;
	}

err:
	COMBINE_STACK_UNWIND (readlink, frame, op_ret, op_errno, path, sbuf);

	return 0;
}

int
combine_mkdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno, inode_t *inode, struct stat *stbuf,
		 struct stat *preparent, struct stat *postparent)
{
	call_frame_t *prev = NULL;
	combine_local_t  *local = NULL;
	int this_call_cnt;

	if (op_ret == -1)
		goto out;

	local = frame->local;
	prev = cookie;
	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
					"subvolume %s returned -1 (%s)",
					prev->this->name, strerror (op_errno));
			goto unlock;
		}
		local->op_ret = 0;
		combine_stat_merge (this, &local->stbuf, stbuf, prev->this);
		combine_stat_merge (this, &local->preparent, preparent, prev->this);
		combine_stat_merge (this, &local->postparent, postparent,
				prev->this);

	
		local->st_ino = local->stbuf.st_ino;
		local->st_dev = local->stbuf.st_dev;
		if (local->loc.parent) {
			local->preparent.st_ino = local->loc.parent->ino;
			local->postparent.st_ino = local->loc.parent->ino;
		}
	}
unlock:
	UNLOCK (&frame->lock);

out:
	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		COMBINE_STACK_UNWIND (mkdir, frame, local->op_ret, local->op_errno,
				inode, &local->stbuf, preparent,
			        postparent);
	}
	return 0;
}

int
combine_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		 int op_ret, int op_errno, struct stat *preparent,
		 struct stat *postparent)
{
	combine_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;
	combine_conf_t *conf = this->private;


	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			local->dir_count ++;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}

		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		if ( local->dir_count == conf->subvolume_cnt) {
			COMBINE_STACK_UNWIND (unlink, frame, 
				local->op_ret, local->op_errno, NULL, NULL);
		} else
			COMBINE_STACK_UNWIND (unlink, frame, 
				0, 0, NULL, NULL);
	}

	return 0;
}

int
combine_rmdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		 int op_ret, int op_errno, struct stat *preparent,
		 struct stat *postparent)
{
	combine_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;
	combine_conf_t *conf = this->private;


	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			local->dir_count ++;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}

		local->op_ret = 0;
		combine_stat_merge (this, &local->preparent, preparent, prev->this);
		combine_stat_merge (this, &local->postparent, postparent,
				prev->this);
		if (local->loc.parent) {
			local->preparent.st_ino = local->loc.parent->ino;
			local->postparent.st_ino = local->loc.parent->ino;
		}
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		if ( local->dir_count == conf->subvolume_cnt) {
			COMBINE_STACK_UNWIND (rmdir, frame, 
				local->op_ret, local->op_errno, 
				&local->preparent, &local->postparent);
		} else 
			COMBINE_STACK_UNWIND (rmdir, frame, 
				0, 0, 
				&local->preparent, &local->postparent);
	}

	return 0;
}

int
combine_symlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		 int32_t op_ret, int32_t op_errno, inode_t *inode,
		 struct stat *stbuf, struct stat *preparent,
		 struct stat *postparent)
{
	call_frame_t *prev = NULL;
	combine_local_t  *local = NULL;
	int           this_call_cnt;

	local = frame->local;

	prev = cookie;
	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}
		local->op_ret = 0;
		combine_itransform (this, prev->this, stbuf->st_ino, &stbuf->st_ino);
		if (local->loc.parent) {
			preparent->st_ino = local->loc.parent->ino;
			postparent->st_ino = local->loc.parent->ino;
		}
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		COMBINE_STACK_UNWIND (symlink, frame, op_ret, op_errno, inode,
				stbuf, preparent, postparent);
	}
	return 0;

}
int
combine_rename_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *stbuf,
		struct stat *preoldparent, struct stat *postoldparent,
		struct stat *prenewparent, struct stat *postnewparent)
{
	combine_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;

	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}
		local->op_ret = 0;

		combine_stat_merge (this, &local->stbuf, stbuf, prev->this);
		combine_stat_merge (this, &local->preoldparent, preoldparent, prev->this);
		combine_stat_merge (this, &local->postoldparent, postoldparent, prev->this);
		combine_stat_merge (this, &local->preparent, prenewparent, prev->this);
		combine_stat_merge (this, &local->postparent, postnewparent, prev->this);

		local->stbuf.st_ino = local->loc.inode->ino;

		local->preoldparent.st_ino = local->loc.parent->ino;
		local->postoldparent.st_ino = local->loc.parent->ino;

		local->preparent.st_ino = local->loc2.parent->ino;
		local->postparent.st_ino = local->loc2.parent->ino;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		COMBINE_STACK_UNWIND (rename, frame, 
				local->op_ret, local->op_errno, 
				&local->stbuf, &local->preoldparent,
				&local->postoldparent, &local->preparent,
				&local->postparent);
	}
	return 0;
}
int
combine_link_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno,
		inode_t *inode, struct stat *stbuf, struct stat *preparent,
		struct stat *postparent)
{
	call_frame_t *prev = NULL;
	combine_local_t  *local = NULL;
	int           this_call_cnt;

	local = frame->local;

	prev = cookie;
	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}
		local->op_ret = 0;

		stbuf->st_ino = local->loc.inode->ino;
		preparent->st_ino = local->loc2.parent->ino;
		postparent->st_ino = local->loc2.parent->ino;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		COMBINE_STACK_UNWIND (link, frame, op_ret, op_errno,
				inode, stbuf, preparent, postparent);
	}
	return 0;
}

int
combine_readdirp_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int op_ret,
		int op_errno, gf_dirent_t *orig_entries)
{
	combine_local_t *local = NULL;
	gf_dirent_t *orig_entry = NULL;
	gf_dirent_t  *entry = NULL, *fentry = NULL;
	gf_dirent_t  *tmp = NULL;
	gf_dirent_t  *found = NULL;
	call_frame_t *prev = NULL;
	int           this_call_cnt,i,n1,n2,nmin,count = 0;
	combine_conf_t *conf = this->private;
	gf_dirent_t	entries,sortentries;
	off_t	     xoff,yoff;

	prev = cookie;
	local = frame->local;
	INIT_LIST_HEAD(&entries.list);
	INIT_LIST_HEAD(&sortentries.list);

	if (op_ret < 0)
		goto done;

	LOCK (&frame->lock);
	list_for_each_entry_safe (orig_entry, tmp,(&orig_entries->list), list) {
		entry = gf_dirent_for_name (orig_entry->d_name);
		if (!entry) {
			gf_log (this->name, GF_LOG_ERROR,
					"Out of memory");
			UNLOCK (&frame->lock);
			goto done;
		}

		entry->d_stat = orig_entry->d_stat;

		combine_itransform (this, prev->this, orig_entry->d_ino,
				&entry->d_ino);
		/* d_off is offset for next read */
		combine_encode_off (this, prev->this, orig_entry->d_off,
				&entry->d_off);

		entry->d_stat.st_ino = entry->d_ino;
		entry->d_type = orig_entry->d_type;
		entry->d_len  = orig_entry->d_len;

	 	/* compare entry with entries, find an exchange if need, if no insert ,free(entry); */
		found = NULL;
		list_for_each_entry(fentry, (&local->entries_list.list), list) {
			if ( entry->d_len == fentry->d_len ) {
				if ( strncmp( entry->d_name, fentry->d_name, entry->d_len) == 0 ) {
					found = fentry;
					break;
				}
			}
		}
		if ( found == NULL ) {
			list_add_tail (&entry->list, &local->entries_list.list);
			count ++;
		} else {
			combine_decode_off (this, entry->d_off, &n1, (uint64_t *)&xoff);
			combine_decode_off (this, fentry->d_off, &n2, (uint64_t *)&yoff);
			if ( n2 < n1 ) {
				list_del_init(&fentry->list);
				list_add_tail (&entry->list, &local->entries_list.list);
				FREE(fentry);
			} else {
				FREE(entry);
			}
		}
	}
	UNLOCK (&frame->lock);

done:
	this_call_cnt = combine_frame_return (frame);
	if ( is_last_call(this_call_cnt) ) {
		//unwind , use offset and size to get entries
		count = 0;
		combine_decode_off (this, local->offset, &n1, (uint64_t *)&xoff);
		nmin = conf->subvolume_cnt;
		
		LOCK (&frame->lock);
		/* sor sequence */
		for ( i = n1; i< nmin; i++){
			list_for_each_entry_safe(entry, tmp,(&local->entries_list.list), list) {
				combine_decode_off (this, entry->d_off, &n2, (uint64_t *)&yoff);
				if ( n2 == i ) {
					list_del_init(&entry->list);
					list_add_tail (&entry->list, &sortentries.list);
				}
			}

		}
		list_for_each_entry_safe(entry, tmp,(&sortentries.list), list) {
			if ( count > local->size/128 ) break;
			combine_decode_off (this, entry->d_off, &n2, (uint64_t *)&yoff);
			/* if same vol,select big off */
			if ( n2== n1 ) {
				if ( (xoff == 0) ||(yoff > xoff) ) {
					list_del_init(&entry->list);
					list_add_tail (&entry->list, &entries.list);
					count ++;
				}
			} else if ( n2 > n1 ) {
				list_del_init(&entry->list);
				list_add_tail (&entry->list, &entries.list);
				count ++;
			}
		}

		UNLOCK (&frame->lock);
		op_ret = count;

		COMBINE_STACK_UNWIND (readdir, frame, op_ret, op_errno, &entries);

		gf_dirent_free (&local->entries_list);
		gf_dirent_free (&entries);
	} 
	return 0;
}

int
combine_readdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int op_ret,
		int op_errno, gf_dirent_t *orig_entries)
{
	combine_local_t *local = NULL;
	gf_dirent_t entries,sortentries;
	gf_dirent_t *orig_entry = NULL;
	gf_dirent_t  *entry = NULL, *fentry = NULL, *tmp = NULL;
	gf_dirent_t  *found = NULL;
	call_frame_t *prev = NULL;
	off_t	     xoff,yoff;
	int           this_call_cnt,i,nmin,n1,n2,count = 0;
	combine_conf_t *conf = this->private;

	INIT_LIST_HEAD (&entries.list);
	INIT_LIST_HEAD (&sortentries.list);
	prev = cookie;
	local = frame->local;

	if (op_ret < 0)
		goto done;

	LOCK (&frame->lock);
	list_for_each_entry_safe (orig_entry, tmp,(&orig_entries->list), list) {
		entry = gf_dirent_for_name (orig_entry->d_name);
		if (!entry) {
			gf_log (this->name, GF_LOG_ERROR,
					"Out of memory");
			UNLOCK (&frame->lock);
			goto done;
		}
		combine_itransform (this, prev->this, orig_entry->d_ino,
				&entry->d_ino);
		combine_encode_off (this, prev->this, orig_entry->d_off,
				&entry->d_off);

		entry->d_type = orig_entry->d_type;
		entry->d_len  = orig_entry->d_len;

	 	/* compare entry with entries, find an exchange if need, if no insert ,free(entry); */
		found = NULL;
		list_for_each_entry(fentry, (&local->entries_list.list), list) {
			if ( entry->d_len == fentry->d_len ) {
				if ( strncmp( entry->d_name, fentry->d_name, entry->d_len) == 0 ) {
					found = fentry;
					break;
				}
			}
		}
		if ( found == NULL ) {
			list_add_tail (&entry->list, &local->entries_list.list);
			count ++;
		} else {
			combine_decode_off (this, entry->d_off, &n1, (uint64_t *)&xoff);
			combine_decode_off (this, fentry->d_off, &n2, (uint64_t *)&yoff);
			if ( n2 < n1 ) {
				list_del_init(&fentry->list);
				list_add_tail (&entry->list, &local->entries_list.list);
				FREE(fentry);
			} else {
				FREE(entry);
			}
		}
	}
	UNLOCK (&frame->lock);
done:
	this_call_cnt = combine_frame_return (frame);
	if ( is_last_call(this_call_cnt) ) {
		//unwind , use offset and size to get entries
		count = 0;
		combine_decode_off (this, local->offset, &n1, (uint64_t *)&xoff);
		nmin = conf->subvolume_cnt;
		
		LOCK (&frame->lock);
		/* get large off into result, n2 must be sequence */
		for ( i = n1; i<= nmin; i++){
			list_for_each_entry_safe(entry, tmp,(&local->entries_list.list), list) {
				combine_decode_off (this, entry->d_off, &n2, (uint64_t *)&yoff);
				if ( n2 == i ) {
					list_del_init(&entry->list);
					list_add_tail (&entry->list, &sortentries.list);
				}
			}

		}
		list_for_each_entry_safe(entry, tmp,(&sortentries.list), list) {
			if ( count > local->size/128 ) break;
			combine_decode_off (this, entry->d_off, &n2, (uint64_t *)&yoff);
			/* if same vol,select big off */
			if ( n2== n1 ) {
				if ( (xoff == 0) ||(yoff > xoff) ) {
					list_del_init(&entry->list);
					list_add_tail (&entry->list, &entries.list);
					count ++;
				}
			} else if ( n2 > n1 ) {
				list_del_init(&entry->list);
				list_add_tail (&entry->list, &entries.list);
				count ++;
			}
		}

		UNLOCK (&frame->lock);
		op_ret = count;

		COMBINE_STACK_UNWIND (readdir, frame, op_ret, op_errno, &entries);

		gf_dirent_free (&local->entries_list);
		gf_dirent_free (&entries);
	} 
	return 0;
}

int
combine_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno,
		struct iovec *vector, int count, struct stat *stbuf,
		struct iobref *iobref)
{
	COMBINE_STACK_UNWIND (readv, frame, op_ret, op_errno, vector, count, stbuf,
			iobref);

	return 0;
}

int
combine_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno, struct stat *prebuf,
		struct stat *postbuf)
{
	combine_local_t *local = NULL;

	if (op_ret == -1) {
		goto out;
	}

	local = frame->local;
	if (!local) {
		op_ret = -1;
		op_errno = EINVAL;
		goto out;
	} 

	prebuf->st_ino = local->st_ino;
	postbuf->st_ino = local->st_ino;
out:
	COMBINE_STACK_UNWIND (writev, frame, op_ret, op_errno, prebuf, postbuf);
	return 0;
}

int
combine_flush_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		 int op_ret, int op_errno)
{
	combine_local_t  *local = NULL;
	int this_call_cnt = 0;
	call_frame_t *prev = NULL;


	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
				"subvolume %s returned -1 (%s)",
				prev->this->name, strerror (op_errno));
			goto unlock;
		}

		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		COMBINE_STACK_UNWIND (flush, frame, local->op_ret, local->op_errno);
	}
	return 0;
}
int
combine_fsync_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int op_ret,
		int op_errno, struct stat *prebuf, struct stat *postbuf)
{
	combine_local_t  *local = NULL;
	int           this_call_cnt = 0;
	call_frame_t *prev = NULL;


	local = frame->local;
	prev = cookie;

	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
					"subvolume %s returned -1 (%s)",
					prev->this->name, strerror (op_errno));
			goto unlock;
		}

		local->op_ret = 0;
	}
unlock:
	UNLOCK (&frame->lock);

	if (local && (op_ret == 0)) {
		prebuf->st_ino = local->st_ino;
		postbuf->st_ino = local->st_ino;
	}

	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt))
		COMBINE_STACK_UNWIND (fsync, frame, local->op_ret, local->op_errno,
			prebuf, postbuf);
	return 0;
}
int
combine_setattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int op_ret, int op_errno, struct stat *statpre,
                 struct stat *statpost)
{
	call_frame_t *prev = NULL;
	combine_local_t  *local = NULL;
	int this_call_cnt;

	if (op_ret == -1)
		goto out;

	local = frame->local;
	prev = cookie;
	LOCK (&frame->lock);
	{
		if (op_ret == -1) {
			local->op_errno = op_errno;
			gf_log (this->name, GF_LOG_DEBUG,
					"subvolume %s returned -1 (%s)",
					prev->this->name, strerror (op_errno));
			goto unlock;
		}
		local->op_ret = 0;
		combine_stat_merge (this, &local->prebuf, statpost, prev->this);
		combine_stat_merge (this, &local->stbuf, statpost, prev->this);
		if (local->inode) {
			local->prebuf.st_ino = local->inode->ino;
			local->stbuf.st_ino = local->inode->ino;
		}
	}
unlock:
	UNLOCK (&frame->lock);

out:
	this_call_cnt = combine_frame_return (frame);
	if (is_last_call (this_call_cnt)) {
		COMBINE_STACK_UNWIND (setattr, frame, local->op_ret, local->op_errno,
				&local->prebuf, &local->stbuf);
	}
	return 0;
}

int
combine_stat (call_frame_t *frame, xlator_t *this,
		loc_t *loc)
{
	xlator_t     *subvol = NULL;
	combine_conf_t *conf = NULL;
	combine_local_t  *local = NULL;
	int           op_errno = -1, i = 0;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);
	VALIDATE_OR_GOTO (loc->inode, err);
	VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;
	local = combine_local_init (frame);
	if (local == NULL){
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = ENOMEM;
		goto err;
	}
	local->inode = inode_ref (loc->inode);

	subvol = get_subvol_from_inode_ctx(this, loc);
	if (subvol == NULL) {
		local->call_cnt = conf->subvolume_cnt;
		for (i = 0; i < conf->subvolume_cnt; i++){
			STACK_WIND (frame, combine_attr_cbk,
					conf->subvolumes[i],
					conf->subvolumes[i]->fops->stat,
					loc);
		}
	} else {
		local->call_cnt = 1;
		STACK_WIND (frame, combine_attr_cbk,
				subvol,
				subvol->fops->stat, loc);
	}
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (stat, frame, -1, op_errno, NULL);
	return 0;
}

int
combine_fstat (call_frame_t *frame, xlator_t *this,
		fd_t *fd)
{
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
	xlator_t     *subvol = NULL;
	int           op_errno = -1, i;


	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (fd, err);

	conf = this->private;
	local = combine_local_init (frame);

	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = -1;
		goto err;
	}
	local->fd = fd_ref (fd);
	local->inode = inode_ref (fd->inode);

	subvol = get_subvol_from_fd_ctx(this, NULL, fd);
	if (subvol == NULL) {
		local->call_cnt = conf->subvolume_cnt;
		for (i = 0; i < conf->subvolume_cnt; i++){
			STACK_WIND (frame, combine_attr_cbk,
					conf->subvolumes[i],
					conf->subvolumes[i]->fops->fstat,
					fd);
		}
	} else {
		local->call_cnt = 1;
		STACK_WIND (frame, combine_attr_cbk,
				subvol,
				subvol->fops->fstat, fd);
	}
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (fstat, frame, -1, EROFS, NULL);
	return 0;
}

int
combine_truncate (call_frame_t *frame, xlator_t *this,
		loc_t *loc, off_t offset)
{
	xlator_t *subvol = NULL;
	combine_local_t *local = NULL;
	combine_conf_t *conf = NULL;
	int op_errno = -1;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);
	VALIDATE_OR_GOTO (loc->parent, err);
	VALIDATE_OR_GOTO (loc->inode, err);
	VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;
	local = combine_local_init (frame);
	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	subvol = get_subvol_from_inode_ctx(this, loc);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for loc failed for path %s",
			loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local->inode = inode_ref (loc->inode);
	local->call_cnt = 1;
	STACK_WIND (frame, combine_truncate_cbk,
			subvol,
			subvol->fops->truncate,
			loc, offset);
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (truncate, frame, -1, op_errno, NULL, NULL);
	return 0;
}

int
combine_ftruncate (call_frame_t *frame, xlator_t *this,
		fd_t *fd, off_t offset)
{

	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
	xlator_t     *subvol = NULL;
	int           op_errno = -1;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (fd, err);

	conf = this->private;
	local = combine_local_init (frame);

       	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = -1;
		goto err;
	}
	local->fd = fd_ref (fd);
	local->inode = inode_ref (fd->inode);

	gf_log (this->name, GF_LOG_TRACE, "ftruncate for inode %p[%"PRId64"]fd %p offset %ld",
			fd->inode, fd->inode->ino, fd, offset);

	subvol = get_subvol_from_fd_ctx(this, NULL, fd);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for loc failed for inode %"PRId64"",
			fd->inode->ino);
		op_errno = EINVAL;
		goto err;
	}

	local->call_cnt = 1;
	STACK_WIND (frame, combine_truncate_cbk,
		subvol, subvol->fops->ftruncate,
		fd, offset);
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (ftruncate, frame, -1, op_errno, NULL, NULL);
	return 0;
}

int
combine_access (call_frame_t *frame, xlator_t *this,
		loc_t *loc, int32_t mask)
{
	xlator_t *subvol = NULL;
	combine_local_t *local = NULL;
	combine_conf_t *conf = NULL;
	int i,op_errno = -1;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);
	VALIDATE_OR_GOTO (loc->inode, err);
	VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;
	local = combine_local_init (frame);
	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = ENOMEM;
		goto err;
	}
	/* 
	 * for root, do access on first child.
	 * for others, do access on it's position child.
	 */
	subvol = get_subvol_from_inode_ctx(this, loc);
	if ( subvol == NULL ) {
		local->call_cnt = conf->subvolume_cnt;
		for ( i=0;i<conf->subvolume_cnt;i++){
			STACK_WIND (frame, combine_access_cbk,
				conf->subvolumes[i],
				conf->subvolumes[i]->fops->access,
				loc, mask);
			
		}
	} else {
		local->call_cnt = 1;
		STACK_WIND (frame, combine_access_cbk,
			subvol,
			subvol->fops->access,
			loc, mask);
	}
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (access, frame, -1, op_errno);
	return 0;
}

int
combine_readlink (call_frame_t *frame, xlator_t *this,
		loc_t *loc, size_t size)
{
	xlator_t *subvol = NULL;
	combine_local_t *local = NULL;
	combine_conf_t *conf = NULL;
	int op_errno = -1;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);
	VALIDATE_OR_GOTO (loc->inode, err);
	VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;
	local = combine_local_init (frame);
	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	subvol = get_subvol_from_inode_ctx(this, loc);
	if ( subvol == NULL ) {
		gf_log (this->name, GF_LOG_ERROR, "readlink for path %s",
		loc->path);
		op_errno = EINVAL;
		goto err;
	} else {
		local->call_cnt = 1;
		STACK_WIND (frame, combine_readlink_cbk,
			subvol,
			subvol->fops->readlink,
			loc, size);
	}

	gf_log (this->name, GF_LOG_TRACE, "readlink for path %s",
			loc->path);

	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (readlink, frame, -1, op_errno, NULL, NULL);
	return 0;
}

int
combine_mknod (call_frame_t *frame, xlator_t *this,
		loc_t *loc, mode_t mode, dev_t rdev)
{
	COMBINE_STACK_UNWIND (mknod, frame, -1, EPERM,
			NULL, NULL, NULL, NULL);
	return 0;
}

int
combine_mkdir (call_frame_t *frame, xlator_t *this,
		loc_t *loc, mode_t mode)
{
	xlator_t *subvol = NULL;
	combine_local_t *local = NULL;
	combine_conf_t *conf = NULL;
	int op_errno = -1;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);
	VALIDATE_OR_GOTO (loc->parent, err)
	VALIDATE_OR_GOTO (loc->inode, err);
	VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;

	if (loc->parent->ino == 1) {
		gf_log (this->name, GF_LOG_ERROR, "Denied operation in root.");
		op_errno = EPERM;
		goto err;
	}
	if (conf->read_only) {
		gf_log (this->name, GF_LOG_WARNING, "read only has be set.");
		op_errno = EROFS;
		goto err;
	}
	conf = this->private;
	local = combine_local_init (frame);
	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = ENOMEM;
		goto err;
	}
	subvol = get_subvol_from_inode_ctx(this, loc);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for loc failed for path %s",
			loc->path);
		op_errno = EINVAL;
		goto err;
	}
	local->inode = inode_ref (loc->inode);
	if (loc_copy(&local->loc, loc)) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	local->call_cnt = 1;
	STACK_WIND (frame, combine_mkdir_cbk,
			subvol,
			subvol->fops->mkdir,
			loc, mode);
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (mkdir, frame, -1, op_errno, NULL, NULL, NULL, NULL);
	return 0;
}

int
combine_unlink (call_frame_t *frame, xlator_t *this,
		loc_t *loc)
{
	xlator_t *subvol = NULL;
	combine_local_t *local = NULL;
	combine_conf_t *conf = NULL;
	int i,op_errno = -1;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);
	VALIDATE_OR_GOTO (loc->inode, err);
	VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;
	local = combine_local_init (frame);
	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = ENOMEM;
		goto err;
	}
	gf_log (this->name, GF_LOG_TRACE, "Unlink file %s, ino %"PRId64"",
			loc->path, loc->inode->ino);

	if (loc_copy(&local->loc, loc)) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
				"Out of memory");
		goto err;
	}
	subvol = get_subvol_from_inode_ctx(this, loc);
	if (subvol == NULL) {
		local->call_cnt = conf->subvolume_cnt;
		for (i = 0; i < conf->subvolume_cnt; i++){
			STACK_WIND (frame, combine_unlink_cbk,
				conf->subvolumes[i],
				conf->subvolumes[i]->fops->unlink,
				loc);
		}
	} else {
		local->call_cnt = 1;

		STACK_WIND (frame, combine_unlink_cbk,
			subvol,
			subvol->fops->unlink,
			loc);
	}
	return 0;
err:
	op_errno = (op_errno == -1)?errno:op_errno;
	COMBINE_STACK_UNWIND (unlink, frame, -1, op_errno, NULL, NULL);
	return 0;
}

int
combine_rmdir (call_frame_t *frame, xlator_t *this,
		loc_t *loc)
{
	/* TODO:
	 * remove directory using this way poor efficency.
	 * provide a new way to deleting directory by ioctl
	 */
	xlator_t *subvol = NULL;
	combine_local_t *local = NULL;
	combine_conf_t *conf = NULL;
	int i,op_errno = -1;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (loc, err);
	VALIDATE_OR_GOTO (loc->path, err);
	VALIDATE_OR_GOTO (loc->parent, err);
	VALIDATE_OR_GOTO (loc->inode, err);

	conf = this->private;
	local = combine_local_init (frame);
	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	if (loc_copy(&local->loc, loc)) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
				"Out of memory");
		goto err;
	}

	subvol = get_subvol_from_inode_ctx(this, loc);
	if (subvol == NULL) {
		local->call_cnt = conf->subvolume_cnt;
		for (i = 0; i < conf->subvolume_cnt; i++){
			STACK_WIND (frame, combine_rmdir_cbk,
				conf->subvolumes[i],
				conf->subvolumes[i]->fops->rmdir,
				loc);
		}
	} else {
		local->call_cnt = 1;
		STACK_WIND (frame, combine_rmdir_cbk,
			subvol,
			subvol->fops->rmdir,
			loc);
	}
	return 0;
err:
	op_errno = (op_errno == -1)?errno:op_errno;
	COMBINE_STACK_UNWIND (rmdir, frame, -1, op_errno, NULL, NULL);
	return 0;
}

int
combine_symlink (call_frame_t *frame, xlator_t *this,
		const char *linkname, loc_t *loc)
{
	xlator_t *subvol1 = NULL;
	combine_local_t *local = NULL;
	combine_conf_t *conf = NULL;
	int op_errno = -1, ret = 0;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (linkname, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->parent, err);
        VALIDATE_OR_GOTO (loc->inode, err);

	conf = this->private;

	local = combine_local_init (frame);
	if (local == NULL) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}
	if (loc->parent->ino == 1) {
		gf_log (this->name, GF_LOG_ERROR, "Operation denied in root");
		op_errno = EPERM;
		goto err;
	}
	if (conf->read_only) {
		gf_log (this->name, GF_LOG_ERROR, "Read only has be set");
		op_errno = EROFS;
		goto err;
	}
	ret = loc_dup (loc, &local->loc);
	if (ret == -1) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}
	subvol1 = get_subvol_from_inode_ctx (this, loc);
	if (subvol1 == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for loc failed for file %s",
			loc->path);
		op_errno = EINVAL;
		goto err;
	}
	local->call_cnt = 1;
	STACK_WIND (frame, combine_symlink_cbk,
			subvol1, subvol1->fops->symlink,
			linkname, loc);
	return 0;
err:
	op_errno = (op_errno == -1)?errno:op_errno;
	COMBINE_STACK_UNWIND (symlink, frame, -1, op_errno, NULL, NULL, NULL, NULL);
	return 0;
}

int
combine_rename (call_frame_t *frame, xlator_t *this,
		loc_t *oldloc, loc_t *newloc)
{

	xlator_t *subvol1 = NULL, *subvol2 = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
        int           op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (oldloc, err);
        VALIDATE_OR_GOTO (oldloc->path, err);
        VALIDATE_OR_GOTO (oldloc->inode, err);
        VALIDATE_OR_GOTO (newloc, err);
        VALIDATE_OR_GOTO (newloc->path, err);
        VALIDATE_OR_GOTO (newloc->parent, err);
        //VALIDATE_OR_GOTO (newloc->inode, err);

	conf = this->private;
	local = combine_local_init (frame);
	if (local == NULL) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	if (newloc->parent->ino == 1) {
		gf_log (this->name, GF_LOG_ERROR, "Operation denied in root");
		op_errno = EPERM;
		goto err;
	}

	if (conf->read_only) {
		gf_log (this->name, GF_LOG_ERROR, "Read only has be set");
		op_errno = EROFS;
		goto err;
	}

	subvol1 = get_subvol_from_inode_ctx (this, oldloc);
	if (subvol1 == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position failed for file %s",
			oldloc->path);
		op_errno = EINVAL;
		goto err;
	}
	subvol2 = get_subvol_from_inode_ctx (this, newloc);
	if (subvol2 == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position failed for file %s",
			newloc->path);
		op_errno = EINVAL;
		goto err;
	}
	if (subvol1 != subvol2) {
		gf_log (this->name, GF_LOG_ERROR,
			"can not rename file from %s to %s",
			oldloc->path, newloc->path);
		op_errno = EPERM;
		goto err;
	}
	gf_log (this->name, GF_LOG_TRACE, "rename from path %s to path %s",
		oldloc->path, newloc->path);

	if (loc_copy(&local->loc, oldloc)) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
				"Out of memory");
		goto err;
	}

	if (loc_copy(&local->loc2, newloc)) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
				"Out of memory");
		goto err;
	}

	local->call_cnt = 1;
	STACK_WIND (frame, combine_rename_cbk,
			subvol1, subvol1->fops->rename,
			oldloc, newloc);
	return 0;
err:
	op_errno = (op_errno == -1)?errno:op_errno;
	COMBINE_STACK_UNWIND (rename, frame, -1, op_errno, 
			NULL, NULL, NULL, NULL, NULL);
	return 0;
}

int
combine_link (call_frame_t *frame, xlator_t *this,
	       loc_t *oldloc, loc_t *newloc)
{
	xlator_t *subvol1 = NULL, *subvol2 = NULL;
	combine_local_t *local = NULL;
	combine_conf_t *conf = NULL;
	int op_errno = -1, ret = 0;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (oldloc->path, err);
        VALIDATE_OR_GOTO (oldloc->parent, err);
        VALIDATE_OR_GOTO (oldloc->inode, err);
        VALIDATE_OR_GOTO (newloc->path, err);
        VALIDATE_OR_GOTO (newloc->parent, err);

	conf = this->private;

	local = combine_local_init (frame);
	if (local == NULL) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}
	if (newloc->parent->ino == 1) {
		gf_log (this->name, GF_LOG_ERROR, "Operation denied in root");
		op_errno = EPERM;
		goto err;
	}
	if (conf->read_only) {
		gf_log (this->name, GF_LOG_ERROR, "Read only has be set");
		op_errno = EROFS;
		goto err;
	}

	subvol1 = get_subvol_from_inode_ctx (this, oldloc);
	if (subvol1 == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for path %s",
			oldloc->path);
		op_errno = EINVAL;
		goto err;
	}
	subvol2 = get_subvol_from_inode_ctx (this, newloc);
	if (subvol2 == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position failed for file %s",
			newloc->path);
		op_errno = EINVAL;
		goto err;
	}
	if (subvol1 != subvol2) {
		gf_log (this->name, GF_LOG_ERROR,
			"can not link file from %s to %s",
			subvol1->name, subvol2->name);
		op_errno = EPERM;
		goto err;
	}
	ret = loc_copy (&local->loc, oldloc);
	if (ret == -1) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
				"Out of memory");
		goto err;
	}

	ret = loc_copy (&local->loc2, newloc);
	if (ret == -1) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
				"Out of memory");
		goto err;
	}

	gf_log (this->name, GF_LOG_TRACE, "link from path %s to path %s",
		oldloc->path, newloc->path);

	local->call_cnt = 1;
	STACK_WIND (frame, combine_link_cbk,
			subvol1, subvol1->fops->link,
			oldloc, newloc);
	return 0;
err:
	op_errno = (op_errno == -1)?errno:op_errno;
	COMBINE_STACK_UNWIND (link, frame, -1, op_errno, NULL, NULL, NULL, NULL);
	return 0;
}

int
combine_create (call_frame_t *frame, xlator_t *this,
		loc_t *loc, int32_t flags, mode_t mode, fd_t *fd)
{
	xlator_t *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
	int           ret = -1;
        int           op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->parent, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (fd, err);
	conf = this->private;

	local = combine_local_init (frame);
	if (local == NULL) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}
	if (loc->parent->ino == 1) {
		gf_log (this->name, GF_LOG_ERROR, "Operation denied in root");
		op_errno = EPERM;
		goto err;
	}
	if (conf->read_only) {
		gf_log (this->name, GF_LOG_ERROR, "Read only has be set");
		op_errno = EROFS;
		goto err;
	}

	local->fd = fd_ref (fd);
	ret = loc_dup (loc, &local->loc);
	if (ret == -1) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	gf_log (this->name, GF_LOG_TRACE, "create path %s, fd %p, flags %d, mode %d",
		loc->path, fd, flags, mode);

	subvol = get_subvol_from_inode_ctx(this, loc);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for loc failed for path %s",
			loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local->call_cnt = 1;
	STACK_WIND (frame, combine_create_cbk,
		subvol,
		subvol->fops->create,
		loc, flags, mode, fd);
	return 0;
err:
	op_errno = (op_errno == -1)?errno:op_errno;
	COMBINE_STACK_UNWIND (create, frame, -1, op_errno, NULL, NULL, NULL, NULL, NULL);
	return 0;
}

int
combine_open (call_frame_t *frame, xlator_t *this,
		loc_t *loc, int32_t flags, fd_t *fd, int32_t wbflags)
{
	xlator_t *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
	int           ret = -1;
        int           op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->parent, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (fd, err);
	conf = this->private;

	local = combine_local_init (frame);
	if (local == NULL) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}
	if (conf->read_only) {
		if ((flags & O_WRONLY) || (flags & O_WRONLY)) {
			gf_log (this->name, GF_LOG_WARNING, "read only file system");
			op_errno = EROFS;
			goto err;
		}
	}
	local->fd = fd_ref (fd);
	ret = loc_dup (loc, &local->loc);
	if (ret == -1) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	gf_log (this->name, GF_LOG_TRACE, "open for path %s,inode %"PRId64", fd %p, flags %d, wbflags %d",
		loc->path, fd->inode->ino, fd, flags, wbflags);

	subvol = get_subvol_from_fd_ctx(this, loc, fd);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for loc failed for path %s",
			loc->path);
		op_errno = EINVAL;
		goto err;
	} else {
		local->call_cnt = 1;
		STACK_WIND (frame, combine_fd_cbk,
			subvol,
			subvol->fops->open,
			loc, flags, fd, wbflags);
	}
	return 0;
err:
	op_errno = (op_errno == -1)?errno:op_errno;
	COMBINE_STACK_UNWIND (open, frame, -1, op_errno, NULL);
	return 0;
}

int
combine_readv (call_frame_t *frame,	xlator_t *this,
		fd_t *fd, size_t size, off_t offset)
{
	xlator_t     *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
	int           op_errno = -1;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (fd, err);

	conf = this->private;
	local = combine_local_init (frame);

       	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = -1;
		goto err;
	}
	local->size = size;

	subvol = get_subvol_from_fd_ctx(this, NULL, fd);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for loc failed for inode %"PRId64"",
			fd->inode->ino);
		op_errno = EINVAL;
		goto err;
	}
	gf_log (this->name, GF_LOG_TRACE, "read for inode %p[%"PRId64"]fd %p size %ld offset %ld",
			fd->inode, fd->inode->ino, fd, size, offset);

	STACK_WIND (frame, combine_readv_cbk,
		subvol, subvol->fops->readv,
		fd, size, offset);
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (readdir, frame, -1, op_errno, NULL);
	return 0;
}

int
combine_writev (call_frame_t *frame, xlator_t *this,
		fd_t *fd, struct iovec *vector,	int32_t count,
		off_t offset, struct iobref *iobref)
{
	xlator_t     *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
	int           op_errno = -1;


	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (fd, err);

	conf = this->private;
	local = combine_local_init (frame);

       	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = -1;
		goto err;
	}
	local->st_ino = fd->inode->ino;

	if (conf->read_only) {
		gf_log (this->name, GF_LOG_ERROR, "Read only has be set");
		op_errno = EROFS;
		goto err;
	}

	subvol = get_subvol_from_fd_ctx(this, NULL, fd);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for loc failed for inode %"PRId64"",
			fd->inode->ino);
		op_errno = EINVAL;
		goto err;
	}
	gf_log (this->name, GF_LOG_TRACE, "write to inode %p[%"PRId64"]fd %p offset %ld",
		fd->inode, fd->inode->ino, fd, offset);

	local->call_cnt = 1;

	STACK_WIND (frame, combine_writev_cbk,
		subvol, subvol->fops->writev,
		fd, vector, count, offset, iobref);

	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (writev, frame, -1, op_errno, NULL, NULL);
	return 0;
}

int
combine_flush (call_frame_t *frame, xlator_t *this,
		fd_t *fd)
{
	xlator_t     *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
	int           op_errno = -1;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (fd, err);

	conf = this->private;
	local = combine_local_init (frame);

       	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = -1;
		goto err;
	}

	subvol = get_subvol_from_fd_ctx(this, NULL, fd);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for loc failed for inode %"PRId64"",
			fd->inode->ino);
		op_errno = EINVAL;
		goto err;
	}
	gf_log (this->name, GF_LOG_TRACE, "flush for inode %p[%"PRId64"]fd %p",
			fd->inode, fd->inode->ino, fd);

	local->fd = fd_ref (fd);
	local->call_cnt = 1;
	STACK_WIND (frame, combine_flush_cbk,
		subvol, subvol->fops->flush, fd);
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (flush, frame, -1, op_errno);
	return 0;
}

int 
combine_fsync (call_frame_t *frame, xlator_t *this,
		fd_t *fd, int32_t datasync)
{
	xlator_t     *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
	int           op_errno = -1;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (fd, err);

	conf = this->private;
	local = combine_local_init (frame);

       	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = -1;
		goto err;
	}
	subvol = get_subvol_from_fd_ctx(this, NULL, fd);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position for loc failed for inode %"PRId64"",
			fd->inode->ino);
		op_errno = EINVAL;
		goto err;
	}
	gf_log (this->name, GF_LOG_TRACE, "fsync for inode %p[%"PRId64"]fd %p",
			fd->inode, fd->inode->ino, fd);

	local->call_cnt = 1;
	local->st_ino = fd->inode->ino;

	STACK_WIND (frame, combine_fsync_cbk,
		subvol, subvol->fops->fsync, fd, datasync);
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (fsync, frame, -1, op_errno, NULL, NULL);
	return 0;
}

int
combine_opendir (call_frame_t *frame, xlator_t *this,
		loc_t *loc, fd_t *fd)
{
	xlator_t *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
	int           ret = -1;
        int           op_errno = -1, i = 0;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (fd, err);
	conf = this->private;

	local = combine_local_init (frame);
	if (local == NULL) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->fd = fd_ref (fd);
	ret = loc_dup (loc, &local->loc);
	if (ret == -1) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		op_errno = ENOMEM;
		goto err;
	}

	gf_log (this->name, GF_LOG_TRACE, "opendir for path %s,inode %"PRId64", fd %p",
			loc->path, fd->inode->ino, fd);
	/*
	 * for root, opendir on every subvol.
	 * for non-root, if we can get ictx from parent or
	 * from inode, then using ctx to determine which
	 * subvol to go on, else we compute which subvol
	 * to go, and set inode ctx, fd ctx.
	 */
	subvol = get_subvol_from_fd_ctx(this, loc, fd);
	if (subvol == NULL) {
		local->call_cnt = conf->subvolume_cnt;
		for (i = 0; i < conf->subvolume_cnt; i++) {
			STACK_WIND (frame, combine_opendir_cbk,
			    conf->subvolumes[i],
			    conf->subvolumes[i]->fops->opendir,
			    loc, fd);
		}
	} else {
gf_log (this->name, GF_LOG_TRACE, "Why here ?opendir for path %s,inode %"PRId64", fd %p",
			loc->path, fd->inode->ino, fd);
		local->call_cnt = 1;
	        STACK_WIND (frame, combine_opendir_cbk,
                      		subvol,
		    		subvol->fops->opendir,
                      		loc, fd);
	}
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (opendir, frame, -1, op_errno, NULL);
	return 0;
}

int
combine_fsyncdir (call_frame_t *frame, xlator_t *this,
		fd_t *fd, int32_t datasync)
{
	xlator_t *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
        int           op_errno = -1, i = 0;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
	conf = this->private;

	local = combine_local_init (frame);
	if (local == NULL) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}

	local->fd = fd_ref (fd);

	gf_log (this->name, GF_LOG_TRACE, "fsyncdir for inode %"PRId64", fd %p",
			fd->inode->ino, fd);
	if (fd->inode->ino == 1) {
		local->call_cnt = conf->subvolume_cnt;

		for (i = 0; i < conf->subvolume_cnt; i++) {
			STACK_WIND (frame, combine_fsyncdir_cbk,
			    conf->subvolumes[i],
			    conf->subvolumes[i]->fops->fsyncdir,
			    fd, datasync);
		}
	} else {
		subvol = get_subvol_from_fd_ctx(this, NULL, fd);
		if (subvol == NULL) {
			gf_log (this->name, GF_LOG_ERROR,
					"get position failed for inode %"PRId64"",
					fd->inode->ino);
			op_errno = EINVAL;
			goto err;
		}

	        STACK_WIND (frame, combine_fsyncdir_cbk,
                       	subvol,
		    	subvol->fops->fsyncdir,
                      	fd, datasync);
	}
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (fsyncdir, frame, -1, op_errno);
	return 0;
}

int
combine_statfs (call_frame_t *frame, xlator_t *this,
		loc_t *loc)
{
	combine_local_t *local = NULL;
	combine_conf_t *conf = NULL;
	int op_errno = -1;
	int i = -1;

        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->inode, err);
        VALIDATE_OR_GOTO (loc->path, err);

	conf = this->private;

	local = combine_local_init (frame);
	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = -1;
		goto err;
	}
	local->call_cnt = conf->subvolume_cnt;

	gf_log (this->name, GF_LOG_TRACE, "statfs of path %s", loc->path);

	for (i = 0; i < conf->subvolume_cnt; i++) {
		STACK_WIND (frame, combine_statfs_cbk,
			conf->subvolumes[i],
			conf->subvolumes[i]->fops->statfs, loc);
	}
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (statfs, frame, -1, op_errno, NULL);
	return 0;
}

int
combine_setxattr (call_frame_t *frame, xlator_t *this,
		loc_t *loc, dict_t *dict, int32_t flags)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (setxattr, frame, -1, EROFS);
	return 0;
}

int
combine_getxattr (call_frame_t *frame, xlator_t *this,
		loc_t *loc, const char *key)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (getxattr, frame, -1, ENOSYS, NULL);
	return 0;
}

int
combine_fsetxattr (call_frame_t *frame, xlator_t *this,
                fd_t *fd, dict_t *dict, int32_t flags)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (fsetxattr, frame, -1, EROFS);
	return 0;
}

int
combine_fgetxattr (call_frame_t *frame, xlator_t *this,
                fd_t *fd, const char *name)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (fgetxattr, frame, -1, EROFS, NULL);
	return 0;
}

int
combine_removexattr (call_frame_t *frame, xlator_t *this,
		loc_t *loc, const char *name)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (removexattr, frame, -1, EROFS);
	return 0;
}

int
combine_lk (call_frame_t *frame, xlator_t *this,
		fd_t *fd, int32_t cmd, struct flock *flock)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (lk, frame, -1, EROFS, NULL);
	return 0;
}

int
combine_inodelk (call_frame_t *frame, xlator_t *this,
                const char *volume, loc_t *loc,
		int32_t cmd, struct flock *flock)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (inodelk, frame, -1, EROFS);
	return 0;
}

int
combine_finodelk (call_frame_t *frame, xlator_t *this,
		const char *volume, fd_t *fd,
		int32_t cmd, struct flock *flock)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (finodelk, frame, -1, EROFS);
	return 0;
}

int
combine_entrylk (call_frame_t *frame, xlator_t *this, 
		const char *volume, loc_t *loc, const char *basename,
		entrylk_cmd cmd, entrylk_type type)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (entrylk, frame, -1, EROFS);
	return 0;
}

int
combine_fentrylk (call_frame_t *frame, xlator_t *this, 
                const char *volume, fd_t *fd,
		const char *basename, entrylk_cmd cmd,
		entrylk_type type)

{
	/* NOSYS */
	COMBINE_STACK_UNWIND (fentrylk, frame, -1, EROFS);
	return 0;
}

int
combine_do_readdir (call_frame_t *frame, xlator_t *this,
		fd_t *fd, size_t size, off_t offset, int whichop)
{
	xlator_t     *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
	int           op_errno = -1;
	int           i,start;
	uint64_t      xoff;

	VALIDATE_OR_GOTO (frame, err);
	VALIDATE_OR_GOTO (this, err);
	VALIDATE_OR_GOTO (fd, err);

	conf = this->private;
	local = combine_local_init (frame);

       	if (local == NULL) {
		gf_log (this->name, GF_LOG_ERROR, "Out of memory");
		op_errno = -1;
		goto err;
	}
	local->fd = fd_ref (fd);
	local->size = size;
	local->offset = offset;

	gf_log (this->name, GF_LOG_TRACE, "readdir for fd %p size %ld offset %ld",
			fd, size, offset);

	subvol = get_subvol_from_fd_ctx(this, NULL, fd);
	if (subvol == NULL) {
		if ( offset != 0 ) {
			combine_decode_off (this, offset, &start, (uint64_t *)&xoff);
		} else {
			start = 0;
			xoff = 0;
		}
		/* readall dir for double name */
		if ( start >= conf->subvolume_cnt ) goto err;
		local->call_cnt = (conf->subvolume_cnt-start);
		for ( i= start; i<conf->subvolume_cnt;i++){
			subvol = conf->subvolumes[i];
			if (whichop == GF_FOP_READDIRP)
				STACK_WIND (frame, combine_readdirp_cbk,
					subvol, subvol->fops->readdirp,
					fd, size, xoff);
			else
				STACK_WIND (frame, combine_readdir_cbk,
					subvol, subvol->fops->readdir,
					fd, size, xoff);
			/* after subvol from 0 */
			xoff = 0;

		}
	} else {
		local->call_cnt = 1;
		if (whichop == GF_FOP_READDIRP)
			STACK_WIND (frame, combine_readdirp_cbk,
				subvol, subvol->fops->readdirp,
				fd, size, offset);
		else
			STACK_WIND (frame, combine_readdir_cbk,
				subvol, subvol->fops->readdir,
				fd, size, offset);
	}
	return 0;
err:
	op_errno = (op_errno == -1) ? errno : op_errno;
	COMBINE_STACK_UNWIND (readdir, frame, -1, op_errno, NULL);
	return 0;
}

int
combine_readdir (call_frame_t *frame, xlator_t *this,
		fd_t *fd, size_t size, off_t offset)
{
	combine_do_readdir (frame, this, fd, size, offset, GF_FOP_READDIR);
	return 0;
}

int
combine_readdirp (call_frame_t *frame, xlator_t *this,
		fd_t *fd, size_t size, off_t offset)
{
	combine_do_readdir (frame, this, fd, size, offset, GF_FOP_READDIRP);
	return 0;
}

int
combine_xattrop (call_frame_t *frame, xlator_t *this,
		loc_t *loc, gf_xattrop_flags_t optype,	dict_t *xattr)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (xattrop, frame, -1, EROFS, NULL);
	return 0;
}

int
combine_fxattrop (call_frame_t *frame, xlator_t *this,
		fd_t *fd, gf_xattrop_flags_t optype, dict_t *xattr)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (fxattrop, frame, -1, EROFS, NULL);
	return 0;
}

int
combine_ioctl (call_frame_t *frame, xlator_t *this, fd_t *fd,
		uint32_t cmd, uint64_t arg)
{
	/* NOSYS */
	COMBINE_STACK_UNWIND (ioctl, frame, -1, EROFS, 0, (uint64_t)NULL);
	return 0;
}

int
combine_setattr (call_frame_t *frame, xlator_t *this,
		loc_t *loc, struct stat *stbuf, int32_t valid)
{
	xlator_t *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
        int           op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (loc, err);
        VALIDATE_OR_GOTO (loc->path, err);
        VALIDATE_OR_GOTO (loc->parent, err);
        VALIDATE_OR_GOTO (loc->inode, err);
	conf = this->private;

	local = combine_local_init (frame);
	if (local == NULL) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}
	if (loc->ino == 1) {
		gf_log (this->name, GF_LOG_ERROR, "Operation denied in root");
		op_errno = EPERM;
		goto err;
	}
	if (conf->read_only) {
		gf_log (this->name, GF_LOG_ERROR, "Read only has be set");
		op_errno = EROFS;
		goto err;
	}

	local->inode = inode_ref (loc->inode);
	if (loc_dup(loc, &local->loc)) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}
	gf_log (this->name, GF_LOG_TRACE, "setattr path %s", loc->path);

	subvol = get_subvol_from_inode_ctx(this, loc);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position failed for path %s",
			loc->path);
		op_errno = EINVAL;
		goto err;
	}

	local->call_cnt = 1;
	STACK_WIND (frame, combine_setattr_cbk,
		subvol,
		subvol->fops->setattr,
		loc, stbuf, valid);
	return 0;
err:
	op_errno = (op_errno == -1)?errno:op_errno;
	COMBINE_STACK_UNWIND (setattr, frame, -1, op_errno, NULL, NULL);
	return 0;
}

int
combine_fsetattr (call_frame_t *frame, xlator_t *this,
                fd_t *fd, struct stat *stbuf, int32_t valid)
{
	xlator_t *subvol = NULL;
	combine_local_t  *local  = NULL;
	combine_conf_t   *conf = NULL;
        int           op_errno = -1;


        VALIDATE_OR_GOTO (frame, err);
        VALIDATE_OR_GOTO (this, err);
        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);
	conf = this->private;

	local = combine_local_init (frame);
	if (local == NULL) {
		op_errno = ENOMEM;
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		goto err;
	}
	if (fd->inode->ino == 1) {
		gf_log (this->name, GF_LOG_ERROR, "Operation denied in root");
		op_errno = EPERM;
		goto err;
	}
	if (conf->read_only) {
		gf_log (this->name, GF_LOG_ERROR, "Read only has be set");
		op_errno = EROFS;
		goto err;
	}

	local->inode = inode_ref (fd->inode);
	gf_log (this->name, GF_LOG_TRACE, "fsetattr path %"PRId64"", fd->inode->ino);

	subvol = get_subvol_from_fd_ctx(this, NULL, fd);
	if (subvol == NULL) {
		gf_log (this->name, GF_LOG_ERROR,
			"get position failed for fd %p",
			fd);
		op_errno = EINVAL;
		goto err;
	}

	local->call_cnt = 1;
	STACK_WIND (frame, combine_setattr_cbk,
		subvol,
		subvol->fops->fsetattr,
		fd, stbuf, valid);
	return 0;
err:
	op_errno = (op_errno == -1)?errno:op_errno;
	COMBINE_STACK_UNWIND (fsetattr, frame, -1, op_errno, NULL, NULL);
	return 0;
}

int
combine_forget (xlator_t *this, inode_t *inode)
{
#if 0
	uint64_t      tmp_layout = 0;
	combine_inode_ctx_t *ictx = NULL;

	inode_ctx_get (inode, this, &tmp_layout);
	if (!tmp_layout)
		return 0;

	ictx = (combine_inode_ctx_t *)(long)tmp_layout;
	
	free(ictx);
#endif
	return 0;
}
int
notify (xlator_t *this, int event, void *data, ...)
{
	xlator_t   *subvol = NULL;
	int         cnt    = -1;
	int         i,upclient    = -1;
	combine_conf_t *conf   = NULL;
	int         ret    = -1;


	conf = this->private;

	switch (event) {
	case GF_EVENT_CHILD_UP:
		subvol = data;

		for (i = 0; i < conf->subvolume_cnt; i++) {
			if (subvol == conf->subvolumes[i]) {
				cnt = i;
				break;
			}
		}

		if (cnt == -1) {
			gf_log (this->name, GF_LOG_DEBUG,
				"got GF_EVENT_CHILD_UP bad subvolume %s",
				subvol->name);
			break;
		}

		LOCK (&conf->subvolume_lock);
		conf->subvolume_status[cnt] += 1;
		upclient = 0;
		for (i = 0; i < conf->subvolume_cnt; i++) {
			if ( conf->subvolume_status[i] == 2 ) {
				upclient ++;
			}
		}
		UNLOCK (&conf->subvolume_lock);
		if ( upclient == conf->subvolume_cnt ) {
			gf_log (this->name, GF_LOG_DEBUG, "JJH Get all GF_EVENT_CHILD_UP  %s", subvol->name);
			ret = default_notify (this, event, data);
		}

		break;

	case GF_EVENT_CHILD_DOWN:
		subvol = data;

		for (i = 0; i < conf->subvolume_cnt; i++) {
			if (subvol == conf->subvolumes[i]) {
				cnt = i;
				break;
			}
		}

		if (cnt == -1) {
			gf_log (this->name, GF_LOG_DEBUG,
				"got GF_EVENT_CHILD_DOWN bad subvolume %s",
				subvol->name);
			break;
		}

		LOCK (&conf->subvolume_lock);
		{
			conf->subvolume_status[cnt] -= 1;
		}
		UNLOCK (&conf->subvolume_lock);
		ret = default_notify (this, event, data);

		break;
	default:
		ret = default_notify (this, event, data);
	}


	return ret;
}
void
fini (xlator_t *this)
{
        combine_conf_t *conf = NULL;

        conf = this->private;

        if (conf) {

                if (conf->subvolumes)
                        FREE (conf->subvolumes);

                if (conf->subvolume_status)
                        FREE (conf->subvolume_status);

                FREE (conf);
        }

        return;
}
#ifndef REFUSE
int
refuse_mknod (call_frame_t *frame, xlator_t *this,
		loc_t *loc, mode_t mode, dev_t rdev)
{
	COMBINE_STACK_UNWIND (mknod, frame, -1, EROFS,
			NULL, NULL, NULL, NULL);
	return 0;
}

int
refuse_create (call_frame_t *frame, xlator_t *this,
		loc_t *loc, int32_t flags, mode_t mode, fd_t *fd)
{
	COMBINE_STACK_UNWIND (create, frame, -1, EROFS,
		NULL, NULL, NULL, NULL, NULL);
	return 0;
}
int
refuse_truncate (call_frame_t *frame, xlator_t *this,
		loc_t *loc, off_t offset)
{
	COMBINE_STACK_UNWIND (truncate, frame, -1, EROFS,
		NULL, NULL);
	return 0;
}
int
refuse_ftruncate (call_frame_t *frame, xlator_t *this,
		fd_t *fd, off_t offset)
{
	COMBINE_STACK_UNWIND (ftruncate, frame, -1, EROFS,
		NULL, NULL);
	return 0;
}
int
refuse_writev (call_frame_t *frame, xlator_t *this,
		fd_t *fd, struct iovec *vector,	int32_t count,
		off_t offset, struct iobref *iobref)
{
	COMBINE_STACK_UNWIND (writev, frame, -1, EROFS,
		NULL, NULL);
	return 0;
}
int
refuse_flush (call_frame_t *frame, xlator_t *this,
		fd_t *fd)
{
	COMBINE_STACK_UNWIND (flush, frame, 0, 0);
	return 0;
}
int 
refuse_fsync (call_frame_t *frame, xlator_t *this,
		fd_t *fd, int32_t datasync)
{
	COMBINE_STACK_UNWIND (fsync, frame, -1, EROFS,
		NULL, NULL);
	return 0;
}
int
refuse_fsyncdir (call_frame_t *frame, xlator_t *this,
		fd_t *fd, int32_t datasync)
{
	COMBINE_STACK_UNWIND (fsyncdir , frame, -1, EROFS);
	return 0;
}
int
refuse_symlink (call_frame_t *frame, xlator_t *this,
		const char *linkname, loc_t *loc)
{
	COMBINE_STACK_UNWIND (symlink, frame, -1, EROFS,
		NULL, NULL, NULL, NULL);
	return 0;
}
int
refuse_link (call_frame_t *frame, xlator_t *this,
	       loc_t *oldloc, loc_t *newloc)
{
	COMBINE_STACK_UNWIND (link, frame, -1, EROFS,
		NULL, NULL, NULL, NULL);
	return 0;
}
int
refuse_mkdir (call_frame_t *frame, xlator_t *this,
		loc_t *loc, mode_t mode)
{
	COMBINE_STACK_UNWIND (mkdir, frame, -1, EROFS,
		NULL, NULL,NULL,NULL);
	return 0;
}
int
refuse_rename (call_frame_t *frame, xlator_t *this,loc_t *oldloc, loc_t *newloc)
{
	COMBINE_STACK_UNWIND (rename, frame, -1, EROFS,
		NULL, NULL, NULL, NULL, NULL);
	return 0;
}
int
refuse_setattr (call_frame_t *frame, xlator_t *this,
		loc_t *loc, struct stat *stbuf, int32_t valid)
{
	COMBINE_STACK_UNWIND (setattr, frame, -1, EROFS,
		NULL, NULL);
	return 0;
}
int
refuse_fsetattr (call_frame_t *frame, xlator_t *this,
                fd_t *fd, struct stat *stbuf, int32_t valid)
{
	COMBINE_STACK_UNWIND (fsetattr , frame, -1, EROFS,
		NULL, NULL);
	return 0;
}
#endif

int
init (xlator_t *this)
{
        combine_conf_t    *conf = NULL;
	char *temp_str = NULL;
        int            ret = -1;

	if (!this->children) {
		gf_log (this->name, GF_LOG_CRITICAL,
			"Distribute needs more than one subvolume");
		return -1;
	}
  
	if (!this->parents) {
		gf_log (this->name, GF_LOG_WARNING,
			"dangling volume. check volfile");
	}

        conf = CALLOC (1, sizeof (*conf));
        if (!conf) {
                gf_log (this->name, GF_LOG_ERROR,
                        "Out of memory");
                goto err;
        }

        ret = combine_init_subvolumes (this, conf);
        if (ret == -1) {
                goto err;
        }

	conf->read_only = 0;
	if (dict_get_str (this->options, "read-only", &temp_str) == 0) {
		gf_string2boolean (temp_str, &conf->read_only);
	}
	conf->rm_permmited = 1;
	if (dict_get_str (this->options, "rm-permmited", &temp_str) == 0) {
		gf_string2boolean (temp_str, &conf->rm_permmited);
	}
	LOCK_INIT (&conf->subvolume_lock);
        this->private = conf;

        return 0;
err:
        if (conf) {

                if (conf->subvolumes)
                        FREE (conf->subvolumes);
		if (conf->subvolume_status)
			FREE (conf->subvolume_status);
                FREE (conf);
        }
        return -1;
}
#ifndef REFUSE
struct xlator_fops fops = {
	.lookup      = combine_lookup,
	.mknod       = refuse_mknod,
	.create      = refuse_create,
	.stat        = combine_stat,
	.fstat       = combine_fstat,
	.truncate    = refuse_truncate,
	.ftruncate   = refuse_ftruncate,
	.access      = combine_access,
	.readlink    = combine_readlink,
	.setxattr    = combine_setxattr,
	.getxattr    = combine_getxattr,
	.removexattr = combine_removexattr,
	.open        = combine_open,
	.readv       = combine_readv,
	.writev      = refuse_writev,
	.flush       = refuse_flush,
	.fsync       = refuse_fsync,
	.statfs      = combine_statfs,
	.lk          = combine_lk,
	.opendir     = combine_opendir,
	.readdir     = combine_readdir,
	.readdirp    = combine_readdirp,
	.fsyncdir    = refuse_fsyncdir,
	.symlink     = refuse_symlink,
	.unlink      = combine_unlink,
	.link        = refuse_link,
	.mkdir       = refuse_mkdir,
	.rmdir       = combine_rmdir,
	.rename      = refuse_rename,
	.inodelk     = combine_inodelk,
	.finodelk    = combine_finodelk,
	.entrylk     = combine_entrylk,
	.fentrylk    = combine_fentrylk,
	.xattrop     = combine_xattrop,
	.fxattrop    = combine_fxattrop,
        .setattr     = refuse_setattr, 
        .fsetattr    = refuse_fsetattr,
};
#else
struct xlator_fops fops = {
	.lookup      = combine_lookup,
	.mknod       = combine_mknod,
	.create      = combine_create,
	.stat        = combine_stat,
	.fstat       = combine_fstat,
	.truncate    = combine_truncate,
	.ftruncate   = combine_ftruncate,
	.access      = combine_access,
	.readlink    = combine_readlink,
	.setxattr    = combine_setxattr,
	.getxattr    = combine_getxattr,
	.removexattr = combine_removexattr,
	.open        = combine_open,
	.readv       = combine_readv,
	.writev      = combine_writev,
	.flush       = combine_flush,
	.fsync       = combine_fsync,
	.statfs      = combine_statfs,
	.lk          = combine_lk,
	.opendir     = combine_opendir,
	.readdir     = combine_readdir,
	.readdirp    = combine_readdirp,
	.fsyncdir    = combine_fsyncdir,
	.symlink     = combine_symlink,
	.unlink      = combine_unlink,
	.link        = combine_link,
	.mkdir       = combine_mkdir,
	.rmdir       = combine_rmdir,
	.rename      = combine_rename,
	.inodelk     = combine_inodelk,
	.finodelk    = combine_finodelk,
	.entrylk     = combine_entrylk,
	.fentrylk    = combine_fentrylk,
	.xattrop     = combine_xattrop,
	.fxattrop    = combine_fxattrop,
        .setattr     = combine_setattr, 
        .fsetattr    = combine_fsetattr,
};
#endif
struct xlator_mops mops = {
};

struct xlator_dumpops dumpops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key = {"read-only"},
	  .type = GF_OPTION_TYPE_BOOL
	},
	{ .key = {"rm-permmited"},
	  .type = GF_OPTION_TYPE_BOOL
	},
	{ .key  = {NULL} },
};
