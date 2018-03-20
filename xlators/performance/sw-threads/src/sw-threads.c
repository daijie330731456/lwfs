/*
  Copyright (c) 2006-2010 Lwfs, Inc. <http://www.lwfs.com>
  This file is part of Lwfs.

  Lwfs is free software; you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation; either version 3 of the License,
  or (at your option) any later version.

  Lwfs is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see
  <http://www.gnu.org/licenses/>.
*/

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "call-stub.h"
#include "lwfs.h"
#include "logging.h"
#include "dict.h"
#include "xlator.h"
#include "sw-threads.h"
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include "locking.h"

void *swt_worker (void *arg);
int swt_workers_scale (swt_conf_t *conf);
int __swt_workers_scale (swt_conf_t *conf);


call_stub_t *
__swt_dequeue (swt_arg_t *parg)
{
        swt_conf_t *conf = parg->wa_conf;
        call_stub_t  *stub = NULL;
        int           i = 0,end=0;
#ifndef WEIWEI_20130201
        if ( parg->wa_id >= MAX_RW_NUM )  {
            end = SWT_PRI_LO1;
        } else {
            end = SWT_PRI_LO;
        }
        for (i = 0; i <= end; i++) {
                if (list_empty (&conf->reqs[i]))
                        continue;
                stub = list_entry (conf->reqs[i].next, call_stub_t, list);
                break;
        }
#else
        for (i = 0; i < SWT_PRI_MAX; i++) {
            if (list_empty (&conf->reqs[i]))
                continue;
            stub = list_entry (conf->reqs[i].next, call_stub_t, list);
            break;
        }
#endif
        if (!stub)
                return NULL;

        conf->queue_size--;
        list_del_init (&stub->list);

        return stub;
}


void
__swt_enqueue (swt_conf_t *conf, call_stub_t *stub, int pri)
{
        if (pri < 0 || pri >= SWT_PRI_MAX)
                pri = SWT_PRI_MAX-1;

        list_add_tail (&stub->list, &conf->reqs[pri]);

        conf->queue_size++;

        return;
}


void *
swt_worker (void *data)
{
        swt_arg_t        *pwarg = NULL;
        swt_conf_t       *conf = NULL;
        xlator_t         *this = NULL;
        call_stub_t      *stub = NULL;
        struct timespec   sleep_till = {0, };
        int               ret = 0;
        char              timeout = 0;
        char              bye = 0;

        pwarg = (swt_arg_t *) data;
        conf = pwarg->wa_conf;
        this = conf->this;
        THIS = this;

        for (;;) {
                sleep_till.tv_sec = time (NULL) + conf->idle_time;

                pthread_mutex_lock (&conf->mutex);
                {
                        while (conf->queue_size == 0) {

                                ret = pthread_cond_timedwait (&conf->cond,
                                                              &conf->mutex,
                                                              &sleep_till);
                                if (ret == ETIMEDOUT)
					break;
                        }
                        stub = __swt_dequeue (pwarg);
                }
                pthread_mutex_unlock (&conf->mutex);

                if (stub) /* guard against spurious wakeups */
                        call_resume (stub);
        }

        free(pwarg);

        return NULL;
}


int
do_swt_schedule (swt_conf_t *conf, call_stub_t *stub, int pri)
{
        int   ret = 0;

        pthread_mutex_lock (&conf->mutex);
        {
                __swt_enqueue (conf, stub, pri);

#ifndef WEIWEI_20130201
                pthread_cond_broadcast (&conf->cond);
#else
                pthread_cond_signal (&conf->cond);
#endif

#ifdef WEIWEI_20110829
                ret = __swt_workers_scale (conf);
#endif
        }
        pthread_mutex_unlock (&conf->mutex);

        return ret;
}


#ifndef WEIWEI_20130201
int
swt_schedule_slow1 (swt_conf_t *conf, call_stub_t *stub)
{
        return do_swt_schedule (conf, stub, SWT_PRI_LO1);
}
#endif

int
swt_schedule_slow (swt_conf_t *conf, call_stub_t *stub)
{
        return do_swt_schedule (conf, stub, SWT_PRI_LO);
}


int
swt_schedule_fast (swt_conf_t *conf, call_stub_t *stub)
{
        return do_swt_schedule (conf, stub, SWT_PRI_HI);
}

int
swt_schedule (swt_conf_t *conf, call_stub_t *stub)
{
        return do_swt_schedule (conf, stub, SWT_PRI_NORMAL);
}


int
swt_schedule_unordered (swt_conf_t *conf, inode_t *inode, call_stub_t *stub)
{
        return do_swt_schedule (conf, stub, 0);
}


int
swt_schedule_ordered (swt_conf_t *conf, inode_t *inode, call_stub_t *stub)
{

        return do_swt_schedule (conf, stub, 0);
}


int
swt_lookup_cbk (call_frame_t *frame, void * cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno,
                inode_t *inode, struct stat *buf, dict_t *xattr,
                struct stat *postparent)
{
        STACK_UNWIND_STRICT (lookup, frame, op_ret, op_errno, inode, buf, xattr,
                             postparent);
        return 0;
}


int
swt_lookup_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                    dict_t *xattr_req)
{
        STACK_WIND (frame, swt_lookup_cbk,
                    FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->lookup,
                    loc, xattr_req);
        return 0;
}


int
swt_lookup (call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *xattr_req)
{
        call_stub_t     *stub = NULL;
        int              ret = -1;

        stub = fop_lookup_stub (frame, swt_lookup_wrapper, loc, xattr_req);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR,
                        "cannot create lookup stub (out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule_fast (this->private, stub);

out:
        if (ret < 0) {
                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
                STACK_UNWIND_STRICT (lookup, frame, -1, -ret, NULL, NULL, NULL,
                                     NULL);
        }

        return 0;
}


int
swt_setattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno,
                 struct stat *preop, struct stat *postop)
{
        STACK_UNWIND_STRICT (setattr, frame, op_ret, op_errno, preop, postop);
        return 0;
}


int
swt_setattr_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                     struct stat *stbuf, int32_t valid)
{
        STACK_WIND (frame, swt_setattr_cbk,
                    FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->setattr,
                    loc, stbuf, valid);
        return 0;
}


int
swt_setattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
             struct stat *stbuf, int32_t valid)
{
        call_stub_t     *stub = NULL;
        int              ret = -1;

        stub = fop_setattr_stub (frame, swt_setattr_wrapper, loc, stbuf, valid);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "Cannot create setattr stub"
                        "(Out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);

out:
        if (ret < 0) {
                if (stub != NULL) {
                        call_stub_destroy (stub);
                }

                STACK_UNWIND_STRICT (setattr, frame, -1, -ret, NULL, NULL);
        }

        return 0;
}


int
swt_fsetattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno,
                  struct stat *preop, struct stat *postop)
{
        STACK_UNWIND_STRICT (fsetattr, frame, op_ret, op_errno, preop, postop);
        return 0;
}


int
swt_fsetattr_wrapper (call_frame_t *frame, xlator_t *this,
                      fd_t *fd, struct stat *stbuf, int32_t valid)
{
        STACK_WIND (frame, swt_fsetattr_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->fsetattr, fd, stbuf, valid);
        return 0;
}


int
swt_fsetattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
              struct stat *stbuf, int32_t valid)
{
        call_stub_t     *stub = NULL;
        int              ret = -1;

        stub = fop_fsetattr_stub (frame, swt_fsetattr_wrapper, fd, stbuf,
                                  valid);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create fsetattr stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (fsetattr, frame, -1, -ret, NULL, NULL);
                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_access_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno)
{
        STACK_UNWIND_STRICT (access, frame, op_ret, op_errno);
        return 0;
}


int
swt_access_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                    int32_t mask)
{
        STACK_WIND (frame, swt_access_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->access, loc, mask);
        return 0;
}


int
swt_access (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t mask)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_access_stub (frame, swt_access_wrapper, loc, mask);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create access stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule_fast (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (access, frame, -1, -ret);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_readlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, const char *path,
                  struct stat *stbuf)
{
        STACK_UNWIND_STRICT (readlink, frame, op_ret, op_errno, path, stbuf);
        return 0;
}


int
swt_readlink_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                      size_t size)
{
        STACK_WIND (frame, swt_readlink_cbk,
                    FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->readlink,
                    loc, size);
        return 0;
}


int
swt_readlink (call_frame_t *frame, xlator_t *this, loc_t *loc, size_t size)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_readlink_stub (frame, swt_readlink_wrapper, loc, size);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create readlink stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule_fast (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (readlink, frame, -1, -ret, NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

        return 0;
}


int
swt_mknod_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, inode_t *inode,
               struct stat *buf, struct stat *preparent,
               struct stat *postparent)
{
        STACK_UNWIND_STRICT (mknod, frame, op_ret, op_errno, inode, buf,
                             preparent, postparent);
        return 0;
}


int
swt_mknod_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode,
                   dev_t rdev)
{
        STACK_WIND (frame, swt_mknod_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->mknod, loc, mode, rdev);
        return 0;
}


int
swt_mknod (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode,
           dev_t rdev)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_mknod_stub (frame, swt_mknod_wrapper, loc, mode, rdev);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create mknod stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (mknod, frame, -1, -ret, NULL, NULL, NULL,
                                     NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_mkdir_cbk (call_frame_t *frame, void * cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, inode_t *inode,
               struct stat *buf, struct stat *preparent,
               struct stat *postparent)
{
        STACK_UNWIND_STRICT (mkdir, frame, op_ret, op_errno, inode, buf,
                             preparent, postparent);
        return 0;
}


int
swt_mkdir_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode)
{
        STACK_WIND (frame, swt_mkdir_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->mkdir, loc, mode);
        return 0;
}


int
swt_mkdir (call_frame_t *frame, xlator_t *this, loc_t *loc, mode_t mode)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_mkdir_stub (frame, swt_mkdir_wrapper, loc, mode);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create mkdir stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (mkdir, frame, -1, -ret, NULL, NULL, NULL,
                                     NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_rmdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct stat *preparent,
               struct stat *postparent)
{
        STACK_UNWIND_STRICT (rmdir, frame, op_ret, op_errno, preparent,
                             postparent);
        return 0;
}


int
swt_rmdir_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
        STACK_WIND (frame, swt_rmdir_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->rmdir, loc);
        return 0;
}


int
swt_rmdir (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_rmdir_stub (frame, swt_rmdir_wrapper, loc);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create rmdir stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (rmdir, frame, -1, -ret, NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_symlink_cbk (call_frame_t *frame, void * cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, inode_t *inode,
                 struct stat *buf, struct stat *preparent,
                 struct stat *postparent)
{
        STACK_UNWIND_STRICT (symlink, frame, op_ret, op_errno, inode, buf,
                             preparent, postparent);
        return 0;
}


int
swt_symlink_wrapper (call_frame_t *frame, xlator_t *this, const char *linkname,
                     loc_t *loc)
{
        STACK_WIND (frame, swt_symlink_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->symlink, linkname, loc);
        return 0;
}


int
swt_symlink (call_frame_t *frame, xlator_t *this, const char *linkname,
             loc_t *loc)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_symlink_stub (frame, swt_symlink_wrapper, linkname, loc);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create symlink stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (symlink, frame, -1, -ret, NULL, NULL, NULL,
                                     NULL);
                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

        return 0;
}


int
swt_rename_cbk (call_frame_t *frame, void * cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, struct stat *buf,
                struct stat *preoldparent, struct stat *postoldparent,
                struct stat *prenewparent, struct stat *postnewparent)
{
        STACK_UNWIND_STRICT (rename, frame, op_ret, op_errno, buf, preoldparent,
                             postoldparent, prenewparent, postnewparent);
        return 0;
}


int
swt_rename_wrapper (call_frame_t *frame, xlator_t *this, loc_t *oldloc,
                    loc_t *newloc)
{
        STACK_WIND (frame, swt_rename_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->rename, oldloc, newloc);
        return 0;
}


int
swt_rename (call_frame_t *frame, xlator_t *this, loc_t *oldloc, loc_t *newloc)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_rename_stub (frame, swt_rename_wrapper, oldloc, newloc);
        if (!stub) {
                gf_log (this->name, GF_LOG_DEBUG, "cannot create rename stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (rename, frame, -1, -ret, NULL, NULL, NULL,
                                     NULL, NULL);
                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

        return 0;
}


int
swt_open_cbk (call_frame_t *frame, void *cookie, xlator_t *this, int32_t op_ret,
              int32_t op_errno, fd_t *fd)
{
	STACK_UNWIND_STRICT (open, frame, op_ret, op_errno, fd);
	return 0;
}


int
swt_open_wrapper (call_frame_t * frame, xlator_t * this, loc_t *loc,
                  int32_t flags, fd_t * fd, int32_t wbflags)
{
	STACK_WIND (frame, swt_open_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->open, loc, flags, fd, wbflags);
	return 0;
}


int
swt_open (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
          fd_t *fd, int32_t wbflags)
{
        call_stub_t	*stub = NULL;
        int             ret = -1;

        stub = fop_open_stub (frame, swt_open_wrapper, loc, flags, fd, wbflags);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR,
                        "cannot create open call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

	ret = swt_schedule_fast (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (open, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

	return 0;
}


int
swt_create_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, fd_t *fd, inode_t *inode,
                struct stat *stbuf, struct stat *preparent,
                struct stat *postparent)
{
	STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode, stbuf,
                             preparent, postparent);
	return 0;
}


int
swt_create_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                    int32_t flags, mode_t mode, fd_t *fd)
{
	STACK_WIND (frame, swt_create_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->create,
		    loc, flags, mode, fd);
	return 0;
}


int
swt_create (call_frame_t *frame, xlator_t *this, loc_t *loc, int32_t flags,
            mode_t mode, fd_t *fd)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_create_stub (frame, swt_create_wrapper, loc, flags, mode,fd);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR,
                        "cannot create \"create\" call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (create, frame, -1, -ret, NULL, NULL, NULL,
                                     NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

        return 0;
}


int
swt_readv_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct iovec *vector,
               int32_t count, struct stat *stbuf, struct iobref *iobref)
{
	STACK_UNWIND_STRICT (readv, frame, op_ret, op_errno, vector, count,
                             stbuf, iobref);

	return 0;
}


int
swt_readv_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
                   off_t offset)
{
	STACK_WIND (frame, swt_readv_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->readv,
		    fd, size, offset);
	return 0;
}


int
swt_readv (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
           off_t offset)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_readv_stub (frame, swt_readv_wrapper, fd, size, offset);
	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
			"cannot create readv call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

#ifndef WEIWEI_20130201
        if ( size <= 8192 ) {
            ret = swt_schedule_slow1 (this->private, stub);
        } else 
            ret = swt_schedule_slow (this->private, stub);
#else
        ret = swt_schedule_slow (this->private, stub);
#endif

out:
        if (ret < 0) {
		STACK_UNWIND_STRICT (readv, frame, -1, -ret, NULL, -1, NULL,
                                     NULL);
                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}


int
swt_flush_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno)
{
	STACK_UNWIND_STRICT (flush, frame, op_ret, op_errno);
	return 0;
}


int
swt_flush_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	STACK_WIND (frame, swt_flush_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->flush,
		    fd);
	return 0;
}


int
swt_flush (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_flush_stub (frame, swt_flush_wrapper, fd);
	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
                        "cannot create flush_cbk call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

        ret = swt_schedule (this->private, stub);
out:
        if (ret < 0) {
		STACK_UNWIND_STRICT (flush, frame, -1, -ret);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}


int
swt_fsync_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct stat *prebuf,
               struct stat *postbuf)
{
	STACK_UNWIND_STRICT (fsync, frame, op_ret, op_errno, prebuf, postbuf);
	return 0;
}


int
swt_fsync_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                   int32_t datasync)
{
	STACK_WIND (frame, swt_fsync_cbk,
		    FIRST_CHILD (this),
		    FIRST_CHILD (this)->fops->fsync,
		    fd, datasync);
	return 0;
}


int
swt_fsync (call_frame_t *frame, xlator_t *this, fd_t *fd, int32_t datasync)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_fsync_stub (frame, swt_fsync_wrapper, fd, datasync);
	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
                        "cannot create fsync_cbk call stub"
                        "(out of memory)");
                ret = -1;
                goto out;
	}

#ifndef WEIWEI_20130201
    ret = swt_schedule_slow1 (this->private, stub);
#else
    ret = swt_schedule_slow (this->private, stub);
#endif

out:
        if (ret < 0) {
		STACK_UNWIND_STRICT (fsync, frame, -1, -ret, NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}


int
swt_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, struct stat *prebuf,
                struct stat *postbuf)
{
	STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno, prebuf, postbuf);
	return 0;
}


int
swt_writev_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                    struct iovec *vector, int32_t count,
                    off_t offset, struct iobref *iobref)
{
	STACK_WIND (frame, swt_writev_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->writev,
		    fd, vector, count, offset, iobref);
	return 0;
}


int
swt_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
            struct iovec *vector, int32_t count, off_t offset,
            struct iobref *iobref)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_writev_stub (frame, swt_writev_wrapper,
				fd, vector, count, offset, iobref);

	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
                        "cannot create writev call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

#ifndef WEIWEI_20130201
        if ( count <= 8192 )
            ret = swt_schedule_slow1 (this->private, stub);
        else
            ret = swt_schedule_slow (this->private, stub);
#else
            ret = swt_schedule_slow (this->private, stub);
#endif
out:
        if (ret < 0) {
		STACK_UNWIND_STRICT (writev, frame, -1, -ret, NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

	return 0;
}


int32_t
swt_lk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
            int32_t op_ret, int32_t op_errno, struct flock *flock)
{
	STACK_UNWIND_STRICT (lk, frame, op_ret, op_errno, flock);
	return 0;
}


int
swt_lk_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                int32_t cmd, struct flock *flock)
{
	STACK_WIND (frame, swt_lk_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->lk,
		    fd, cmd, flock);
	return 0;
}


int
swt_lk (call_frame_t *frame, xlator_t *this, fd_t *fd, int32_t cmd,
	struct flock *flock)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_lk_stub (frame, swt_lk_wrapper, fd, cmd, flock);

	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
                        "cannot create fop_lk call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

        ret = swt_schedule (this->private, stub);
out:
        if (ret < 0) {
		STACK_UNWIND_STRICT (lk, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}


int
swt_stat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
              int32_t op_ret, int32_t op_errno, struct stat *buf)
{
	STACK_UNWIND_STRICT (stat, frame, op_ret, op_errno, buf);
	return 0;
}


int
swt_stat_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	STACK_WIND (frame, swt_stat_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->stat,
		    loc);
	return 0;
}


int
swt_stat (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

        stub = fop_stat_stub (frame, swt_stat_wrapper, loc);
	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
                        "cannot create fop_stat call stub"
                        "(out of memory)");
                ret = -1;
                goto out;
	}

        ret = swt_schedule_fast (this->private, stub);

out:
        if (ret < 0) {
		STACK_UNWIND_STRICT (stat, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}


int
swt_fstat_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, struct stat *buf)
{
	STACK_UNWIND_STRICT (fstat, frame, op_ret, op_errno, buf);
	return 0;
}


int
swt_fstat_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	STACK_WIND (frame, swt_fstat_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fstat,
		    fd);
	return 0;
}


int
swt_fstat (call_frame_t *frame, xlator_t *this, fd_t *fd)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_fstat_stub (frame, swt_fstat_wrapper, fd);
	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
                        "cannot create fop_fstat call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

        ret = swt_schedule_fast (this->private, stub);
out:
        if (ret < 0) {
		STACK_UNWIND_STRICT (fstat, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}


int
swt_truncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, struct stat *prebuf,
                  struct stat *postbuf)
{
	STACK_UNWIND_STRICT (truncate, frame, op_ret, op_errno, prebuf,
                             postbuf);
	return 0;
}


int
swt_truncate_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                      off_t offset)
{
	STACK_WIND (frame, swt_truncate_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->truncate,
		    loc, offset);
	return 0;
}


int
swt_truncate (call_frame_t *frame, xlator_t *this, loc_t *loc, off_t offset)
{
	call_stub_t *stub;
        int         ret = -1;

        stub = fop_truncate_stub (frame, swt_truncate_wrapper, loc, offset);

	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
                        "cannot create fop_stat call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

#ifndef WEIWEI_20130201
        ret = swt_schedule_slow1 (this->private, stub);
#else
        ret = swt_schedule_slow (this->private, stub);
#endif

out:
        if (ret < 0) {
		STACK_UNWIND_STRICT (truncate, frame, -1, -ret, NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

	return 0;
}


int
swt_ftruncate_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct stat *prebuf,
                   struct stat *postbuf)
{
	STACK_UNWIND_STRICT (ftruncate, frame, op_ret, op_errno, prebuf,
                             postbuf);
	return 0;
}


int
swt_ftruncate_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                       off_t offset)
{
	STACK_WIND (frame, swt_ftruncate_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->ftruncate,
		    fd, offset);
	return 0;
}


int
swt_ftruncate (call_frame_t *frame, xlator_t *this, fd_t *fd, off_t offset)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_ftruncate_stub (frame, swt_ftruncate_wrapper, fd, offset);
	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
                        "cannot create fop_ftruncate call stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
	}

#ifndef WEIWEI_20130201
        ret = swt_schedule_slow1 (this->private, stub);
#else
        ret = swt_schedule_slow (this->private, stub);
#endif
out:
        if (ret < 0) {
		STACK_UNWIND_STRICT (ftruncate, frame, -1, -ret, NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
	return 0;
}



int
swt_unlink_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
		int32_t op_ret, int32_t op_errno, struct stat *preparent,
                struct stat *postparent)
{
	STACK_UNWIND_STRICT (unlink, frame, op_ret, op_errno, preparent,
                             postparent);
	return 0;
}


int
swt_unlink_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	STACK_WIND (frame, swt_unlink_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->unlink,
		    loc);
	return 0;
}


int
swt_unlink (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
	call_stub_t *stub = NULL;
        int         ret = -1;

	stub = fop_unlink_stub (frame, swt_unlink_wrapper, loc);
	if (!stub) {
		gf_log (this->name, GF_LOG_ERROR,
                        "cannot create fop_unlink call stub"
                        "(out of memory)");
                ret = -1;
                goto out;
	}

        ret = swt_schedule (this->private, stub);

out:
        if (ret < 0) {
		STACK_UNWIND_STRICT (unlink, frame, -1, -ret, NULL, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

	return 0;
}


int
swt_link_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
              int32_t op_ret, int32_t op_errno, inode_t *inode,
              struct stat *buf, struct stat *preparent, struct stat *postparent)
{
        STACK_UNWIND_STRICT (link, frame, op_ret, op_errno, inode, buf,
                             preparent, postparent);
        return 0;
}


int
swt_link_wrapper (call_frame_t *frame, xlator_t *this, loc_t *old, loc_t *new)
{
        STACK_WIND (frame, swt_link_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->link, old, new);

        return 0;
}


int
swt_link (call_frame_t *frame, xlator_t *this, loc_t *oldloc, loc_t *newloc)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_link_stub (frame, swt_link_wrapper, oldloc, newloc);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create link stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (link, frame, -1, -ret, NULL, NULL, NULL,
                                     NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_opendir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, fd_t *fd)
{
        STACK_UNWIND_STRICT (opendir, frame, op_ret, op_errno, fd);
        return 0;
}


int
swt_opendir_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc, fd_t *fd)
{
        STACK_WIND (frame, swt_opendir_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->opendir, loc, fd);
        return 0;
}


int
swt_opendir (call_frame_t *frame, xlator_t *this, loc_t *loc, fd_t *fd)
{
        call_stub_t     *stub  = NULL;
        int             ret = -1;

        stub = fop_opendir_stub (frame, swt_opendir_wrapper, loc, fd);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create opendir stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule_fast (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (opendir, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_fsyncdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno)
{
        STACK_UNWIND_STRICT (fsyncdir, frame, op_ret, op_errno);
        return 0;
}


int
swt_fsyncdir_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                      int datasync)
{
        STACK_WIND (frame, swt_fsyncdir_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->fsyncdir, fd, datasync);
        return 0;
}


int
swt_fsyncdir (call_frame_t *frame, xlator_t *this, fd_t *fd, int datasync)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_fsyncdir_stub (frame, swt_fsyncdir_wrapper, fd, datasync);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create fsyncdir stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

#ifndef WEIWEI_20130201
        ret = swt_schedule_slow1 (this->private, stub);
#else
        ret = swt_schedule_slow (this->private, stub);
#endif
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (fsyncdir, frame, -1, -ret);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_statfs_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                int32_t op_ret, int32_t op_errno, struct statvfs *buf)
{
        STACK_UNWIND_STRICT (statfs, frame, op_ret, op_errno, buf);
        return 0;
}


int
swt_statfs_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
        STACK_WIND (frame, swt_statfs_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->statfs, loc);
        return 0;
}


int
swt_statfs (call_frame_t *frame, xlator_t *this, loc_t *loc)
{
        call_stub_t     *stub = NULL;
        int              ret = -1;

        stub = fop_statfs_stub (frame, swt_statfs_wrapper, loc);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create statfs stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule_fast (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (statfs, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_setxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno)
{
        STACK_UNWIND_STRICT (setxattr, frame, op_ret, op_errno);
        return 0;
}


int
swt_setxattr_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                      dict_t *dict, int32_t flags)
{
        STACK_WIND (frame, swt_setxattr_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->setxattr, loc, dict, flags);
        return 0;
}


int
swt_setxattr (call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *dict,
              int32_t flags)
{
        call_stub_t     *stub = NULL;
        int              ret = -1;

        stub = fop_setxattr_stub (frame, swt_setxattr_wrapper, loc, dict,
                                  flags);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create setxattr stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (setxattr, frame, -1, -ret);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_getxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, dict_t *dict)
{
        STACK_UNWIND_STRICT (getxattr, frame, op_ret, op_errno, dict);
        return 0;
}


int
swt_getxattr_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                      const char *name)
{
        STACK_WIND (frame, swt_getxattr_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->getxattr, loc, name);
        return 0;
}


int
swt_getxattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
              const char *name)
{
        call_stub_t     *stub = NULL;
        int              ret = -1;

        stub = fop_getxattr_stub (frame, swt_getxattr_wrapper, loc, name);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create getxattr stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);

out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (getxattr, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_fgetxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, dict_t *dict)
{
        STACK_UNWIND_STRICT (fgetxattr, frame, op_ret, op_errno, dict);
        return 0;
}


int
swt_fgetxattr_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                       const char *name)
{
        STACK_WIND (frame, swt_fgetxattr_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->fgetxattr, fd, name);
        return 0;
}


int
swt_fgetxattr (call_frame_t *frame, xlator_t *this, fd_t *fd,
               const char *name)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_fgetxattr_stub (frame, swt_fgetxattr_wrapper, fd, name);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create fgetxattr stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (fgetxattr, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_fsetxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno)
{
        STACK_UNWIND_STRICT (fsetxattr, frame, op_ret, op_errno);
        return 0;
}


int
swt_fsetxattr_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                       dict_t *dict, int32_t flags)
{
        STACK_WIND (frame, swt_fsetxattr_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->fsetxattr, fd, dict, flags);
        return 0;
}


int
swt_fsetxattr (call_frame_t *frame, xlator_t *this, fd_t *fd, dict_t *dict,
               int32_t flags)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_fsetxattr_stub (frame, swt_fsetxattr_wrapper, fd, dict,
                                        flags);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create fsetxattr stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (fsetxattr, frame, -1, -ret);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_removexattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                     int32_t op_ret, int32_t op_errno)
{
        STACK_UNWIND_STRICT (removexattr, frame, op_ret, op_errno);
        return 0;
}


int
swt_removexattr_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                         const char *name)
{
        STACK_WIND (frame, swt_removexattr_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->removexattr, loc, name);
        return 0;
}


int
swt_removexattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
                 const char *name)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_removexattr_stub (frame, swt_removexattr_wrapper, loc,
                                     name);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR,"cannot get removexattr fop"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (removexattr, frame, -1, -ret);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_readdirp_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, gf_dirent_t *entries)
{
        STACK_UNWIND_STRICT (readdirp, frame, op_ret, op_errno, entries);
        return 0;
}


int
swt_readdirp_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                      size_t size, off_t offset)
{
        STACK_WIND (frame, swt_readdirp_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->readdirp, fd, size, offset);
        return 0;
}


int
swt_readdirp (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
              off_t offset)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_readdirp_stub (frame, swt_readdirp_wrapper, fd, size,
                                  offset);
        if (!stub) {
                gf_log (this->private, GF_LOG_ERROR,"cannot get readdir stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule_fast (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (readdirp, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_readdir_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, gf_dirent_t *entries)
{
        STACK_UNWIND_STRICT (readdir, frame, op_ret, op_errno, entries);
        return 0;
}


int
swt_readdir_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                     size_t size, off_t offset)
{
        STACK_WIND (frame, swt_readdir_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->readdir, fd, size, offset);
        return 0;
}


int
swt_readdir (call_frame_t *frame, xlator_t *this, fd_t *fd, size_t size,
             off_t offset)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_readdir_stub (frame, swt_readdir_wrapper, fd, size, offset);
        if (!stub) {
                gf_log (this->private, GF_LOG_ERROR,"cannot get readdir stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule_fast (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (readdir, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_xattrop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, dict_t *xattr)
{
        STACK_UNWIND_STRICT (xattrop, frame, op_ret, op_errno, xattr);
        return 0;
}


int
swt_xattrop_wrapper (call_frame_t *frame, xlator_t *this, loc_t *loc,
                     gf_xattrop_flags_t optype, dict_t *xattr)
{
        STACK_WIND (frame, swt_xattrop_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->xattrop, loc, optype, xattr);
        return 0;
}


int
swt_xattrop (call_frame_t *frame, xlator_t *this, loc_t *loc,
             gf_xattrop_flags_t optype, dict_t *xattr)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_xattrop_stub (frame, swt_xattrop_wrapper, loc, optype,
                                        xattr);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create xattrop stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

#ifndef WEIWEI_20130201
        ret = swt_schedule_slow1 (this->private, stub);
#else
        ret = swt_schedule_slow (this->private, stub);
#endif
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (xattrop, frame, -1, -ret, NULL);

                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int
swt_fxattrop_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, dict_t *xattr)
{
        STACK_UNWIND_STRICT (fxattrop, frame, op_ret, op_errno, xattr);
        return 0;
}

int
swt_fxattrop_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                      gf_xattrop_flags_t optype, dict_t *xattr)
{
        STACK_WIND (frame, swt_fxattrop_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->fxattrop, fd, optype, xattr);
        return 0;
}


int
swt_fxattrop (call_frame_t *frame, xlator_t *this, fd_t *fd,
              gf_xattrop_flags_t optype, dict_t *xattr)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_fxattrop_stub (frame, swt_fxattrop_wrapper, fd, optype,
                                        xattr);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create fxattrop stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

        ret = swt_schedule_slow (this->private, stub);
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (fxattrop, frame, -1, -ret, NULL);
                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }
        return 0;
}


int32_t
swt_rchecksum_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, uint32_t weak_checksum,
                   uint8_t *strong_checksum)
{
        STACK_UNWIND_STRICT (rchecksum, frame, op_ret, op_errno, weak_checksum,
                             strong_checksum);
        return 0;
}


int32_t
swt_rchecksum_wrapper (call_frame_t *frame, xlator_t *this, fd_t *fd,
                       off_t offset, int32_t len)
{
        STACK_WIND (frame, swt_rchecksum_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->rchecksum, fd, offset, len);
        return 0;
}


int32_t
swt_rchecksum (call_frame_t *frame, xlator_t *this, fd_t *fd, off_t offset,
               int32_t len)
{
        call_stub_t     *stub = NULL;
        int             ret = -1;

        stub = fop_rchecksum_stub (frame, swt_rchecksum_wrapper, fd, offset,
                                   len);
        if (!stub) {
                gf_log (this->name, GF_LOG_ERROR, "cannot create rchecksum stub"
                        "(out of memory)");
                ret = -ENOMEM;
                goto out;
        }

#ifndef WEIWEI_20130201
        ret = swt_schedule_slow1 (this->private, stub);
#else
        ret = swt_schedule_slow (this->private, stub);
#endif
out:
        if (ret < 0) {
                STACK_UNWIND_STRICT (rchecksum, frame, -1, -ret, -1, NULL);
                if (stub != NULL) {
                        call_stub_destroy (stub);
                }
        }

        return 0;
}

#ifndef WEIWEI_20110824
int
log_base2 (unsigned long x)
{
	int val = 0;

	while (x > 1) {
		x /= 2;
		val++;
	}

	return val;
}
#endif



#ifndef WEIWEI_20110829
/* Do not create work threads dynamic, just create them according to "max_count". */
int
__swt_workers_scale (swt_conf_t *conf)
{
    pthread_t thread;
    swt_arg_t    *pwarg;
    int ret = 0;
    int i; 

#ifndef WEIWEI_20110831
	gf_log(conf->this->name, GF_LOG_NORMAL, "max_count=%d.",conf->max_count);
#endif
	
#ifndef WEIWEI_20130201
	for(i=0; i<(conf->max_count); i++){
            pwarg = CALLOC (1, sizeof (*pwarg));
            pwarg->wa_conf = conf;
            pwarg->wa_id = i;
            ret = pthread_create (&thread, &conf->w_attr, swt_worker, pwarg);
            if (ret == 0) {
                    conf->curr_count++;
                    gf_log (conf->this->name, GF_LOG_DEBUG,
                            "scaled threads to %d.",
                            conf->curr_count);
            } else {
                    free(pwarg);
                    break;
            }
	}
#else
    for(i=0; i<(conf->max_count); i++){
        ret = pthread_create (&thread, &conf->w_attr, swt_worker, conf);
        if (ret == 0) {
            conf->curr_count++;
            gf_log (conf->this->name, GF_LOG_DEBUG,"scaled threads to %d.",
            conf->curr_count);
        } else {
            break;
        }
    }
#endif
}
#endif


int
swt_workers_scale (swt_conf_t *conf)
{
        int     ret = -1;

        if (conf == NULL) {
                ret = -EINVAL;
                goto out;
        }

        pthread_mutex_lock (&conf->mutex);
        {
                ret = __swt_workers_scale (conf);
        }
        pthread_mutex_unlock (&conf->mutex);

out:
        return ret;
}


void
set_stack_size (swt_conf_t *conf)
{
        int     err = 0;
        size_t  stacksize = SWT_THREAD_STACK_SIZE;

        pthread_attr_init (&conf->w_attr);
        err = pthread_attr_setstacksize (&conf->w_attr, stacksize);
        if (err == EINVAL) {
                gf_log (conf->this->name, GF_LOG_WARNING,
                        "Using default thread stack size");
        }
}

int
init (xlator_t *this)
{
        swt_conf_t      *conf = NULL;
        dict_t          *options = this->options;
        int              thread_count = SWT_DEFAULT_THREADS;
        int              idle_time = SWT_DEFAULT_IDLE;
        int              ret = -1;
        int              i = 0;

	if (!this->children || this->children->next) {
		gf_log ("sw-threads", GF_LOG_ERROR,
			"FATAL: swt not configured with exactly one child");
                goto out;
	}

	if (!this->parents) {
		gf_log (this->name, GF_LOG_WARNING,
			"dangling volume. check volfile ");
	}

	conf = (void *) CALLOC (1, sizeof (*conf));
        if (conf == NULL) {
                gf_log (this->name, GF_LOG_ERROR,
                        "out of memory");
                goto out;
        }

        set_stack_size (conf);

        thread_count = SWT_DEFAULT_THREADS;

	if (dict_get (options, "thread-count")) {
                thread_count = data_to_int32 (dict_get (options,
                                                        "thread-count"));
                if (thread_count < SWT_MIN_THREADS) {
                        gf_log ("sw-threads", GF_LOG_WARNING,
                                "Number of threads opted is less then min"
                                "threads allowed scaling it up to min");
                        thread_count = SWT_MIN_THREADS;
                }
                if (thread_count > SWT_MAX_THREADS) {
                        gf_log ("sw-threads", GF_LOG_WARNING,
                                "Number of threads opted is more then max"
                                " threads allowed scaling it down to max");
                        thread_count = SWT_MAX_THREADS;
                }
        }
        conf->max_count = thread_count;

	if (dict_get (options, "idle-time")) {
                idle_time = data_to_int32 (dict_get (options,
                                                     "idle-time"));
                if (idle_time < 0)
                        idle_time = 1;
        }
        conf->idle_time = idle_time;

        conf->this = this;

        for (i = 0; i < SWT_PRI_MAX; i++) {
                INIT_LIST_HEAD (&conf->reqs[i]);
        }

	ret = swt_workers_scale (conf);

        if (ret == -1) {
                gf_log (this->name, GF_LOG_ERROR,
                        "cannot initialize worker threads, exiting init");
                FREE (conf);
                goto out;
        }

	this->private = conf;
        ret = 0;
out:
	return ret;
}


void
fini (xlator_t *this)
{
	swt_conf_t *conf = this->private;

	FREE (conf);

	this->private = NULL;
	return;
}


struct xlator_fops fops = {
	.open        = swt_open,
	.create      = swt_create,
	.readv       = swt_readv,
	.writev      = swt_writev,
	.flush       = swt_flush,
	.fsync       = swt_fsync,
	.lk          = swt_lk,
	.stat        = swt_stat,
	.fstat       = swt_fstat,
	.truncate    = swt_truncate,
	.ftruncate   = swt_ftruncate,
	.unlink      = swt_unlink,
        .lookup      = swt_lookup,
        .setattr     = swt_setattr,
        .fsetattr    = swt_fsetattr,
        .access      = swt_access,
        .readlink    = swt_readlink,
        .mknod       = swt_mknod,
        .mkdir       = swt_mkdir,
        .rmdir       = swt_rmdir,
        .symlink     = swt_symlink,
        .rename      = swt_rename,
        .link        = swt_link,
        .opendir     = swt_opendir,
        .fsyncdir    = swt_fsyncdir,
        .statfs      = swt_statfs,
        .setxattr    = swt_setxattr,
        .getxattr    = swt_getxattr,
        .fgetxattr   = swt_fgetxattr,
        .fsetxattr   = swt_fsetxattr,
        .removexattr = swt_removexattr,
        .readdir     = swt_readdir,
        .readdirp    = swt_readdirp,
        .xattrop     = swt_xattrop,
	.fxattrop    = swt_fxattrop,
        .rchecksum   = swt_rchecksum,
};

#ifndef WEIWEI_20110824
struct xlator_mops mops = {
};
#endif

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key  = {"thread-count"},
	  .type = GF_OPTION_TYPE_INT,
	  .min  = SWT_MIN_THREADS,
	  .max  = SWT_MAX_THREADS
	},
        {.key   = {"idle-time"},
         .type  = GF_OPTION_TYPE_INT,
         .min   = 1,
         .max   = 0x7fffffff,
        },
	{ .key  = {NULL},
        },
};