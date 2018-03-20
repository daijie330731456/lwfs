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

/* liblwfs/src/behe_acls.h:
       This file contains definition of behe_acl fops and mops functions.
*/

#ifndef _DEFAULTS_H
#define _DEFAULTS_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include "xlator.h"
#include "common-utils.h"
#include "byte-order.h"

#ifndef behe_acl_xattr
#define POSIX_ACL_ACCESS_XATTR "system.posix_acl_access"
#define POSIX_ACL_DEFAULT_XATTR "system.posix_acl_default"

#define POSIX_ACL_VERSION 2 

struct posix_acl_xattr_entry {
        uint16_t            tag;
        uint16_t            perm;
        uint32_t            id;
};

struct posix_acl_xattr_header {
        uint32_t                        version;
        struct posix_acl_xattr_entry    entries[0];
};

struct posix_acl *posix_acl_from_xattr (xlator_t *this, const char *buf, int size);

int posix_acl_to_xattr (xlator_t *this, struct posix_acl *acl, char *buf, int size);

int posix_acl_matches_xattr (xlator_t *this, struct posix_acl *acl, const char *buf, int size);
#endif

#ifndef behe_acl

#define POSIX_ACL_READ                (0x04)
#define POSIX_ACL_WRITE               (0x02)
#define POSIX_ACL_EXECUTE             (0x01)

#define POSIX_ACL_UNDEFINED_TAG       (0x00)
#define POSIX_ACL_USER_OBJ            (0x01)
#define POSIX_ACL_USER                (0x02)
#define POSIX_ACL_GROUP_OBJ           (0x04)
#define POSIX_ACL_GROUP               (0x08)
#define POSIX_ACL_MASK                (0x10)
#define POSIX_ACL_OTHER               (0x20)

#define POSIX_ACL_UNDEFINED_ID        ((id_t)-1)


struct posix_ace {
        uint16_t     tag;
        uint16_t     perm;
        uint32_t     id;
};


struct posix_acl {
        int               refcnt;
        int               count;
        struct posix_ace  entries[0];
};


struct posix_acl_ctx {
        uid_t             uid;
        gid_t             gid;
        mode_t            perm;
        struct posix_acl *acl_access;
        struct posix_acl *acl_default;
};


struct posix_acl_conf {
        gf_lock_t         acl_lock;
        struct posix_acl *minimal_acl;
};


struct posix_acl *posix_acl_new (xlator_t *this, int entry_count);
struct posix_acl *posix_acl_ref (xlator_t *this, struct posix_acl *acl);
void posix_acl_unref (xlator_t *this, struct posix_acl *acl);
void posix_acl_destroy (xlator_t *this, struct posix_acl *acl);
struct posix_acl_ctx *posix_acl_ctx_get (inode_t *inode, xlator_t *this);
int posix_acl_get (inode_t *inode, xlator_t *this,
                   struct posix_acl **acl_access_p,
                   struct posix_acl **acl_default_p);
int posix_acl_set (inode_t *inode, xlator_t *this, struct posix_acl *acl_access,
                   struct posix_acl *acl_default);

#endif

int32_t behe_acl_stats (call_frame_t *frame,
		       xlator_t *this,
		       int32_t flags);

int32_t behe_acl_getspec (call_frame_t *frame,
			 xlator_t *this,
			 const char *key,
			 int32_t flag);

int32_t
behe_acl_log (call_frame_t *frame,
             xlator_t *this,
             const char *msg);

int32_t behe_acl_checksum (call_frame_t *frame,
			  xlator_t *this,
			  loc_t *loc,
			  int32_t flag);

int32_t behe_acl_rchecksum (call_frame_t *frame,
                           xlator_t *this,
                           fd_t *fd, off_t offset,
                           int32_t len);

/* FileSystem operations */
int32_t behe_acl_lookup (call_frame_t *frame,
			xlator_t *this,
			loc_t *loc,
			dict_t *xattr_req);

int32_t behe_acl_stat (call_frame_t *frame,
		      xlator_t *this,
		      loc_t *loc);

int32_t behe_acl_fstat (call_frame_t *frame,
		       xlator_t *this,
		       fd_t *fd);

int32_t behe_acl_truncate (call_frame_t *frame,
			  xlator_t *this,
			  loc_t *loc,
			  off_t offset);

int32_t behe_acl_ftruncate (call_frame_t *frame,
			   xlator_t *this,
			   fd_t *fd,
			   off_t offset);

int32_t behe_acl_access (call_frame_t *frame,
			xlator_t *this,
			loc_t *loc,
			int32_t mask);

int32_t behe_acl_readlink (call_frame_t *frame,
			  xlator_t *this,
			  loc_t *loc,
			  size_t size);

int32_t behe_acl_mknod (call_frame_t *frame,
		       xlator_t *this,
		       loc_t *loc,
		       mode_t mode,
		       dev_t rdev);

int32_t behe_acl_mkdir (call_frame_t *frame,
		       xlator_t *this,
		       loc_t *loc,
		       mode_t mode);

int32_t behe_acl_unlink (call_frame_t *frame,
			xlator_t *this,
			loc_t *loc);

int32_t behe_acl_rmdir (call_frame_t *frame,
		       xlator_t *this,
		       loc_t *loc);

int32_t behe_acl_symlink (call_frame_t *frame,
			 xlator_t *this,
			 const char *linkpath,
			 loc_t *loc);

int32_t behe_acl_rename (call_frame_t *frame,
			xlator_t *this,
			loc_t *oldloc,
			loc_t *newloc);

int32_t behe_acl_link (call_frame_t *frame,
		      xlator_t *this,
		      loc_t *oldloc,
		      loc_t *newloc);

int32_t behe_acl_create (call_frame_t *frame,
			xlator_t *this,
			loc_t *loc,
			int32_t flags,
			mode_t mode, fd_t *fd);

int32_t behe_acl_open (call_frame_t *frame,
		      xlator_t *this,
		      loc_t *loc,
		      int32_t flags, fd_t *fd,
                      int32_t wbflags);

int32_t behe_acl_readv (call_frame_t *frame,
		       xlator_t *this,
		       fd_t *fd,
		       size_t size,
		       off_t offset);

int32_t behe_acl_writev (call_frame_t *frame,
			xlator_t *this,
			fd_t *fd,
			struct iovec *vector,
			int32_t count,
			off_t offset,
                        struct iobref *iobref);

#ifndef IOCTL /* wanghy add */
int32_t behe_acl_ioctl (call_frame_t *frame,
                       xlator_t *this,
                       fd_t *fd,
                       uint32_t cmd,
                       uint64_t arg);
#endif

int32_t behe_acl_flush (call_frame_t *frame,
		       xlator_t *this,
		       fd_t *fd);

int32_t behe_acl_fsync (call_frame_t *frame,
		       xlator_t *this,
		       fd_t *fd,
		       int32_t datasync);

int32_t behe_acl_opendir (call_frame_t *frame,
			 xlator_t *this,
			 loc_t *loc, fd_t *fd);

int32_t behe_acl_getdents (call_frame_t *frame,
			  xlator_t *this,
			  fd_t *fd,
			  size_t size,
			  off_t offset,
			  int32_t flag);

int32_t behe_acl_fsyncdir (call_frame_t *frame,
			  xlator_t *this,
			  fd_t *fd,
			  int32_t datasync);

int32_t behe_acl_statfs (call_frame_t *frame,
			xlator_t *this,
			loc_t *loc);

int32_t behe_acl_setxattr (call_frame_t *frame,
			  xlator_t *this,
			  loc_t *loc,
			  dict_t *dict,
			  int32_t flags);

int32_t behe_acl_getxattr (call_frame_t *frame,
			  xlator_t *this,
			  loc_t *loc,
			  const char *name);

int32_t behe_acl_fsetxattr (call_frame_t *frame,
                           xlator_t *this,
                           fd_t *fd,
                           dict_t *dict,
                           int32_t flags);

int32_t behe_acl_fgetxattr (call_frame_t *frame,
                           xlator_t *this,
                           fd_t *fd,
                           const char *name);

int32_t behe_acl_removexattr (call_frame_t *frame,
			     xlator_t *this,
			     loc_t *loc,
			     const char *name);

int32_t behe_acl_lk (call_frame_t *frame,
		    xlator_t *this,
		    fd_t *fd,
		    int32_t cmd,
		    struct flock *flock);

int32_t behe_acl_inodelk (call_frame_t *frame, xlator_t *this,
			 const char *volume, loc_t *loc, int32_t cmd, 
                         struct flock *flock);

int32_t behe_acl_finodelk (call_frame_t *frame, xlator_t *this,
			  const char *volume, fd_t *fd, int32_t cmd, 
                          struct flock *flock);

int32_t behe_acl_entrylk (call_frame_t *frame, xlator_t *this,
			 const char *volume, loc_t *loc, const char *basename,
			 entrylk_cmd cmd, entrylk_type type);

int32_t behe_acl_fentrylk (call_frame_t *frame, xlator_t *this,
			  const char *volume, fd_t *fd, const char *basename,
			  entrylk_cmd cmd, entrylk_type type);

int32_t behe_acl_readdir (call_frame_t *frame,
			  xlator_t *this,
			  fd_t *fd,
			  size_t size, off_t off);

int32_t behe_acl_readdirp (call_frame_t *frame,
			  xlator_t *this,
			  fd_t *fd,
			  size_t size, off_t off);

int32_t behe_acl_setdents (call_frame_t *frame,
			  xlator_t *this,
			  fd_t *fd,
			  int32_t flags,
			  dir_entry_t *entries,
			  int32_t count);

int32_t behe_acl_xattrop (call_frame_t *frame,
			 xlator_t *this,
			 loc_t *loc,
			 gf_xattrop_flags_t flags,
			 dict_t *dict);

int32_t behe_acl_fxattrop (call_frame_t *frame,
			  xlator_t *this,
			  fd_t *fd,
			  gf_xattrop_flags_t flags,
			  dict_t *dict);

int32_t
behe_acl_lock_notify (call_frame_t *frame, xlator_t *this,
                     loc_t *loc, int32_t timeout);

int32_t
behe_acl_lock_fnotify (call_frame_t *frame, xlator_t *this,
                      fd_t *fd, int32_t timeout);


int32_t behe_acl_notify (xlator_t *this,
			int32_t event,
			void *data,
			...);

int32_t behe_acl_forget (xlator_t *this,
			inode_t *inode);

int32_t behe_acl_release (xlator_t *this,
			 fd_t *fd);

int32_t behe_acl_releasedir (xlator_t *this,
			    fd_t *fd);

int32_t behe_acl_setattr (call_frame_t *frame,
                         xlator_t *this,
                         loc_t *loc,
                         struct stat *stbuf,
                         int32_t valid);

int32_t behe_acl_fsetattr (call_frame_t *frame,
                          xlator_t *this,
                          fd_t *fd,
                          struct stat *stbuf,
                          int32_t valid);

struct behe_acl_local {
        /* Used by _cbk functions */
        struct stat          stbuf;
        struct stat          pre_buf;
        struct stat          post_buf;
        struct stat          preparent;
        struct stat          postparent;

        off_t                stbuf_size;
        off_t                prebuf_size;
        off_t                postbuf_size;
        off_t                preparent_size;
        off_t                postparent_size;

        blkcnt_t             stbuf_blocks;
        blkcnt_t             prebuf_blocks;
        blkcnt_t             postbuf_blocks;
        blkcnt_t             preparent_blocks;
        blkcnt_t             postparent_blocks;

	int8_t               failed;

        int32_t              op_ret;
        int32_t              op_errno;
        int32_t              count;
        int32_t              flags;

        char                *name;
	inode_t 	    *inode;
	loc_t		     loc;
	dict_t		    *dict;
	fd_t		    *fd;
};

typedef struct behe_acl_local behe_acl_local_t;

#endif /* _DEFAULTS_H */
