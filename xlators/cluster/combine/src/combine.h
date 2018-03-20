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

#ifndef _COMBINE_H
#define _COMBINE_H

#define is_fs_root(loc) (strcmp (loc->path, "/") == 0)
#define is_revalidate(loc) (inode_ctx_get (loc->inode, this, NULL) == 0)
#define MAX_DIROFF (8*1024*1024)

struct combine_bits{
	uint32_t cb_bitmap[8];	//max support 256 subvol
};
struct combine_local {
	int                      op_ret;
	int                      op_errno;
	int                      call_cnt;
        int                      file_count;
        int                      dir_count;
	ino_t                    st_ino;
        ino_t                    st_dev;
	loc_t                    loc;
	loc_t 			 loc2;
        /* Use stbuf as the postbuf, when we require both
         * pre and post attrs */
	struct stat              stbuf;
	struct stat 		 prebuf;
	struct stat              preoldparent;
	struct stat              postoldparent; 
	struct stat              preparent;
	struct stat              postparent;
	struct statvfs		 statvfs;
	gf_dirent_t  	entries_list;
	fd_t                    *fd;
	inode_t                 *inode;
	size_t                   size;
	off_t                    offset;
	xlator_t                *cmbn_cached;
	dict_t                  *xattr_req;
};

typedef struct combine_local combine_local_t;

struct combine_conf {
	gf_lock_t      subvolume_lock;
        int32_t        subvolume_cnt;
	gf_boolean_t   read_only;
	gf_boolean_t   rm_permmited;
        xlator_t     **subvolumes;
	char          *subvolume_status;
        char           disk_unit;
        int32_t        refresh_interval;
	struct timeval last_stat_fetch;
        gf_lock_t      layout_lock;
        void          *private;     /* Can be used by wrapper xlators over combine */
};
typedef struct _combine_inode_ctx {
	xlator_t 	*position;
	struct	combine_bits subvol_bits;
} combine_inode_ctx_t;

typedef struct _combine_fd_ctx {
        char              is_dir;
        char              released;
        int32_t           flags;
        int32_t           wbflags;
	xlator_t 	*position;
	struct	combine_bits subvol_bits;
} combine_fd_ctx_t;

typedef struct combine_conf combine_conf_t;

#define COMBINE_STACK_UNWIND(fop, frame, params ...) do {       \
		combine_local_t *__local = NULL;                \
                xlator_t *__xl = NULL;                          \
                __xl = frame->this;                             \
		__local = frame->local;                         \
		frame->local = NULL;                            \
		STACK_UNWIND_STRICT (fop, frame, params);       \
		combine_local_wipe (__xl, __local);             \
	} while (0)

#define is_last_call(cnt) (cnt == 0)
#define check_is_dir(i,s,x) (S_ISDIR(s->st_mode))

#define set_if_greater(a, b) do {		\
		if ((a) < (b))			\
			(a) = (b);		\
	} while (0)


int combine_init_subvolumes (xlator_t *this, combine_conf_t *conf);
int combine_frame_return (call_frame_t *frame);

void combine_set_bit(struct combine_bits *pcb, int num, int val);
int combine_get_bit(struct combine_bits *pcb, int num);
void combine_local_wipe (xlator_t *this, combine_local_t *local);
combine_local_t *combine_local_init (call_frame_t *frame);
int combine_stat_merge (xlator_t *this, struct stat *to, struct stat *from, xlator_t *subvol);
int32_t combine_fd_set_ctx (fd_t *file, xlator_t *this, loc_t *loc, combine_fd_ctx_t *ctx);
xlator_t *combine_vol_by_path (xlator_t *this, char *path);
int combine_encode_off (xlator_t *this, xlator_t *subvol, uint64_t x, uint64_t *y_p);
int combine_decode_off (xlator_t *this, uint64_t y, int *volid,uint64_t *x_p);
int combine_itransform (xlator_t *this, xlator_t *subvol, uint64_t x, uint64_t *y_p);
int combine_deitransform (xlator_t *this, uint64_t y, int *volid,uint64_t *x_p);
xlator_t *combine_subvol_next (xlator_t *this, xlator_t *prev);
xlator_t *combine_first_up_subvol (xlator_t *this);
int combine_is_local_loc (xlator_t *this, loc_t *loc);
xlator_t *get_subvol_from_inode_ctx (xlator_t *this, loc_t *loc);
xlator_t *get_subvol_from_fd_ctx (xlator_t *this, loc_t *loc, fd_t *fd);
xlator_t *set_subvol_inode_ctx (xlator_t *this, combine_local_t *local, xlator_t *subvol,int flag);
int combine_getlayouts(xlator_t *this,loc_t *loc);
#endif
