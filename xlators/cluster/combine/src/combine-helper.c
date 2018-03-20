/*
   Copyright (c) 2009-2009 LW, Inc. <http://www.lw.com>
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
#include "combine.h"
#include "defaults.h"

#include <sys/time.h>
#include <libgen.h>

void combine_set_bit(struct combine_bits *pcb, int num, int val)
{
	int i,j;

	/* from 0 to 255 */
	if ( num <0 || num > 255 )
		return;
	i = num / 32;
	j = num % 32;
	if ( val ) {
		pcb->cb_bitmap[i] |= (0x1 << j);
	} else {
		pcb->cb_bitmap[i] &= ~(0x1 << j);
	}
	return;
}
int combine_get_bit(struct combine_bits *pcb, int num)
{
	int i,j,ret;

	/* from 0 to 255 */
	if ( num <0 || num > 255 )
		return 0;
	i = num / 32;
	j = num % 32;

	ret = (pcb->cb_bitmap[i]) & (0x1 << j);
	return ret;
}
int
combine_init_subvolumes (xlator_t *this, combine_conf_t *conf)
{
        xlator_list_t *subvols = NULL;
        int            cnt = 0;


        for (subvols = this->children; subvols; subvols = subvols->next)
                cnt++;

        conf->subvolumes = CALLOC (cnt, sizeof (xlator_t *));
        if (!conf->subvolumes) {
                gf_log (this->name, GF_LOG_ERROR,
                        "Out of memory");
                return -1;
        }
        conf->subvolume_cnt = cnt;

        cnt = 0;
        for (subvols = this->children; subvols; subvols = subvols->next)
                conf->subvolumes[cnt++] = subvols->xlator;

	conf->subvolume_status = CALLOC (cnt, sizeof (char));
	if (!conf->subvolume_status) {
		gf_log (this->name, GF_LOG_ERROR,
			"Out of memory");
		return -1;
	}

        return 0;
}

int
combine_frame_return (call_frame_t *frame)
{
	combine_local_t *local = NULL;
	int          this_call_cnt = -1;

	if (!frame)
		return -1;

	local = frame->local;

	LOCK (&frame->lock);
	{
		this_call_cnt = --local->call_cnt;
	}
	UNLOCK (&frame->lock);

	return this_call_cnt;
}

void
combine_local_wipe (xlator_t *this, combine_local_t *local)
{
	if (!local)
		return;

	loc_wipe (&local->loc);

	if (local->inode)
		inode_unref (local->inode);

	if (local->fd) {
		fd_unref (local->fd);
		local->fd = NULL;
	}

	FREE (local);
}

combine_fd_ctx_t*
combine_fdctx_init ()
{
	combine_fd_ctx_t *fdctx = NULL;

	fdctx = CALLOC (1, sizeof (*fdctx));
	if (!fdctx)
		return NULL;

	return fdctx;
}
combine_local_t *
combine_local_init (call_frame_t *frame)
{
	combine_local_t *local = NULL;

	/* TODO: use mem-pool */
	local = CALLOC (1, sizeof (*local));

	if (!local)
		return NULL;

	local->op_ret = -1;
	local->op_errno = EUCLEAN;

	INIT_LIST_HEAD (&local->entries_list);
	
	frame->local = local;

	return local;
}

int
combine_subvol_cnt (xlator_t *this, xlator_t *subvol)
{
	int i = 0;
	int ret = -1;
	combine_conf_t *conf = NULL;


	conf = this->private;

	for (i = 0; i < conf->subvolume_cnt; i++) {
		if (subvol == conf->subvolumes[i]) {
			ret = i;
			break;
		}
	}

	return ret;
}

int
combine_itransform (xlator_t *this, xlator_t *subvol, uint64_t x, uint64_t *y_p)
{
	combine_conf_t *conf = NULL;
	int         cnt = 0;
	int         max = 0;
	uint64_t    y = 0;


	if (x == ((uint64_t) -1)) {
		y = (uint64_t) -1;
		goto out;
	}

	conf = this->private;

	max = conf->subvolume_cnt;
	cnt = combine_subvol_cnt (this, subvol);

	y = ((x * max) + cnt);

out:
	if (y_p)
		*y_p = y;

	return 0;
}
int
combine_encode_off (xlator_t *this, xlator_t *subvol, uint64_t x, uint64_t *y_p)
{
	combine_conf_t *conf = NULL;
	int         cnt = 0;
	int         max = 0;
	uint64_t    tmp,y = 0;

	conf = this->private;

	max = conf->subvolume_cnt;
	cnt = combine_subvol_cnt (this, subvol);
	
	tmp = (uint64_t)cnt;
	y = (tmp << 56);
	*y_p = y | (0x0000ffffffffffff & x);

	return 0;
}
int
combine_decode_off (xlator_t *this, uint64_t y, int *volid,
		uint64_t *x_p)
{
	combine_conf_t *conf = NULL;
	int         max = 0;

	conf = this->private;
	max = conf->subvolume_cnt;

	if ( y == 0 ) {
		*volid = 0;
		*x_p = 0;
		return 0;
	}

	*volid = (y & 0xffff000000000000) >> 56;
	*x_p = y & 0x0000ffffffffffff;

	if ( *volid /max ) {
		/* need warnning */
		*volid = 0;
	}

	return 0;
}
int
combine_deitransform (xlator_t *this, uint64_t y, int *volid,
		uint64_t *x_p)
{
	combine_conf_t *conf = NULL;
	int         cnt = 0;
	int         max = 0;
	uint64_t    x = 0;

	conf = this->private;
	max = conf->subvolume_cnt;

	cnt = y % max;
	x   = y / max;

	if ( volid )
		*volid = cnt;

	if (x_p)
		*x_p = x;

	return 0;
}

int32_t
combine_stat_merge (xlator_t *this, struct stat *to,
		struct stat *from, xlator_t *subvol)
{
	int	n1,n2;
	uint64_t	xoff,yoff;

        if (!from || !to)
                return 0;


	to->st_mode     = from->st_mode;
	if ( to->st_ino == 0 ) {
		to->st_ino = from->st_ino;
		to->st_dev = from->st_dev;
		to->st_nlink = from->st_nlink;

	} else {
		if ( S_ISDIR(from->st_mode) ) {
			to->st_nlink = to->st_nlink + from->st_nlink - 2 ;
		}
		combine_deitransform(this,from->st_ino,&n1,&xoff);
		combine_deitransform(this,to->st_ino,&n2,&yoff);
		if ( n1 < n2 ) {
			to->st_ino = from->st_ino;
			to->st_dev = from->st_dev;
			to->st_nlink = from->st_nlink;
		}
	}
	to->st_rdev     = from->st_rdev;
	to->st_size    += from->st_size;
	to->st_blksize  = from->st_blksize;
	to->st_blocks  += from->st_blocks;

	set_if_greater (to->st_uid, from->st_uid);
	set_if_greater (to->st_gid, from->st_gid);

	set_if_greater (to->st_atime, from->st_atime);
	set_if_greater (to->st_mtime, from->st_mtime);
	set_if_greater (to->st_ctime, from->st_ctime);

	return 0;
}

xlator_t *
combine_subvol_next (xlator_t *this, xlator_t *prev)
{
	combine_conf_t *conf = NULL;
	int         i = 0;
	xlator_t   *next = NULL;

	conf = this->private;

	for (i = 0; i < conf->subvolume_cnt; i++) {
		if (conf->subvolumes[i] == prev) {
			if ((i + 1) < conf->subvolume_cnt)
				next = conf->subvolumes[i + 1];
			break;
		}
	}

	return next;
}

xlator_t *
combine_first_up_subvol (xlator_t *this)
{
	combine_conf_t *conf = NULL;
	xlator_t   *child = NULL;
	int         i = 0;

	conf = this->private;

	LOCK (&conf->subvolume_lock);
	{
		for (i = 0; i < conf->subvolume_cnt; i++) {
			if (conf->subvolume_status[i]) {
				child = conf->subvolumes[i];
				break;
			}
		}
	}
	UNLOCK (&conf->subvolume_lock);

	return child;
}

xlator_t *
get_subvol_from_inode_ctx (xlator_t *this, loc_t *loc)
{
	combine_inode_ctx_t *ictx1 = NULL;
	uint64_t ictx1_int = 0;
	int           ret    = -1;

	VALIDATE_OR_GOTO (loc, err);
	VALIDATE_OR_GOTO (loc->path, err);
	/* root or ? */
	if ( !loc->parent ) 
		goto err;

	if (loc->inode != NULL) {
		ret = inode_ctx_get (loc->inode, this, &ictx1_int);
		if (ret) {
			ictx1 = CALLOC (1, sizeof(combine_inode_ctx_t));
			if (ictx1 == NULL) {
				gf_log (this->name, GF_LOG_ERROR, "Out of memory");
				goto err;
			}
			ictx1->position = NULL;
			ret = inode_ctx_put (loc->inode, this, (uint64_t)ictx1);
			if (ret) {
				gf_log (this->name, GF_LOG_ERROR, "Could not set ctx");
			}
		} else {
			ictx1 = (combine_inode_ctx_t *)ictx1_int;
			/* search all io's dir */
#if 0
			if ( S_ISDIR(loc->inode->st_mode) ) {
				ictx1->position = NULL;
			}
#endif
		}
	} else {
		return NULL;
	}

	return ictx1->position;
err:
	if (ictx1 != NULL)
		free(ictx1);
	return NULL;
}
xlator_t *
get_subvol_from_fd_ctx (xlator_t *this, loc_t *loc, fd_t *fd)
{
	combine_fd_ctx_t      *fdctx = NULL;
	combine_inode_ctx_t *ictx = NULL;
	uint64_t ictx_int = 0, fdctx_int = 0;
	int           ret = -1;

        VALIDATE_OR_GOTO (fd, err);
        VALIDATE_OR_GOTO (fd->inode, err);

	ret = fd_ctx_get (fd, this, &fdctx_int);
	if (ret) {
		fdctx = CALLOC (1, sizeof(combine_fd_ctx_t));
		if (fdctx == NULL) {
			gf_log (this->name, GF_LOG_ERROR, "Out of memory");
			goto err;
		}

		if (loc != NULL && loc->inode != NULL)
			ret = inode_ctx_get (loc->inode, this, &ictx_int);
		else
			ret = inode_ctx_get (fd->inode, this, &ictx_int);

		if (ret) {
			gf_log (this->name, GF_LOG_WARNING, "Could not get ctx from inode %"PRId64"",
					loc->inode->ino);
			goto err;
		} else {
			ictx = (combine_inode_ctx_t *)ictx_int;
			fdctx->position = ictx->position;
			fdctx->subvol_bits = ictx->subvol_bits;
		}

		/*
		 * TODO: OTHER FIELD to fill.
		 */

		ret = fd_ctx_set (fd, this, (uint64_t)fdctx);
		if (ret) {
			gf_log (this->name, GF_LOG_ERROR, "could not set fd ctx");
			goto err;
		}
	}else  {
		fdctx = (combine_fd_ctx_t *)fdctx_int;
		if (loc != NULL && loc->inode != NULL)
			ret = inode_ctx_get (loc->inode, this, &ictx_int);
		else
			ret = inode_ctx_get (fd->inode, this, &ictx_int);
		if ( ret == 0 ) {
			ictx = (combine_inode_ctx_t *)ictx_int;
			/* here dir set NULL */
			fdctx->position = ictx->position;
			fdctx->subvol_bits = ictx->subvol_bits;
		} else {
			fdctx->position = NULL;
		}
	}

	return fdctx->position;
err:
	if (fdctx != NULL)
		free(fdctx);
	return NULL;
}
int
combine_getlayouts(xlator_t *this, loc_t *loc)
{
	int i,j,ret,num=0;
	combine_inode_ctx_t *ictx = NULL;
	uint64_t ictx_int;
	struct combine_bits *pcb;

	ret = inode_ctx_get (loc->inode, this, &ictx_int);
	if (ret) 
		return 0;
	ictx = (combine_inode_ctx_t *)ictx_int;
	pcb = &ictx->subvol_bits;
	for ( i=0; i<8; i++) {
	    for ( j=0; j<32; j++) {
		if ( pcb->cb_bitmap[i] &(0x1 << j) ) 
				num++;
	    }

	}
	return num;
}
void
combine_setsubvol(xlator_t *this,xlator_t *subvol,combine_inode_ctx_t *ictx,int num)
{
	int i,oldpos=-1,subpos=-1;
	combine_conf_t   *conf         = NULL;

	conf  = this->private;

	/* set oldpos to max */
	oldpos = 255;
	for ( i= 0; i< conf->subvolume_cnt; i++) {
		if ( conf->subvolumes[i] == subvol ) {
			subpos = i;
		}
		if ( ictx->position != NULL) {
			if  ( ictx->position == conf->subvolumes[i] ) {
				oldpos = i;
			}
		}
	}
	/* set or clear */
	combine_set_bit(&ictx->subvol_bits, subpos, num);
	if ( num ) {
		if ( subpos >= 0 ) {
			if ( subpos < oldpos ) {
				ictx->position = conf->subvolumes[subpos];
			}
		}
	} else if ( oldpos == subpos ){
		ictx->position = NULL;
	}
	return;
}
xlator_t *
set_subvol_inode_ctx (xlator_t *this, combine_local_t *local, xlator_t *subvol,int flag)
{
	combine_inode_ctx_t *ictx1 = NULL;
	uint64_t ictx1_int = 0;
	int           ret    = -1;
	loc_t	*loc;

	loc = &(local->loc);
	VALIDATE_OR_GOTO (loc, err);

	if (loc->inode != NULL) {
		ret = inode_ctx_get (loc->inode, this, &ictx1_int);
		if (ret) {
			ictx1 = CALLOC (1, sizeof(combine_inode_ctx_t));
			if (ictx1 == NULL) {
				gf_log (this->name, GF_LOG_ERROR, "Out of memory");
				goto err;
			}
			if ( S_ISDIR(loc->inode->st_mode) ){
				ictx1->position = NULL;
			} else {
				combine_setsubvol(this,subvol,ictx1,flag);
			}
			ret = inode_ctx_put (loc->inode, this, (uint64_t)ictx1);
			if (ret) {
				gf_log (this->name, GF_LOG_ERROR, "Could not set ctx");
			}
		} else {
			ictx1 = (combine_inode_ctx_t *)ictx1_int;
			combine_setsubvol(this,subvol,ictx1,flag);
			/* first lookup ino==0 & inode->st_mode=0,search all io's dir */
			if ( S_ISDIR(local->stbuf.st_mode) ){
				ictx1->position = NULL;
			}
		}
	} else {
		return NULL;
	}

	return ictx1->position;
err:
	if (ictx1 != NULL)
		free(ictx1);
	return NULL;
}
