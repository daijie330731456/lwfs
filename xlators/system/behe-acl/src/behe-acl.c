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

/* liblwfs/src/behe_acls.c:
   This file contains functions, which are used to fill the 'fops' and 'mops'
   structures in the xlator structures, if they are not written. Here, all the
   function calls are plainly forwared to the first child of the xlator, and
   all the *_cbk function does plain STACK_UNWIND of the frame, and returns.

   All the functions are plain enough to understand.
*/

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "xlator.h"
#include "behe-acl.h"

#define UINT64(ptr) ((uint64_t)((long)(ptr)))
#define PTR(num) ((void *)((long)(num)))

int
whitelisted_xattr (const char *key)
{
        if (!key)
                return 0;

        if (strcmp (POSIX_ACL_ACCESS_XATTR, key) == 0)
                return 1;
        if (strcmp (POSIX_ACL_DEFAULT_XATTR, key) == 0)
                return 1;
        return 0;
}


int
frame_is_user (call_frame_t *frame, uid_t uid)
{
        return (frame->root->uid == uid);
}


int
frame_in_group (call_frame_t *frame, gid_t gid)
{
        int  i = 0;

        if (frame->root->gid == gid)
                return 1;

        for (i = 0; i < frame->root->ngrps; i++)
                if (frame->root->groups[i] == gid)
                        return 1;
        return 0;
}


mode_t
posix_acl_access_set_mode (struct posix_acl *acl, struct posix_acl_ctx *ctx)
{
        struct posix_ace  *ace = NULL;
        struct posix_ace  *group_ce = NULL;
        struct posix_ace  *mask_ce = NULL;
        int                count = 0;
        int                i = 0;
        mode_t             mode = 0;
        int                mask = 0;

        count = acl->count;

        ace = acl->entries;
        for (i = 0; i < count; i++) {
                switch (ace->tag) {
                case POSIX_ACL_USER_OBJ:
                        mask |= S_IRWXU;
                        mode |= (ace->perm << 6);
                        break;
                case POSIX_ACL_GROUP_OBJ:
                        group_ce = ace;
                        break;
                case POSIX_ACL_MASK:
                        mask_ce = ace;
                        break;
                case POSIX_ACL_OTHER:
                        mask |= S_IRWXO;
                        mode |= (ace->perm);
                        break;
                }
                ace++;
        }

        if (mask_ce) {
                mask |= S_IRWXG;
                mode |= (mask_ce->perm << 3);
        } else {
                if (!group_ce)
                        goto out;
                mask |= S_IRWXG;
                mode |= (group_ce->perm << 3);
        }

out:
        ctx->perm = (ctx->perm & ~mask) | mode;

        return mode;
}


static int
sticky_permits (call_frame_t *frame, inode_t *parent, inode_t *inode)
{
        struct posix_acl_ctx  *par = NULL;
        struct posix_acl_ctx  *ctx = NULL;

        par = posix_acl_ctx_get (parent, frame->this);
        ctx = posix_acl_ctx_get (inode, frame->this);

        if (frame_is_user (frame, 0))
                return 1;

        if (!(par->perm & S_ISVTX))
                return 1;

        if (frame_is_user (frame, par->uid))
                return 1;

        if (frame_is_user (frame, ctx->uid))
                return 1;

        return 0;
}


static int
acl_permits (call_frame_t *frame, inode_t *inode, int want)
{
        int                     verdict = 0;
        int                     ret = 0;
        struct posix_acl       *acl = NULL;
        struct posix_ace       *ace = NULL;
        struct posix_acl_ctx   *ctx = NULL;
        struct posix_acl_conf  *conf = NULL;
        int                     i = 0;
        int                     perm = 0;
        int                     found = 0;
        int                     acl_present = 0;

gf_log ("acl", GF_LOG_TRACE, "acl_permits entered\n");
        conf = frame->this->private;

        ctx = posix_acl_ctx_get (inode, frame->this);
        if (!ctx)
                goto red;

        if (frame->root->uid == 0)
                goto green;

        ret = posix_acl_get (inode, frame->this, &acl, NULL);

        if (!acl) {
                acl = posix_acl_ref (frame->this, conf->minimal_acl);
        }

        ace = acl->entries;

        if (acl->count > 3)
                acl_present = 1;
        
        for (i = 0; i < acl->count; i++) {
                switch (ace->tag) {
                case POSIX_ACL_USER_OBJ:
                        perm = ((ctx->perm & S_IRWXU) >> 6);
                        if (frame_is_user (frame, ctx->uid))
                                goto perm_check;
                        break;
                case POSIX_ACL_USER:
                        perm = ace->perm;
                        if (frame_is_user (frame, ace->id))
                                goto mask_check;
                        break;
                case POSIX_ACL_GROUP_OBJ:
                        if (acl_present)
                                perm = ace->perm;
                        else
                                perm = ((ctx->perm & S_IRWXG) >> 3);
                        if (frame_in_group (frame, ctx->gid)) {
                                found = 1;
                                if ((perm & want) == want)
                                        goto mask_check;
                        }
                        break;
                case POSIX_ACL_GROUP:
                        perm = ace->perm;
                        if (frame_in_group (frame, ace->id)) {
                                found = 1;
                                if ((perm & want) == want)
                                        goto mask_check;
                        }
                        break;
                case POSIX_ACL_MASK:
                        break;
                case POSIX_ACL_OTHER:
                        perm = (ctx->perm & S_IRWXO);
                        if (!found)
                                goto perm_check;
                        /* fall through */
                default:
                        goto red;
                }

                ace++;
        }
mask_check:
        ace = acl->entries;

        for (i = 0; i < acl->count; i++, ace++) {
                if (ace->tag != POSIX_ACL_MASK)
                        continue;
#ifndef behe_110926_acl
                if ((perm & want) == want) {
                        goto green;
                }
#else
                if ((ace->perm & perm & want) == want) {
                        goto green;
                }
#endif
                goto red;
        }

perm_check:
        if ((perm & want) == want) {
                goto green;
        } else {
                goto red;
        }

green:
        verdict = 1;
        goto out;
red:
        verdict = 0;
out:
        if (acl)
                posix_acl_unref (frame->this, acl);

        return verdict;
}

struct posix_acl_ctx *
posix_acl_ctx_get (inode_t *inode, xlator_t *this)
{
        struct posix_acl_ctx *ctx = NULL;
        uint64_t              int_ctx = 0;
        int                   ret = 0;

        ret = inode_ctx_get (inode, this, &int_ctx);
        if ((ret == 0) && (int_ctx))
                return PTR(int_ctx);

        ctx = CALLOC (1, sizeof (*ctx));
        if (!ctx)
                return NULL;

        ret = inode_ctx_put (inode, this, UINT64(ctx));

        return ctx;
}


int
__posix_acl_set (inode_t *inode, xlator_t *this, struct posix_acl *acl_access,
                 struct posix_acl *acl_default)
{
        int                    ret = 0;
        struct posix_acl_ctx  *ctx = NULL;

        ctx = posix_acl_ctx_get (inode, this);
        if (!ctx)
                goto out;

        ctx->acl_access = acl_access;
        ctx->acl_default = acl_default;

out:
        return ret;
}


int
__posix_acl_get (inode_t *inode, xlator_t *this, struct posix_acl **acl_access_p,
                 struct posix_acl **acl_default_p)
{
        int                    ret = 0;
        struct posix_acl_ctx  *ctx = NULL;

        ctx = posix_acl_ctx_get (inode, this);
        if (!ctx)
                goto out;

        if (acl_access_p)
                *acl_access_p = ctx->acl_access;
        if (acl_default_p)
                *acl_default_p = ctx->acl_default;

out:
        return ret;
}


struct posix_acl *
posix_acl_new (xlator_t *this, int entrycnt)
{
        struct posix_acl *acl = NULL;
        struct posix_ace *ace = NULL;

        acl = CALLOC (1, sizeof (*acl) + (entrycnt * sizeof (*ace)));
        if (!acl)
                return NULL;

        acl->count = entrycnt;

        posix_acl_ref (this, acl);

        return acl;
}


void
posix_acl_destroy (xlator_t *this, struct posix_acl *acl)
{
        FREE (acl);

        return;
}


struct posix_acl *
posix_acl_ref (xlator_t *this, struct posix_acl *acl)
{
        struct posix_acl_conf  *conf = NULL;

        conf = this->private;

        LOCK(&conf->acl_lock);
        {
                acl->refcnt++;
        }
        UNLOCK(&conf->acl_lock);

        return acl;
}

struct posix_acl *
posix_acl_dup (xlator_t *this, struct posix_acl *acl)
{
        struct posix_acl_conf  *conf = NULL;
        struct posix_acl       *dup = NULL;

        conf = this->private;

        dup = posix_acl_new (this, acl->count);
        if (!dup)
                return NULL;

        memcpy (dup->entries, acl->entries,
                sizeof (struct posix_ace) * acl->count);

        return dup;
}


void
posix_acl_unref (xlator_t *this, struct posix_acl *acl)
{
        struct posix_acl_conf  *conf = NULL;
        int                     refcnt = 0;

        conf = this->private;

        LOCK(&conf->acl_lock);
        {
                refcnt = --acl->refcnt;
        }
        UNLOCK(&conf->acl_lock);

        if (!refcnt)
                posix_acl_destroy (this, acl);
}


int
posix_acl_set (inode_t *inode, xlator_t *this, struct posix_acl *acl_access,
               struct posix_acl *acl_default)
{
        int                     ret = 0;
        int                     oldret = 0;
        struct posix_acl       *old_access = NULL;
        struct posix_acl       *old_default = NULL;
        struct posix_acl_conf  *conf = NULL;

        conf = this->private;

        LOCK(&conf->acl_lock);
        {
                oldret = __posix_acl_get (inode, this, &old_access,
                                          &old_default);
                if (acl_access)
                        acl_access->refcnt++;
                if (acl_default)
                        acl_default->refcnt++;

                ret = __posix_acl_set (inode, this, acl_access, acl_default);
        }
        UNLOCK(&conf->acl_lock);

        if (oldret == 0) {
                if (old_access)
                        posix_acl_unref (this, old_access);
                if (old_default)
                        posix_acl_unref (this, old_default);
        }

        return ret;
}


int
posix_acl_get (inode_t *inode, xlator_t *this, struct posix_acl **acl_access_p,
               struct posix_acl **acl_default_p)
{
        struct posix_acl_conf  *conf = NULL;
        struct posix_acl       *acl_access = NULL;
        struct posix_acl       *acl_default = NULL;
        int                     ret = 0;

        conf = this->private;

        LOCK(&conf->acl_lock);
        {
                ret = __posix_acl_get (inode, this, &acl_access, &acl_default);

                if (ret != 0)
                        goto unlock;

                if (acl_access && acl_access_p)
                        acl_access->refcnt++;
                if (acl_default && acl_default_p)
                        acl_default->refcnt++;
        }
unlock:
        UNLOCK(&conf->acl_lock);

        if (acl_access_p)
                *acl_access_p = acl_access;
        if (acl_default_p)
                *acl_default_p = acl_default;

        return ret;
}

mode_t
posix_acl_inherit_mode (struct posix_acl *acl, mode_t modein)
{
        struct posix_ace       *ace = NULL;
        int                     count = 0;
        int                     i = 0;
        mode_t                  newmode = 0;
        mode_t                  mode = 0;
        struct posix_ace       *mask_ce = NULL;
        struct posix_ace       *group_ce = NULL;

        newmode = mode = modein;

        count = acl->count;

        ace = acl->entries;
        for (i = 0; i < count; i++) {
                switch (ace->tag) {
                case POSIX_ACL_USER_OBJ:
                        ace->perm &= (mode >> 6) | ~S_IRWXO;
                        mode &= (ace->perm << 6) | ~S_IRWXU;
                        break;
                case POSIX_ACL_GROUP_OBJ:
                        group_ce = ace;
                        break;
                case POSIX_ACL_MASK:
                        mask_ce = ace;
                        break;
                case POSIX_ACL_OTHER:
                        ace->perm &= (mode) | ~S_IRWXO;
                        mode &= (ace->perm) | ~S_IRWXO;
                        break;
                }
                ace++;
        }

#ifdef behe_110926_acl
	if (!mask_ce) {
		if (group_ce) {
			group_ce->perm &= (mode >> 3) | ~S_IRWXO;
			mode &= (group_ce->perm << 3) | ~S_IRWXG;
		}
	}
#else
        if (mask_ce) {
gf_log ("inherit_mode", GF_LOG_TRACE, "mask_ce %d", mask_ce->perm);
gf_log ("inherit_mode", GF_LOG_TRACE, "mode %o", mode);
                mask_ce->perm &= (mode >> 3) | ~S_IRWXO;
                mode &= (mask_ce->perm << 3) | ~S_IRWXG;
gf_log ("inherit_mode", GF_LOG_TRACE, "mask_ce %d", mask_ce->perm);
gf_log ("inherit_mode", GF_LOG_TRACE, "mode %o", mode);
        } else {
                group_ce->perm &= (mode >> 3) | ~S_IRWXO;
                mode &= (group_ce->perm << 3) | ~S_IRWXG;
        }
#endif

        newmode = ((modein & S_IFMT) | (mode & (S_IRWXU|S_IRWXG|S_IRWXO)));

        return newmode;
}


mode_t
posix_acl_inherit (xlator_t *this, loc_t *loc, dict_t *params, mode_t mode,
                   int is_dir)
{
        int                    ret = 0;
        struct posix_acl      *par_default = NULL;
        struct posix_acl      *acl_default = NULL;
        struct posix_acl      *acl_access = NULL;
        struct posix_acl_ctx  *ctx = NULL;
        char                  *xattr_default = NULL;
        char                  *xattr_access = NULL;
        int                    size_default = 0;
        int                    size_access = 0;
        mode_t                 retmode = 0;

        retmode = mode;

        ret = posix_acl_get (loc->parent, this, NULL, &par_default);

        if (!par_default)
                goto out;

        ctx = posix_acl_ctx_get (loc->inode, this);

        acl_access = posix_acl_dup (this, par_default);
        if (!acl_access)
                goto out;

        retmode = posix_acl_inherit_mode (acl_access, mode);
        ctx->perm = retmode;

        size_access = posix_acl_to_xattr (this, acl_access, NULL, 0);
gf_log (this->name, GF_LOG_TRACE, "inherit dump access");
posix_acl_dump_acl (this, acl_access);
        xattr_access = CALLOC (1, size_access);
        if (!xattr_access) {
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                ret = -1;
                goto out;
        }
        posix_acl_to_xattr (this, acl_access, xattr_access, size_access);

        ret = dict_set_bin (params, POSIX_ACL_ACCESS_XATTR, xattr_access,
                            size_access);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                ret = -1;
                goto out;
        }

        if (!is_dir)
                goto set;


        acl_default = posix_acl_ref (this, par_default);

        size_default = posix_acl_to_xattr (this, acl_default, NULL, 0);
gf_log (this->name, GF_LOG_TRACE, "inherit dump default");
posix_acl_dump_acl (this, acl_default);
        xattr_default = CALLOC (1, size_default);
        if (!xattr_default) {
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                ret = -1;
                goto out;
        }
        posix_acl_to_xattr (this, acl_default, xattr_default, size_default);

        ret = dict_set_bin (params, POSIX_ACL_DEFAULT_XATTR, xattr_default,
                            size_default);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "out of memory");
                ret = -1;
                goto out;
        }

set:
        ret = posix_acl_set (loc->inode, this, acl_access, acl_default);
        if (ret != 0)
                goto out;

out:
        if (par_default)
                posix_acl_unref (this, par_default);
        if (acl_access)
                posix_acl_unref (this, acl_access);
        if (acl_default)
                posix_acl_unref (this, acl_default);

        return retmode;
}


mode_t
posix_acl_inherit_dir (xlator_t *this, loc_t *loc, dict_t *params, mode_t mode)
{
        mode_t  retmode = 0;

        retmode = posix_acl_inherit (this, loc, params, mode, 1);

        return retmode;
}


mode_t
posix_acl_inherit_file (xlator_t *this, loc_t *loc, dict_t *params, mode_t mode)
{
        mode_t  retmode = 0;

        retmode = posix_acl_inherit (this, loc, params, mode, 0);

        return retmode;
}


int
posix_ace_cmp (const void *val1, const void *val2)
{
        const struct posix_ace *ace1 = NULL;
        const struct posix_ace *ace2 = NULL;
        int                     ret = 0;

        ace1 = val1;
        ace2 = val2;

        ret = (ace1->tag - ace2->tag);
        if (!ret)
                ret = (ace1->id - ace2->id);

        return ret;
}


void
posix_acl_normalize (xlator_t *this, struct posix_acl *acl)
{
        qsort (acl->entries, acl->count, sizeof (struct posix_ace *),
               posix_ace_cmp);
}


struct posix_acl *
posix_acl_from_xattr (xlator_t *this, const char *xattr_buf, int xattr_size)
{
        struct posix_acl_xattr_header   *header = NULL;
        struct posix_acl_xattr_entry    *entry = NULL;
        struct posix_acl                *acl = NULL;
        struct posix_ace                *ace = NULL;
        int                              size = 0;
        int                              count = 0;
        int                              i = 0;

        size = xattr_size;

        if (size < sizeof (*header))
                return NULL;

        size -= sizeof (*header);

        if (size % sizeof (*entry))
                return NULL;

        count = size / sizeof (*entry);

        header = (struct posix_acl_xattr_header *) (xattr_buf);
        entry = (struct posix_acl_xattr_entry *) (header + 1);

        if (header->version != htole32 (POSIX_ACL_VERSION))
                return NULL;

        acl = posix_acl_new (this, count);
        if (!acl)
                return NULL;

        ace = acl->entries;

        for (i = 0; i < count; i++) {
                ace->tag  = letoh16 (entry->tag);
                ace->perm = letoh16 (entry->perm);

                switch (ace->tag) {
                case POSIX_ACL_USER_OBJ:
                case POSIX_ACL_MASK:
                case POSIX_ACL_OTHER:
                        ace->id = POSIX_ACL_UNDEFINED_ID;
                        break;

                case POSIX_ACL_GROUP:
                case POSIX_ACL_USER:
                case POSIX_ACL_GROUP_OBJ:
                        ace->id = letoh32 (entry->id);
                        break;

                default:
                        goto err;
                }

                ace++;
                entry++;
        }

        posix_acl_normalize (this, acl);

        return acl;
err:
        posix_acl_destroy (this, acl);
        return NULL;
}


int
posix_acl_to_xattr (xlator_t *this, struct posix_acl *acl, char *xattr_buf,
                    int xattr_size)
{
        int                             size = 0;
        struct posix_acl_xattr_header  *header = NULL;
        struct posix_acl_xattr_entry   *entry = NULL;
        struct posix_ace               *ace = NULL;
        int                             i = 0;

        size = sizeof (*header) + (acl->count * sizeof (*entry));

        if (xattr_size < size)
                return size;

        header = (struct posix_acl_xattr_header *) (xattr_buf);
        entry = (struct posix_acl_xattr_entry *) (header + 1);
        ace = acl->entries;

        header->version = htole32 (POSIX_ACL_VERSION);

        for (i = 0; i < acl->count; i++) {
                entry->tag   = htole16 (ace->tag);
                entry->perm  = htole16 (ace->perm);

                switch (ace->tag) {
                case POSIX_ACL_USER:
                case POSIX_ACL_GROUP:
                        entry->id  = htole32 (ace->id);
                        break;
                default:
                        entry->id = POSIX_ACL_UNDEFINED_ID;
                        break;
                }

                ace++;
                entry++;
        }

        return 0;
}


int
posix_acl_matches_xattr (xlator_t *this, struct posix_acl *acl, const char *buf,
                         int size)
{
        struct posix_acl  *acl2 = NULL;
        int                ret = 1;

        acl2 = posix_acl_from_xattr (this, buf, size);
        if (!acl2)
                return 0;

        if (acl->count != acl2->count) {
                ret = 0;
                goto out;
        }

        if (memcmp (acl->entries, acl2->entries,
                    (acl->count * sizeof (struct posix_ace))))
                ret = 0;
out:
        posix_acl_destroy (this, acl2);

        return ret;
}

int 
posix_acl_dump_acl(xlator_t *this, struct posix_acl *acl)
{
	struct posix_ace *ace = NULL;
	int i = 0;

	ace = acl->entries;
	for (i = 0; i < acl->count; i++) 
	{
		gf_log (this->name, GF_LOG_TRACE, "ace tag:%5d, perm:%5d, id:%10d\n", ace->tag, ace->perm, ace->id);
		ace++;
	}	
}



int
posix_acl_ctx_update (inode_t *inode, xlator_t *this, struct stat *buf)
{
        struct posix_acl_ctx *ctx = NULL;
        int                   ret = 0;

        ctx = posix_acl_ctx_get (inode, this);
        if (!ctx) {
                ret = -1;
                goto out;
        }

        LOCK(&inode->lock);
        {
                ctx->uid   = buf->st_uid;
                ctx->gid   = buf->st_gid;
                //ctx->perm  = st_mode_from_ia (buf->ia_prot, buf->ia_type);
                ctx->perm  = buf->st_mode;
        }
        UNLOCK(&inode->lock);
out:
        return ret;
}


static int32_t
behe_acl_lookup_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
		    inode_t *inode,
		    struct stat *buf,
                    dict_t *xattr,
                    struct stat *postparent)
{
        struct posix_acl     *acl_access = NULL;
        struct posix_acl     *acl_default = NULL;
        struct posix_acl     *old_access = NULL;
        struct posix_acl     *old_default = NULL;
        data_t               *data = NULL;
        int                   ret = 0;
        dict_t               *my_xattr = NULL;
	struct posix_acl     *dump_acl=NULL;
		
	if (op_ret != 0)
		goto unwind;

        ret = posix_acl_get (inode, this, &old_access, &old_default);

	data = dict_get (xattr, POSIX_ACL_ACCESS_XATTR);
	if (!data)
                goto acl_default;

        if (old_access &&
            posix_acl_matches_xattr (this, old_access, data->data,
                                     data->len)) {
gf_log (this->name, GF_LOG_DEBUG, "acl access\n");
                acl_access = posix_acl_ref (this, old_access);
        } else {
                acl_access = posix_acl_from_xattr (this, data->data,
                                                   data->len);
        }

acl_default:	
	data = dict_get (xattr, POSIX_ACL_DEFAULT_XATTR);
        if (!data)
                goto acl_set;

        if (old_default &&
            posix_acl_matches_xattr (this, old_default, data->data,
                                     data->len)) {
gf_log (this->name, GF_LOG_DEBUG, "acl default\n");
                acl_default = posix_acl_ref (this, old_default);
        } else {
                acl_default = posix_acl_from_xattr (this, data->data,
                                                    data->len);
        }

acl_set:
gf_log (this->name, GF_LOG_DEBUG, "lookup mode %o\n", buf->st_mode);
        posix_acl_ctx_update (inode, this, buf);

        ret = posix_acl_set (inode, this, acl_access, acl_default);

unwind:
	my_xattr = frame->local;
	frame->local = NULL;
	STACK_UNWIND_STRICT (lookup, frame, op_ret, op_errno, inode, buf, xattr,
                             postparent);
	if (acl_access)
		posix_acl_unref (this, acl_access);
        if (acl_default)
                posix_acl_unref (this, acl_default);
        if (old_access)
                posix_acl_unref (this, old_access);
        if (old_default)
                posix_acl_unref (this, old_default);
        if (my_xattr)
                dict_unref (my_xattr);
	return 0;
}

int32_t
behe_acl_lookup (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc,
		dict_t *xattr)
{
	int      ret = 0;
        dict_t  *my_xattr = NULL;

        if (!loc->parent)
                /* lookup of / is always permitted */
                goto green;

	/* get parent's acl */
	if (acl_permits (frame, loc->parent, POSIX_ACL_EXECUTE))
		goto green;
	else
		goto red;
	
green:
	if (xattr) {
		my_xattr = dict_ref (xattr);
	} else {
		my_xattr = dict_new ();
	}

	ret = dict_set_int8 (my_xattr, POSIX_ACL_ACCESS_XATTR, 0);
        ret = dict_set_int8 (my_xattr, POSIX_ACL_DEFAULT_XATTR, 0);
	
	frame->local = my_xattr;
	STACK_WIND (frame,
		    behe_acl_lookup_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->lookup,
		    loc,
		    my_xattr);
	return 0;
red:
        STACK_UNWIND_STRICT (lookup, frame, -1, EACCES, NULL, NULL, NULL,
                             NULL);

        return 0;
}

int32_t
behe_acl_forget (xlator_t *this,
		inode_t *inode)
{
	return 0;
}

static int32_t
behe_acl_stat_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
		  struct stat *buf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      buf);
	return 0;
}

int32_t
behe_acl_stat (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *loc)
{
	STACK_WIND (frame,
		    behe_acl_stat_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->stat,
		    loc);
	return 0;
}

static int32_t
behe_acl_truncate_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno,
		      struct stat *prebuf,
                      struct stat *postbuf)
{
        STACK_UNWIND_STRICT (truncate, frame, op_ret, op_errno, prebuf, postbuf);
	return 0;
}

int32_t
behe_acl_truncate (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  off_t offset)
{
        if (acl_permits (frame, loc->inode, POSIX_ACL_WRITE))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, behe_acl_truncate_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->truncate,
                    loc, offset);
        return 0;
red:
        STACK_UNWIND_STRICT (truncate, frame, -1, EACCES, NULL, NULL);
	return 0;
}

static int32_t
behe_acl_ftruncate_cbk (call_frame_t *frame,
		       void *cookie,
		       xlator_t *this,
		       int32_t op_ret,
		       int32_t op_errno,
		       struct stat *prebuf,
                       struct stat *postbuf)
{
        STACK_UNWIND_STRICT (ftruncate, frame, op_ret, op_errno,
                             prebuf, postbuf);
	return 0;
}

int32_t
behe_acl_ftruncate (call_frame_t *frame,
		   xlator_t *this,
		   fd_t *fd,
		   off_t offset)
{
        if (__is_fuse_call (frame))
                goto green;

        if (acl_permits (frame, fd->inode, POSIX_ACL_WRITE))
                goto green;
        else
                goto red;

green:
        STACK_WIND (frame, behe_acl_ftruncate_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->ftruncate,
                    fd, offset);
        return 0;
red:
        STACK_UNWIND_STRICT (ftruncate, frame, -1, EACCES, NULL, NULL);
	return 0;
}

static int32_t
behe_acl_access_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno);
	return 0;
}

int32_t
behe_acl_access (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc,
		int32_t mask)
{
        int  op_ret = 0;
        int  op_errno = 0;
        int  perm = 0;
        int  mode = 0;
        int  is_fuse_call = 0;

        is_fuse_call = __is_fuse_call (frame);

        if (mask & R_OK)
                perm |= POSIX_ACL_READ;
        if (mask & W_OK)
                perm |= POSIX_ACL_WRITE;
        if (mask & X_OK)
                perm |= POSIX_ACL_EXECUTE;
        if (!mask) {
                goto unwind;
        }
        if (!perm) {
                op_ret = -1;
                op_errno = EINVAL;
                goto unwind;
        }

        if (is_fuse_call) {
                mode = acl_permits (frame, loc->inode, perm);
                if (mode) {
                        op_ret = 0;
                        op_errno = 0;
                } else {
                        op_ret = -1;
                        op_errno = EACCES;
                }
        } else {
                if (perm & POSIX_ACL_READ) {
                        if (acl_permits (frame, loc->inode, POSIX_ACL_READ))
                                mode |= POSIX_ACL_READ;
                }

                if (perm & POSIX_ACL_WRITE) {
                        if (acl_permits (frame, loc->inode, POSIX_ACL_WRITE))
                                mode |= POSIX_ACL_WRITE;
                }

                if (perm & POSIX_ACL_EXECUTE) {
                        if (acl_permits (frame, loc->inode, POSIX_ACL_EXECUTE))
                                mode |= POSIX_ACL_EXECUTE;
                }
        }

unwind:
        if (is_fuse_call)
                STACK_UNWIND_STRICT (access, frame, op_ret, op_errno);
        else
                STACK_UNWIND_STRICT (access, frame, 0, mode);
        return 0;
}


static int32_t
behe_acl_readlink_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno,
		      const char *path,
                      struct stat *buf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      path,
                      buf);
	return 0;
}

int32_t
behe_acl_readlink (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  size_t size)
{
	STACK_WIND (frame,
		    behe_acl_readlink_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->readlink,
		    loc,
		    size);
	return 0;
}

static int32_t
behe_acl_newinode_fail_unlink_cbk (call_frame_t *frame,
                    void *cookie,
                    xlator_t *this,
                    int32_t op_ret,
                    int32_t op_errno,
                    struct stat *preparent,
                    struct stat *postparent)
{
        inode_t          *local_inode = NULL;
        fd_t             *lfd = NULL;
        behe_acl_local_t        *local = frame->local;

        local_inode = local->inode;
        lfd = local->fd;
        loc_wipe (&local->loc);

        STACK_UNWIND (frame, local->op_ret, local->op_errno,
                        local->inode, &local->stbuf,
                        &local->preparent, &local->postparent);

        if (local_inode)
                inode_unref (local_inode);
        if (lfd)
                fd_unref (lfd);
}

static int32_t
behe_acl_newinode_setxattr_cbk (call_frame_t *frame,
                    void *cookie,
                    xlator_t *this,
                    int32_t op_ret,
                    int32_t op_errno)
{
        inode_t          *local_inode = NULL;
        fd_t             *lfd = NULL;
        behe_acl_local_t        *local = frame->local;

        LOCK (&frame->lock);
        {
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                ((call_frame_t *)cookie)->this->name,
                                strerror (op_errno));
                        local->op_ret = -1;
                        local->op_errno = op_errno;
                }
        }
        UNLOCK (&frame->lock);

        /* setxattr failed */
        if (local->op_ret == -1) {
gf_log (this->name, GF_LOG_TRACE, "before newinode fail unlink");
                STACK_WIND (frame, behe_acl_newinode_fail_unlink_cbk,
                                FIRST_CHILD(this), FIRST_CHILD(this)->fops->unlink,
                                &local->loc);
        /* setxattr ok */
        } else {
                lfd = local->fd;
                local_inode = local->inode;
                loc_wipe (&local->loc);

gf_log (this->name, GF_LOG_TRACE, "before newinode setxattr unwind");
                STACK_UNWIND (frame, local->op_ret, local->op_errno,
                              local->inode, &local->stbuf,
                              &local->preparent, &local->postparent);

                if (local_inode)
                        inode_unref (local_inode);
                if (lfd)
                        fd_unref (lfd);
        }
}

static int32_t
behe_acl_newinode_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   inode_t *inode,
                   struct stat *buf,
                   struct stat *preparent,
                   struct stat *postparent)
{
        inode_t          *local_inode = NULL;
        fd_t             *lfd = NULL;
        behe_acl_local_t        *local = frame->local;
        dict_t                  *params = local->dict;

        LOCK (&frame->lock);
        {
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                ((call_frame_t *)cookie)->this->name,
                                strerror (op_errno));
                        local->failed = 1;
                        local->op_errno = op_errno;
                }

                if (op_ret >= 0) {
                        local->op_ret = op_ret;
                        /* Get the mapping in inode private */
                        /* Get the stat buf right */
                        if (FIRST_CHILD(this) ==
                            ((call_frame_t *)cookie)->this) {
                                local->stbuf      = *buf;
                                local->preparent  = *preparent;
                                local->postparent = *postparent;
                        }

                        local->stbuf_blocks += buf->st_blocks;
                        local->preparent_blocks  += preparent->st_blocks;
                        local->postparent_blocks += postparent->st_blocks;

                        if (local->stbuf_size < buf->st_size)
                                local->stbuf_size = buf->st_size;
                        if (local->preparent_size < preparent->st_size)
                                local->preparent_size = preparent->st_size;
                        if (local->postparent_size < postparent->st_size)
                                local->postparent_size = postparent->st_size;
                }
        }
        UNLOCK (&frame->lock);

        if (local->failed) {
                local->op_ret = -1;
        } else
                local->op_ret = op_ret;

        if (local->op_ret >= 0) {
gf_log (this->name, GF_LOG_TRACE, "before newinode setxattr cbk");
                posix_acl_ctx_update (inode, this, buf);
gf_log ("before setxattr", GF_LOG_TRACE, "mode %o", buf->st_mode);
                STACK_WIND (frame, behe_acl_newinode_setxattr_cbk,
                                FIRST_CHILD(this), FIRST_CHILD(this)->fops->setxattr,
                                &local->loc, params, XATTR_CREATE);
        /* new inode failed */
        } else {
                lfd = local->fd;
                local_inode = local->inode;
                loc_wipe (&local->loc);

gf_log (this->name, GF_LOG_TRACE, "before newinode unwind");
                STACK_UNWIND (frame, local->op_ret, local->op_errno,
                                local->inode, &local->stbuf,
                                &local->preparent, &local->postparent);

                if (local_inode)
                        inode_unref (local_inode);
                if (lfd)
                        fd_unref (lfd);
        }
        /* free acl xattr */
        dict_unref (params);
}

int32_t
behe_acl_mkdir (call_frame_t *frame,
	       xlator_t *this,
	       loc_t *loc,
	       mode_t mode)
{
        int32_t           op_errno = EINVAL;
        mode_t  newmode = 0;
        behe_acl_local_t        *local = NULL;

        newmode = mode;
        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        /* local will be freed when frame is destroyed */
        local = CALLOC (1, sizeof(*local));
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        local->op_errno = ENOTCONN;
        local->inode = inode_ref (loc->inode);
        loc_copy (&local->loc, loc);

        /* use dict to store acl */
        local->dict = get_new_dict();
        dict_ref(local->dict);
        frame->local = local;

        newmode = posix_acl_inherit_dir (this, loc, local->dict, mode);
gf_log ("mkdir", GF_LOG_TRACE, "newmode %o", newmode);

        STACK_WIND (frame, behe_acl_newinode_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->mkdir,
                    loc, newmode);
        return 0;
red:
        STACK_UNWIND_STRICT (mkdir, frame, -1, EACCES, NULL, NULL, NULL, NULL);
	return 0;
err:
        STACK_UNWIND_STRICT (mkdir, frame, -1, op_errno, NULL, NULL, NULL, NULL);
        return 0;
}

int32_t
behe_acl_mknod (call_frame_t *frame,
	       xlator_t *this,
	       loc_t *loc,
	       mode_t mode,
	       dev_t rdev)
{
        mode_t  newmode = 0;
        int32_t           op_errno = EINVAL;
        behe_acl_local_t        *local = NULL;

        newmode = mode;

        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        /* local will be freed when frame is destroyed */
        local = CALLOC (1, sizeof(*local));
        if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
        local->op_ret = -1;
        local->op_errno = ENOTCONN;
        local->inode = inode_ref (loc->inode);
        loc_copy (&local->loc, loc);

        /* use dict to store acl */
        local->dict = get_new_dict();
        dict_ref(local->dict);
        frame->local = local;

        newmode = posix_acl_inherit_file (this, loc, local->dict, mode);

        STACK_WIND (frame, behe_acl_newinode_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->mknod,
                    loc, newmode, rdev);
        return 0;
red:
        STACK_UNWIND_STRICT (mknod, frame, -1, EACCES, NULL, NULL, NULL, NULL);
	return 0;
err:	
        STACK_UNWIND_STRICT (mknod, frame, -1, op_errno, NULL, NULL, NULL, NULL);
	return 0;
}

static int32_t
behe_acl_unlink_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
                    struct stat *preparent,
                    struct stat *postparent)
{
        if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (unlink, frame, op_ret, op_errno,
                             preparent, postparent);
	return 0;
}

int32_t
behe_acl_unlink (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc)
{
        if (!sticky_permits (frame, loc->parent, loc->inode))
                goto red;

        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, behe_acl_unlink_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->unlink,
                    loc);
        return 0;
red:
        STACK_UNWIND_STRICT (unlink, frame, -1, EACCES, NULL, NULL);
	return 0;
}

static int32_t
behe_acl_rmdir_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
                   struct stat *preparent,
                   struct stat *postparent)
{
        if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (rmdir, frame, op_ret, op_errno,
                             preparent, postparent);
	return 0;
}

int32_t
behe_acl_rmdir (call_frame_t *frame,
	       xlator_t *this,
	       loc_t *loc)
{
        if (!sticky_permits (frame, loc->parent, loc->inode))
                goto red;

        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, behe_acl_rmdir_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->rmdir,
                    loc);
        return 0;
red:
        STACK_UNWIND_STRICT (rmdir, frame, -1, EACCES, NULL, NULL);
	return 0;
}


static int32_t
behe_acl_symlink_cbk (call_frame_t *frame,
		     void *cookie,
		     xlator_t *this,
		     int32_t op_ret,
		     int32_t op_errno,
		     inode_t *inode,
                     struct stat *buf,
                     struct stat *preparent,
                     struct stat *postparent)
{
        if (op_ret != 0)
                goto unwind;

        posix_acl_ctx_update (inode, this, buf);

unwind:
        STACK_UNWIND_STRICT (symlink, frame, op_ret, op_errno, inode, buf,
                             preparent, postparent);
	return 0;
}

int32_t
behe_acl_symlink (call_frame_t *frame,
		 xlator_t *this,
		 const char *linkpath,
		 loc_t *loc)
{
        int32_t           op_errno = EINVAL;
        behe_acl_local_t        *local = NULL;

        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, behe_acl_symlink_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->symlink,
                    linkpath, loc);
        return 0;
red:
        STACK_UNWIND_STRICT (mknod, frame, -1, EACCES, NULL, NULL, NULL, NULL);
        return 0;
}

static int32_t
behe_acl_rename_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
		    struct stat *buf,
                    struct stat *preoldparent,
                    struct stat *postoldparent,
                    struct stat *prenewparent,
                    struct stat *postnewparent)
{
        if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (rename, frame, op_ret, op_errno, buf,
                             preoldparent, postoldparent,
                             prenewparent, postnewparent);
	return 0;
}

int32_t
behe_acl_rename (call_frame_t *frame,
		xlator_t *this,
		loc_t *old,
		loc_t *new)
{
        if (!acl_permits (frame, old->parent, POSIX_ACL_WRITE))
                goto red;

        if (!acl_permits (frame, new->parent, POSIX_ACL_WRITE))
                goto red;

        if (!sticky_permits (frame, old->parent, old->inode))
                goto red;

        if (new->inode) {
                if (!sticky_permits (frame, new->parent, new->inode))
                        goto red;
        }

        STACK_WIND (frame, behe_acl_rename_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->rename,
                    old, new);
        return 0;
red:
        STACK_UNWIND_STRICT (rename, frame, -1, EACCES, NULL, NULL, NULL, NULL,
                             NULL);
	return 0;
}


static int32_t
behe_acl_link_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
		  inode_t *inode,
                  struct stat *buf,
                  struct stat *preparent,
                  struct stat *postparent)
{
	if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (link, frame, op_ret, op_errno, inode, buf,
                             preparent, postparent);
	return 0;
}

int32_t
behe_acl_link (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *old,
	      loc_t *new)
{
        struct posix_acl_ctx *ctx = NULL;
        int                   op_errno = 0;

        ctx = posix_acl_ctx_get (old->inode, this);
        if (!ctx) {
                op_errno = EIO;
                goto red;
        }

        if (!acl_permits (frame, new->parent, POSIX_ACL_WRITE)) {
                op_errno = EACCES;
                goto red;
        }

        STACK_WIND (frame, behe_acl_link_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->link,
                    old, new);
        return 0;
red:
        STACK_UNWIND_STRICT (link, frame, -1, op_errno, NULL, NULL, NULL, NULL);
	return 0;
}

static int32_t
behe_acl_create_fail_unlink_cbk (call_frame_t *frame,
                    void *cookie,
                    xlator_t *this,
                    int32_t op_ret,
                    int32_t op_errno,
                    struct stat *preparent,
                    struct stat *postparent)
{
        inode_t          *local_inode = NULL;
        fd_t             *lfd = NULL;
	behe_acl_local_t	*local = frame->local;

	local_inode = local->inode;
	lfd = local->fd;
	loc_wipe (&local->loc);

	STACK_UNWIND (frame, local->op_ret, local->op_errno,
			local->fd, local->inode, &local->stbuf,
			&local->preparent, &local->postparent);

	if (local_inode)
		inode_unref (local_inode);
	if (lfd)
		fd_unref (lfd);	
}

static int32_t
behe_acl_create_setxattr_cbk (call_frame_t *frame,
                    void *cookie,
                    xlator_t *this,
                    int32_t op_ret,
                    int32_t op_errno)
{
        inode_t          *local_inode = NULL;
        fd_t             *lfd = NULL;
	behe_acl_local_t	*local = frame->local;

	LOCK (&frame->lock);
        {
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                ((call_frame_t *)cookie)->this->name, 
                                strerror (op_errno));
                        local->op_ret = -1;
                        local->op_errno = op_errno;
                }
	}
	UNLOCK (&frame->lock);
	
	/* setxattr failed */
	if (local->op_ret == -1) {
gf_log (this->name, GF_LOG_TRACE, "before create fail unlink");
		STACK_WIND (frame, behe_acl_create_fail_unlink_cbk,
				FIRST_CHILD(this), FIRST_CHILD(this)->fops->unlink,
				&local->loc);
	/* setxattr ok */
	} else {
                lfd = local->fd;
                local_inode = local->inode;
                loc_wipe (&local->loc);

gf_log (this->name, GF_LOG_TRACE, "before create setxattr unwind");
                STACK_UNWIND (frame, local->op_ret, local->op_errno,
                              local->fd, local->inode, &local->stbuf,
                              &local->preparent, &local->postparent);

                if (local_inode)
                        inode_unref (local_inode);
                if (lfd)
                        fd_unref (lfd);
	}
}

static int32_t
behe_acl_create_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
		    fd_t *fd,
		    inode_t *inode,
		    struct stat *buf,
                    struct stat *preparent,
                    struct stat *postparent)
{
        inode_t          *local_inode = NULL;
        fd_t             *lfd = NULL;
	behe_acl_local_t	*local = frame->local;
	dict_t			*params = local->dict;

gf_log (this->name, GF_LOG_TRACE, "create cbk entered");
        LOCK (&frame->lock);
        {
                if (op_ret == -1) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "%s returned error %s",
                                ((call_frame_t *)cookie)->this->name, 
                                strerror (op_errno));
                        local->failed = 1;
                        local->op_errno = op_errno;
                }
		
                if (op_ret >= 0) {
                        local->op_ret = op_ret;
                        /* Get the mapping in inode private */
                        /* Get the stat buf right */
                        if (FIRST_CHILD(this) ==
                            ((call_frame_t *)cookie)->this) {
                                local->stbuf      = *buf;
                                local->preparent  = *preparent;
                                local->postparent = *postparent;
                        }

                        local->stbuf_blocks += buf->st_blocks;
                        local->preparent_blocks  += preparent->st_blocks;
                        local->postparent_blocks += postparent->st_blocks;

                        if (local->stbuf_size < buf->st_size)
                                local->stbuf_size = buf->st_size;
                        if (local->preparent_size < preparent->st_size)
                                local->preparent_size = preparent->st_size;
                        if (local->postparent_size < postparent->st_size)
                                local->postparent_size = postparent->st_size;
                }
	}
	UNLOCK (&frame->lock);

        if (local->failed) {
        	local->op_ret = -1;
	} else 
		local->op_ret = op_ret;

	/* create ok */
        if (local->op_ret >= 0) {
gf_log (this->name, GF_LOG_TRACE, "before create setxattr cbk");
		posix_acl_ctx_update (inode, this, buf);
        	STACK_WIND (frame, behe_acl_create_setxattr_cbk,
                    		FIRST_CHILD(this), FIRST_CHILD(this)->fops->setxattr,
                    		&local->loc, params, XATTR_CREATE);
	/* create failed */
	} else { 
		lfd = local->fd;
		local_inode = local->inode;
		loc_wipe (&local->loc);

gf_log (this->name, GF_LOG_TRACE, "before create unwind");
		STACK_UNWIND (frame, local->op_ret, local->op_errno,
				local->fd, local->inode, &local->stbuf,
				&local->preparent, &local->postparent);

		if (local_inode)
			inode_unref (local_inode);
                if (lfd)
                        fd_unref (lfd);
	}
	/* free acl xattr */
	dict_unref (params);
	return 0;
}

int32_t
behe_acl_create (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc,
		int32_t flags,
		mode_t mode, fd_t *fd)
{
        int32_t           op_errno = EINVAL;
        mode_t  newmode = 0;
	behe_acl_local_t	*local = NULL;
	
        newmode = mode;

        if (acl_permits (frame, loc->parent, POSIX_ACL_WRITE|POSIX_ACL_EXECUTE)) {
gf_log (this->name, GF_LOG_TRACE, "goto green");
                goto green;
	}
        else
                goto red;
green:
	/* local will be freed when frame is destroyed */
	local = CALLOC (1, sizeof(*local));
	if (!local) {
                op_errno = ENOMEM;
                goto err;
        }
	local->op_ret = -1;
        local->op_errno = ENOTCONN;
	local->inode = inode_ref (loc->inode);
	loc_copy (&local->loc, loc);
	local->fd = fd_ref (fd);

	/* use dict to store acl */
	local->dict = get_new_dict();
	dict_ref(local->dict);
	frame->local = local;

        newmode = posix_acl_inherit_file (this, loc, local->dict, mode);

gf_log (this->name, GF_LOG_TRACE, "before cbk");
        STACK_WIND (frame, behe_acl_create_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->create,
                    loc, flags, newmode, fd);
        return 0;
red:
        STACK_UNWIND_STRICT (create, frame, -1, EACCES, NULL, NULL, NULL, NULL, NULL);
	return 0;
err:
        STACK_UNWIND_STRICT (create, frame, -1, op_errno, NULL, NULL, NULL, NULL, NULL);
	return 0;
}

static int32_t
behe_acl_open_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
		  fd_t *fd)
{
	STACK_UNWIND_STRICT (open, frame, op_ret, op_errno, fd);
	return 0;
}

int32_t
behe_acl_open (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *loc,
	      int32_t flags, fd_t *fd,
              int32_t wbflags)
{
        int perm = 0;

        switch (flags & O_ACCMODE) {
        case O_RDONLY:
                perm = POSIX_ACL_READ;
                break;
        case O_WRONLY:
        case O_APPEND:
        case O_TRUNC:
                perm = POSIX_ACL_WRITE;
                break;
        case O_RDWR:
                perm = POSIX_ACL_READ|POSIX_ACL_WRITE;
                break;
        }
        if (acl_permits (frame, loc->inode, perm)) {
                goto green;
	}
        else {
                goto red;
	}
green:
        STACK_WIND (frame, behe_acl_open_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->open,
                    loc, flags, fd, wbflags);
        return 0;
red:
        STACK_UNWIND_STRICT (open, frame, -1, EACCES, NULL);
        return 0;
}

static int32_t
behe_acl_readv_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct iovec *vector,
		   int32_t count,
		   struct stat *stbuf,
                   struct iobref *iobref)
{
        STACK_UNWIND_STRICT (readv, frame, op_ret, op_errno, vector, count,
                             stbuf, iobref);
	return 0;
}

int32_t
behe_acl_readv (call_frame_t *frame,
	       xlator_t *this,
	       fd_t *fd,
	       size_t size,
	       off_t offset)
{
        if (__is_fuse_call (frame))
                goto green;

        if (acl_permits (frame, fd->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;

green:
        STACK_WIND (frame, behe_acl_readv_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->readv,
                    fd, size, offset);
        return 0;
red:
        STACK_UNWIND_STRICT (readv, frame, -1, EACCES, NULL, 0, NULL, NULL);
	return 0;
}

#ifndef IOCTL /* wanghy add */
static int32_t
behe_acl_ioctl_cbk (call_frame_t *frame,
                   void *cookie,
                   xlator_t *this,
                   int32_t op_ret,
                   int32_t op_errno,
                   uint32_t cmd,
                   uint64_t retaddr)
{

        STACK_UNWIND (frame,
                      op_ret,
                      op_errno,
                      cmd,
                      retaddr);

        return 0;
}

int32_t
behe_acl_ioctl (call_frame_t *frame,
               xlator_t *this,
               fd_t *fd,
               uint32_t cmd,
               uint64_t arg)
{

        STACK_WIND (frame,
                    behe_acl_ioctl_cbk,
                    FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->ioctl,
                    fd,
                    cmd,
                    arg);

        return 0;
}
#endif

static int32_t
behe_acl_writev_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
                    struct stat *prebuf,
		    struct stat *postbuf)
{
	STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno,
				prebuf, postbuf);
	return 0;
}

int32_t
behe_acl_writev (call_frame_t *frame,
		xlator_t *this,
		fd_t *fd,
		struct iovec *vector,
		int32_t count,
		off_t off,
                struct iobref *iobref)
{
        if (__is_fuse_call (frame))
                goto green;

        if (acl_permits (frame, fd->inode, POSIX_ACL_WRITE))
                goto green;
        else
                goto red;

green:
        STACK_WIND (frame, behe_acl_writev_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->writev,
                    fd, vector, count, off, iobref);
        return 0;
red:
        STACK_UNWIND_STRICT (writev, frame, -1, EACCES, NULL, NULL);
	return 0;
}

static int32_t
behe_acl_flush_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno);
	return 0;
}

int32_t
behe_acl_flush (call_frame_t *frame,
	       xlator_t *this,
	       fd_t *fd)
{
	STACK_WIND (frame,
		    behe_acl_flush_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->flush,
		    fd);
	return 0;
}


static int32_t
behe_acl_fsync_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
                   struct stat *prebuf,
                   struct stat *postbuf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
                      prebuf,
                      postbuf);
	return 0;
}

int32_t
behe_acl_fsync (call_frame_t *frame,
	       xlator_t *this,
	       fd_t *fd,
	       int32_t flags)
{
	STACK_WIND (frame,
		    behe_acl_fsync_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fsync,
		    fd,
		    flags);
	return 0;
}

static int32_t
behe_acl_fstat_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct stat *buf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      buf);
	return 0;
}

int32_t
behe_acl_fstat (call_frame_t *frame,
	       xlator_t *this,
	       fd_t *fd)
{
	STACK_WIND (frame,
		    behe_acl_fstat_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fstat,
		    fd);
	return 0;
}

static int32_t
behe_acl_opendir_cbk (call_frame_t *frame,
		     void *cookie,
		     xlator_t *this,
		     int32_t op_ret,
		     int32_t op_errno,
		     fd_t *fd)
{
	STACK_UNWIND_STRICT (opendir, frame, op_ret, op_errno, fd);
}

int32_t
behe_acl_opendir (call_frame_t *frame,
		 xlator_t *this,
		 loc_t *loc, fd_t *fd)
{
gf_log (this->name, GF_LOG_TRACE, "acl_opendir entered\n");
	if (acl_permits (frame, loc->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, behe_acl_opendir_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->opendir,
                    loc, fd);
        return 0;
red:
        STACK_UNWIND_STRICT (opendir, frame, -1, EACCES, NULL);
        return 0;
}


static int32_t
behe_acl_getdents_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno,
		      dir_entry_t *entries,
		      int32_t count)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      entries,
		      count);
	return 0;
}

int32_t
behe_acl_getdents (call_frame_t *frame,
		  xlator_t *this,
		  fd_t *fd,
		  size_t size,
		  off_t offset,
		  int32_t flag)
{
	STACK_WIND (frame,
		    behe_acl_getdents_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->getdents,
		    fd,
		    size,
		    offset,
		    flag);
	return 0;
}


static int32_t
behe_acl_setdents_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno);
	return 0;
}

int32_t
behe_acl_setdents (call_frame_t *frame,
		  xlator_t *this,
		  fd_t *fd,
		  int32_t flags,
		  dir_entry_t *entries,
		  int32_t count)
{
	STACK_WIND (frame,
		    behe_acl_setdents_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->setdents,
		    fd,
		    flags,
		    entries,
		    count);
	return 0;
}


static int32_t
behe_acl_fsyncdir_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno);
	return 0;
}

int32_t
behe_acl_fsyncdir (call_frame_t *frame,
		  xlator_t *this,
		  fd_t *fd,
		  int32_t flags)
{
	STACK_WIND (frame,
		    behe_acl_fsyncdir_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fsyncdir,
		    fd,
		    flags);
	return 0;
}


static int32_t
behe_acl_statfs_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
		    struct statvfs *buf)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      buf);
	return 0;
}

int32_t
behe_acl_statfs (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc)
{
	STACK_WIND (frame,
		    behe_acl_statfs_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->statfs,
		    loc);
	return 0;
}

int
setxattr_scrutiny (call_frame_t *frame, inode_t *inode, dict_t *xattr)
{
        struct posix_acl_ctx   *ctx = NULL;
        int                     found = 0;

        if (frame->root->uid == 0)
                return 0;

        ctx = posix_acl_ctx_get (inode, frame->this);
        if (!ctx)
                return EIO;

        if (dict_get (xattr, POSIX_ACL_ACCESS_XATTR)) {
                found = 1;
                if (!frame_is_user (frame, ctx->uid))
                        return EPERM;
        }

        if (dict_get (xattr, POSIX_ACL_DEFAULT_XATTR)) {
                found = 1;
                if (!frame_is_user (frame, ctx->uid))
                        return EPERM;
        }

        if (!found && !acl_permits (frame, inode, POSIX_ACL_WRITE))
                return EACCES;

        return 0;
}

struct posix_acl *
posix_acl_xattr_update (xlator_t *this, inode_t *inode, dict_t *xattr,
                        char *name, struct posix_acl *old)
{
        struct  posix_acl      *acl = NULL;
        data_t                 *data = NULL;

        data = dict_get (xattr, name);
        if (data) {
                acl = posix_acl_from_xattr (this, data->data,
                                            data->len);
        }

        if (!acl && old)
                acl = posix_acl_ref (this, old);

        return acl;
}

int
posix_acl_setxattr_update (xlator_t *this, inode_t *inode, dict_t *xattr)
{
        struct posix_acl     *acl_access = NULL;
        struct posix_acl     *acl_default = NULL;
        struct posix_acl     *old_access = NULL;
        struct posix_acl     *old_default = NULL;
        struct posix_acl_ctx *ctx = NULL;
        int                   ret = 0;
        mode_t                mode = 0;

        ctx = posix_acl_ctx_get (inode, this);
        if (!ctx)
                return -1;

        ret = posix_acl_get (inode, this, &old_access, &old_default);

        acl_access = posix_acl_xattr_update (this, inode, xattr,
                                             POSIX_ACL_ACCESS_XATTR,
                                             old_access);

        acl_default = posix_acl_xattr_update (this, inode, xattr,
                                              POSIX_ACL_DEFAULT_XATTR,
                                              old_default);

        ret = posix_acl_set (inode, this, acl_access, acl_default);

        if (acl_access && acl_access != old_access) {
                mode = posix_acl_access_set_mode (acl_access, ctx);
        }

        if (acl_access)
                posix_acl_unref (this, acl_access);
        if (acl_default)
                posix_acl_unref (this, acl_default);
        if (old_access)
                posix_acl_unref (this, old_access);
        if (old_default)
                posix_acl_unref (this, old_default);

        return 0;
}

static int32_t
behe_acl_setxattr_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno)
{
	STACK_UNWIND_STRICT (setxattr,
				frame,
		      		op_ret,
		      		op_errno);
	return 0;
}

int32_t
behe_acl_setxattr (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  dict_t *dict,
		  int32_t flags)
{
        int  op_errno = 0;

        op_errno = setxattr_scrutiny (frame, loc->inode, dict);

        if (op_errno != 0)
                goto red;

        posix_acl_setxattr_update (this, loc->inode, dict);

        STACK_WIND (frame, behe_acl_setxattr_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->setxattr,
                    loc, dict, flags);
        return 0;
red:
        STACK_UNWIND_STRICT (setxattr, frame, -1, op_errno);
	return 0;
}


static int32_t
behe_acl_fsetxattr_cbk (call_frame_t *frame,
                       void *cookie,
                       xlator_t *this,
                       int32_t op_ret,
                       int32_t op_errno)
{
	STACK_UNWIND_STRICT(fsetxattr,
				frame,
		      		op_ret,
		      		op_errno);
	return 0;
}

int32_t
behe_acl_fsetxattr (call_frame_t *frame,
                   xlator_t *this,
                   fd_t *fd,
                   dict_t *dict,
                   int32_t flags)
{
        int  op_errno = 0;

        op_errno = setxattr_scrutiny (frame, fd->inode, dict);

        if (op_errno != 0)
                goto red;

        posix_acl_setxattr_update (this, fd->inode, dict);

        STACK_WIND (frame, behe_acl_fsetxattr_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->fsetxattr,
                    fd, dict, flags);
        return 0;
red:
        STACK_UNWIND_STRICT (fsetxattr, frame, -1, op_errno);
	return 0;
}


static int32_t
behe_acl_fgetxattr_cbk (call_frame_t *frame,
                       void *cookie,
                       xlator_t *this,
                       int32_t op_ret,
                       int32_t op_errno,
                       dict_t *xattr)
{
	STACK_UNWIND_STRICT (fgetxattr, frame, op_ret, op_errno, xattr);
	return 0;
}


int32_t
behe_acl_fgetxattr (call_frame_t *frame,
                   xlator_t *this,
                   fd_t *fd,
                   const char *name)
{
        if (whitelisted_xattr (name))
                goto green;

        if (acl_permits (frame, fd->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, behe_acl_fgetxattr_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->fgetxattr,
                    fd, name);
        return 0;
red:
        STACK_UNWIND_STRICT (fgetxattr, frame, -1, EACCES, NULL);
	return 0;
}

static int32_t
behe_acl_getxattr_cbk (call_frame_t *frame,
                      void *cookie,
                      xlator_t *this,
                      int32_t op_ret,
                      int32_t op_errno,
                      dict_t *xattr)
{
	STACK_UNWIND_STRICT (getxattr, frame, op_ret, op_errno, xattr);
	return 0;
}

int32_t
behe_acl_getxattr (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  const char *name)
{
        if (whitelisted_xattr (name))
                goto green;

        if (acl_permits (frame, loc->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, behe_acl_getxattr_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->getxattr,
                    loc, name);
        return 0;
red:
        STACK_UNWIND_STRICT (getxattr, frame, -1, EACCES, NULL);
	return 0;
}

int32_t
behe_acl_xattrop_cbk (call_frame_t *frame,
		     void *cookie,
		     xlator_t *this,
		     int32_t op_ret,
		     int32_t op_errno,
		     dict_t *dict)
{
	STACK_UNWIND (frame, op_ret, op_errno, dict);
	return 0;
}

int32_t
behe_acl_xattrop (call_frame_t *frame,
		 xlator_t *this,
		 loc_t *loc,
		 gf_xattrop_flags_t flags,
		 dict_t *dict)
{
	STACK_WIND (frame,
		    behe_acl_xattrop_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->xattrop,
		    loc,
		    flags,
		    dict);
	return 0;
}

int32_t
behe_acl_fxattrop_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno,
		      dict_t *dict)
{
	STACK_UNWIND (frame, op_ret, op_errno, dict);
	return 0;
}

int32_t
behe_acl_fxattrop (call_frame_t *frame,
		  xlator_t *this,
		  fd_t *fd,
		  gf_xattrop_flags_t flags,
		  dict_t *dict)
{
	STACK_WIND (frame,
		    behe_acl_fxattrop_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fxattrop,
		    fd,
		    flags,
		    dict);
	return 0;
}


static int32_t
behe_acl_removexattr_cbk (call_frame_t *frame,
			 void *cookie,
			 xlator_t *this,
			 int32_t op_ret,
			 int32_t op_errno)
{
        STACK_UNWIND_STRICT (removexattr, frame, op_ret, op_errno);
	return 0;
}

int32_t
behe_acl_removexattr (call_frame_t *frame,
		     xlator_t *this,
		     loc_t *loc,
		     const char *name)
{
        struct  posix_acl_ctx  *ctx = NULL;
        int                     op_errno = EACCES;

        if (frame_is_user (frame, 0))
                goto green;

        ctx = posix_acl_ctx_get (loc->inode, this);
        if (!ctx) {
                op_errno = EIO;
                goto red;
        }

        if (whitelisted_xattr (name)) {
                if (!frame_is_user (frame, ctx->uid)) {
                        op_errno = EPERM;
                        goto red;
                }
        }

        if (acl_permits (frame, loc->inode, POSIX_ACL_WRITE))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, behe_acl_removexattr_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->removexattr,
                    loc, name);
        return 0;
red:
        STACK_UNWIND_STRICT (removexattr, frame, -1, op_errno);
	return 0;
}

static int32_t
behe_acl_lk_cbk (call_frame_t *frame,
		void *cookie,
		xlator_t *this,
		int32_t op_ret,
		int32_t op_errno,
		struct flock *lock)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      lock);
	return 0;
}

int32_t
behe_acl_lk (call_frame_t *frame,
	    xlator_t *this,
	    fd_t *fd,
	    int32_t cmd,
	    struct flock *lock)
{
	STACK_WIND (frame,
		    behe_acl_lk_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->lk,
		    fd,
		    cmd,
		    lock);
	return 0;
}


static int32_t
behe_acl_inodelk_cbk (call_frame_t *frame, void *cookie,
		     xlator_t *this, int32_t op_ret, int32_t op_errno)

{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int32_t
behe_acl_inodelk (call_frame_t *frame, xlator_t *this,
		 const char *volume, loc_t *loc, int32_t cmd, 
                 struct flock *lock)
{
	STACK_WIND (frame,
		    behe_acl_inodelk_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->inodelk,
		    volume, loc, cmd, lock);
	return 0;
}


static int32_t
behe_acl_finodelk_cbk (call_frame_t *frame, void *cookie,
		      xlator_t *this, int32_t op_ret, int32_t op_errno)

{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int32_t
behe_acl_finodelk (call_frame_t *frame, xlator_t *this,
		  const char *volume, fd_t *fd, int32_t cmd, struct flock *lock)
{
	STACK_WIND (frame,
		    behe_acl_finodelk_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->finodelk,
		    volume, fd, cmd, lock);
	return 0;
}


static int32_t
behe_acl_entrylk_cbk (call_frame_t *frame, void *cookie,
		     xlator_t *this, int32_t op_ret, int32_t op_errno)

{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}

int32_t
behe_acl_entrylk (call_frame_t *frame, xlator_t *this,
		 const char *volume, loc_t *loc, const char *basename,
		 entrylk_cmd cmd, entrylk_type type)
{
	STACK_WIND (frame, behe_acl_entrylk_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->entrylk,
		    volume, loc, basename, cmd, type);
	return 0;
}

static int32_t
behe_acl_fentrylk_cbk (call_frame_t *frame, void *cookie,
		      xlator_t *this, int32_t op_ret, int32_t op_errno)

{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}

int32_t
behe_acl_fentrylk (call_frame_t *frame, xlator_t *this,
		  const char *volume, fd_t *fd, const char *basename,
		  entrylk_cmd cmd, entrylk_type type)
{
	STACK_WIND (frame, behe_acl_fentrylk_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fentrylk,
		    volume, fd, basename, cmd, type);
	return 0;
}


/* Management operations */

static int32_t
behe_acl_stats_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct xlator_stats *stats)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      stats);
	return 0;
}


int32_t
behe_acl_stats (call_frame_t *frame,
	       xlator_t *this,
	       int32_t flags)
{
	STACK_WIND (frame,
		    behe_acl_stats_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->mops->stats,
		    flags);
	return 0;
}

static int32_t
behe_acl_getspec_cbk (call_frame_t *frame,
		     void *cookie,
		     xlator_t *this,
		     int32_t op_ret,
		     int32_t op_errno,
		     char *spec_data)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      spec_data);
	return 0;
}


int32_t
behe_acl_getspec (call_frame_t *frame,
		 xlator_t *this,
		 const char *key,
		 int32_t flags)
{
	STACK_WIND (frame,
		    behe_acl_getspec_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->mops->getspec,
		    key, flags);
	return 0;
}


static int32_t
behe_acl_log_cbk (call_frame_t *frame,
                 void *cookie,
                 xlator_t *this,
                 int32_t op_ret,
                 int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int32_t
behe_acl_log (call_frame_t *frame,
             xlator_t *this,
             const char *msg)
{
	STACK_WIND (frame,
		    behe_acl_log_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->mops->log,
		    msg);
	return 0;
}


static int32_t
behe_acl_checksum_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno,
		      uint8_t *file_checksum,
		      uint8_t *dir_checksum)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      file_checksum,
		      dir_checksum);
	return 0;
}


int32_t
behe_acl_checksum (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  int32_t flag)
{
	STACK_WIND (frame,
		    behe_acl_checksum_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->checksum,
		    loc,
		    flag);
	return 0;
}


static int32_t
behe_acl_rchecksum_cbk (call_frame_t *frame,
                       void *cookie,
                       xlator_t *this,
                       int32_t op_ret,
                       int32_t op_errno,
                       uint32_t weak_checksum,
                       uint8_t *strong_checksum)
{
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      weak_checksum,
		      strong_checksum);
	return 0;
}


int32_t
behe_acl_rchecksum (call_frame_t *frame,
                   xlator_t *this,
                   fd_t *fd, off_t offset,
                   int32_t len)
{
	STACK_WIND (frame,
		    behe_acl_rchecksum_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->rchecksum,
		    fd, offset, len);
	return 0;
}


int32_t
behe_acl_readdir_cbk (call_frame_t *frame,
		     void *cookie,
		     xlator_t *this,
		     int32_t op_ret,
		     int32_t op_errno,
		     gf_dirent_t *entries)
{
        if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (readdir, frame, op_ret, op_errno, entries);
        return 0;
}


int32_t
behe_acl_readdirp_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno,
		      gf_dirent_t *entries)
{
        if (op_ret != 0)
                goto unwind;
unwind:
        STACK_UNWIND_STRICT (readdirp, frame, op_ret, op_errno, entries);
        return 0;
}

int32_t
behe_acl_readdir (call_frame_t *frame,
		 xlator_t *this,
		 fd_t *fd,
		 size_t size,
		 off_t off)
{
        if (acl_permits (frame, fd->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, behe_acl_readdir_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->readdir,
                    fd, size, off);
        return 0;
red:
        STACK_UNWIND_STRICT (readdir, frame, -1, EACCES, NULL);

        return 0;
}


int32_t
behe_acl_readdirp (call_frame_t *frame,
		  xlator_t *this,
		  fd_t *fd,
		  size_t size,
		  off_t off)
{
        if (acl_permits (frame, fd->inode, POSIX_ACL_READ))
                goto green;
        else
                goto red;
green:
        STACK_WIND (frame, behe_acl_readdirp_cbk,
                    FIRST_CHILD(this), FIRST_CHILD(this)->fops->readdirp,
                    fd, size, off);
        return 0;
red:
        STACK_UNWIND_STRICT (readdirp, frame, -1, EACCES, NULL);

        return 0;
}

int32_t
behe_acl_lock_notify_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
			 int32_t op_ret, int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int32_t
behe_acl_lock_fnotify_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
			  int32_t op_ret, int32_t op_errno)
{
	STACK_UNWIND (frame, op_ret, op_errno);
	return 0;
}


int32_t
behe_acl_lock_notify (call_frame_t *frame, xlator_t *this, 
		     loc_t *loc, int32_t timeout)
{
	STACK_WIND (frame, 
		    behe_acl_lock_notify_cbk,
		    FIRST_CHILD (this),
		    FIRST_CHILD (this)->fops->lock_notify,
		    loc, timeout);
	return 0;
}


int32_t
behe_acl_lock_fnotify (call_frame_t *frame, xlator_t *this, 
		      fd_t *fd, int32_t timeout)
{
	STACK_WIND (frame, 
		    behe_acl_lock_notify_cbk,
		    FIRST_CHILD (this),
		    FIRST_CHILD (this)->fops->lock_fnotify,
		    fd, timeout);
	return 0;
}


/* notify */
int
behe_acl_notify (xlator_t *this, int32_t event, void *data, ...)
{
	switch (event)
	{
	case GF_EVENT_PARENT_UP:
	{
		xlator_list_t *list = this->children;

		while (list)
		{
			xlator_notify (list->xlator, event, this);
			list = list->next;
		}
	}
	break;
	case GF_EVENT_CHILD_DOWN:
	case GF_EVENT_CHILD_UP:
	behe_acl:
	{
		xlator_list_t *parent = this->parents;
		while (parent) {
                        if (parent->xlator->ready)
                                xlator_notify (parent->xlator, event,
                                               this, NULL);
			parent = parent->next;
		}
	}
	}

	return 0;
}

int32_t
behe_acl_releasedir (xlator_t *this,
		    fd_t *fd)
{
	return 0;
}

int32_t
behe_acl_release (xlator_t *this,
		 fd_t *fd)
{
	return 0;
}

int32_t
behe_acl_setattr_cbk (call_frame_t *frame,
                     void *cookie,
                     xlator_t *this,
                     int32_t op_ret,
                     int32_t op_errno,
                     struct stat *statpre,
                     struct stat *statpost)
{
	STACK_UNWIND (frame, op_ret, op_errno, statpre, statpost);
	return 0;
}

int32_t
behe_acl_setattr (call_frame_t *frame,
                 xlator_t *this,
                 loc_t *loc,
                 struct stat *stbuf,
                 int32_t valid)
{
	STACK_WIND (frame,
		    behe_acl_setattr_cbk,
		    FIRST_CHILD (this),
		    FIRST_CHILD (this)->fops->setattr,
		    loc, stbuf, valid);
	return 0;
}

int32_t
behe_acl_fsetattr_cbk (call_frame_t *frame,
                      void *cookie,
                      xlator_t *this,
                      int32_t op_ret,
                      int32_t op_errno,
                      struct stat *statpre,
                      struct stat *statpost)
{
	STACK_UNWIND (frame, op_ret, op_errno, statpre, statpost);
	return 0;
}

int32_t
behe_acl_fsetattr (call_frame_t *frame,
                  xlator_t *this,
                  fd_t *fd,
                  struct stat *stbuf,
                  int32_t valid)
{
	STACK_WIND (frame,
		    behe_acl_fsetattr_cbk,
		    FIRST_CHILD (this),
		    FIRST_CHILD (this)->fops->fsetattr,
		    fd, stbuf, valid);
	return 0;
}

void 
fini (xlator_t *this)
{
	return;
}

int
init (xlator_t *this)
{
	struct posix_acl_conf   *conf = NULL;
        struct posix_acl        *minacl = NULL;
        struct posix_ace        *minace = NULL;

	conf = CALLOC (1, sizeof (*conf));
        if (!conf) {
                gf_log (this->name, GF_LOG_ERROR,
                        "out of memory");
                return -1;
        }

        LOCK_INIT (&conf->acl_lock);

        this->private = conf;

	minacl = posix_acl_new (this, 3);
        if (!minacl)
                return -1;

        minace = minacl->entries;
        minace[0].tag = POSIX_ACL_USER_OBJ;
        minace[1].tag = POSIX_ACL_GROUP_OBJ;
        minace[2].tag = POSIX_ACL_OTHER;

        conf->minimal_acl = minacl;

        return 0;
	return 0;
}

struct xlator_fops fops = {
	.lookup		= behe_acl_lookup,
        .open             = behe_acl_open,
        .readv            = behe_acl_readv,
        .writev           = behe_acl_writev,
        .ftruncate        = behe_acl_ftruncate,
        .access           = behe_acl_access,
        .truncate         = behe_acl_truncate,
        .mkdir            = behe_acl_mkdir,
        .mknod            = behe_acl_mknod,
        .create           = behe_acl_create,
        .symlink          = behe_acl_symlink,
        .unlink           = behe_acl_unlink,
        .rmdir            = behe_acl_rmdir,
        .rename           = behe_acl_rename,
        .link             = behe_acl_link,
        .opendir          = behe_acl_opendir,
        .readdir          = behe_acl_readdir,
        .readdirp         = behe_acl_readdirp,
#if 0
        .setattr          = behe_acl_setattr,
        .fsetattr         = behe_acl_fsetattr,
        .setxattr         = behe_acl_setxattr,
        .fsetxattr        = behe_acl_fsetxattr,
#endif
        .getxattr         = behe_acl_getxattr,
        .fgetxattr        = behe_acl_fgetxattr,
        .removexattr      = behe_acl_removexattr,
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};


