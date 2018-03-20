/*
  Copyright (c) 2007-2009 LW, Inc. <http://www.lw.com>
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

#include "inode.h"
#include "common-utils.h"
#include "statedump.h"
#include <pthread.h>
#include <sys/types.h>
#include <stdint.h>
#include "list.h"
#include <time.h>
#include <assert.h>

#ifndef behe_100825
char *posix_path;
int posix_path_len;
#endif

/* TODO:
   move latest accessed dentry to list_head of inode
*/

#define INODE_DUMP_LIST(head, key_buf, key_prefix, list_type)           \
        {                                                               \
                int i = 1;                                              \
                inode_t *inode = NULL;                                  \
                list_for_each_entry (inode, head, list) {               \
                        gf_proc_dump_build_key(key_buf, key_prefix, "%s.%d",list_type, \
                                               i++);                    \
                        gf_proc_dump_add_section(key_buf);              \
                        inode_dump(inode, key);                         \
                }                                                       \
        }

static inode_t *
__inode_unref (inode_t *inode);

static int
inode_table_prune (inode_table_t *table);

static int
hash_dentry (inode_t *parent, const char *name, int mod)
{
        int hash = 0;
        int ret = 0;

        hash = *name;
        if (hash) {
                for (name += 1; *name != '\0'; name++) {
                        hash = (hash << 5) - hash + *name;
                }
        }
        ret = (hash + (unsigned long)parent) % mod;

        return ret;
}


static int
hash_name (ino_t par, const char *name, int mod)
{
        int hash = 0;
        int ret = 0;

        hash = *name;
        if (hash) {
                for (name += 1; *name != '\0'; name++) {
                        hash = (hash << 5) - hash + *name;
                }
        }
        ret = (hash + par) % mod;

        return ret;
}


static int
hash_inode (ino_t ino, int mod)
{
        int hash = 0;

        hash = ino % mod;

        return hash;
}


static void
__dentry_hash (dentry_t *dentry)
{
        inode_table_t   *table = NULL;
        int              hash = 0;

        table = dentry->inode->table;
        hash = hash_dentry (dentry->parent, dentry->name,
                            table->hashsize);

        list_del_init (&dentry->hash);
        list_add (&dentry->hash, &table->name_hash[hash]);
}


static int
__is_dentry_hashed (dentry_t *dentry)
{
        return !list_empty (&dentry->hash);
}


static void
__dentry_unhash (dentry_t *dentry)
{
        list_del_init (&dentry->hash);
}

static void
__inode_unhash (inode_t *inode)
{
        if (!list_empty (&inode->hash)) {
                if (inode->in_attic)
                        inode->table->attic_size--;
                inode->in_attic = 0;
        }

        list_del_init (&inode->hash);
}

static int
__inode_atticize (inode_t *inode)
{
        inode_table_t *table = NULL;

        table = inode->table;

        __inode_unhash (inode);

        list_add (&inode->hash, &table->attic);
        inode->in_attic = 1;
        table->attic_size++;

        return 0;
}


static void
__inode_hash (inode_t *inode)
{
        inode_table_t *table = NULL;
        int            hash = 0;

        table = inode->table;
        hash = hash_inode (inode->ino, table->hashsize);

        list_del_init (&inode->hash);
        list_add (&inode->hash, &table->inode_hash[hash]);
#ifndef HXB0315
        hash = hash_inode (inode->fuse_gen, table->hashsize);
        list_del_init (&inode->gen_hash);
        list_add (&inode->gen_hash, &table->fuse_hash[hash]);
#endif
}

#ifndef WEIWEI
static void
__dentry_unset_one (dentry_t *dentry)
{
        __dentry_unhash (dentry);

        list_del_init (&dentry->inode_list);
	//weiwei
        list_del_init (&dentry->child_list);

        if (dentry->name)
                FREE (dentry->name);

        if (dentry->parent) {
                __inode_unref (dentry->parent);
                dentry->parent = NULL;
        }

	/* set inode to NULL */
	dentry->inode = NULL;
        FREE (dentry);
}

/* change dentry_unset to unset a tree */
static void
__dentry_unset_real (dentry_t *dentry,int force_free)
{
	inode_t		*inode,*do_inode;
	dentry_t	*cdentry,*tmp;
	struct list_head unset_inodes = {0,};

	inode = dentry->inode;
	if ( !inode ) {
		__dentry_unset_one(dentry);
		return;
	}

	INIT_LIST_HEAD(&unset_inodes);

#ifndef JJH_20120331
	list_del_init(&inode->unset_list);
#endif
	/* use hash list to attach unset_inodes list */
	list_add(&inode->unset_list,&unset_inodes);
	while ( ! list_empty(&unset_inodes) ) {
		do_inode = list_entry(unset_inodes.next,inode_t,unset_list);
		list_del_init(&do_inode->unset_list);
		/* unset and check link */
		if ( do_inode == inode ) {
			/* root just unset dentry */
			__dentry_unset_one(dentry);

			/* call from unlink_inode && links > 1 && not force_free */
			if ( (!list_empty(&inode->dentry_list))&&(!force_free) ) {
				break;
			}
		}

		/* add child to unset_inodes */
		list_for_each_entry_safe(cdentry,tmp,&do_inode->child_dentry_list,child_list){
			if ( (cdentry->inode) && (cdentry->inode != inode) ) {
				list_del_init(&cdentry->inode->unset_list);
				list_add(&cdentry->inode->unset_list,&unset_inodes);
			} else {
				/* link back to root?*/
                		gf_log ("inode", GF_LOG_ERROR, "link back");
			}
		}
		/* unset current inode dentry and tree */
		if ( do_inode != inode ) {
			/* clean these dentry, link >=2 directory in used will ENOENT? */
			list_for_each_entry_safe(cdentry,tmp,&do_inode->dentry_list,inode_list){
				__dentry_unset_one(cdentry);
			}

			/* add inode to attic */
			__inode_atticize(do_inode);
		} else {
			/* inode & force_free */
			__inode_atticize(inode);
		}

	}

	return;
}
static void
__dentry_unset (dentry_t *dentry)
{
	//__dentry_unset_real(dentry,0);
	__dentry_unset_one(dentry);	// WEIWEI modified at 20120405
}
#else
static void
__dentry_unset (dentry_t *dentry)
{
        __dentry_unhash (dentry);

        list_del_init (&dentry->inode_list);

        if (dentry->name)
                FREE (dentry->name);

        if (dentry->parent) {
                __inode_unref (dentry->parent);
                dentry->parent = NULL;
        }

        FREE (dentry);
}
#endif


static int
__is_inode_hashed (inode_t *inode)
{
        return !list_empty (&inode->hash);
}


static inode_t *
__inode_search (inode_table_t *table, ino_t ino)
{
        int       hash = 0;
        inode_t  *inode = NULL;
        inode_t  *tmp = NULL;

        hash = hash_inode (ino, table->hashsize);

        list_for_each_entry (tmp, &table->inode_hash[hash], hash) {
                if (tmp->ino == ino) {
                        inode = tmp;
                        break;
                }
        }

        return inode;
}


static inode_t *
__inode_search_attic (inode_table_t *table, ino_t ino, uint64_t gen)
{
        inode_t  *inode = NULL;
        inode_t  *tmp = NULL;

        list_for_each_entry (tmp, &table->attic, hash) {
                if (tmp->ino == ino && tmp->generation == gen) {
                        inode = tmp;
                        break;
                }
        }

        return inode;
}


static dentry_t *
__dentry_search_for_inode (inode_t *inode, ino_t par, const char *name)
{
        dentry_t *dentry = NULL;
        dentry_t *tmp = NULL;

        list_for_each_entry (tmp, &inode->dentry_list, inode_list) {
                if (tmp->parent->ino == par && !strcmp (tmp->name, name)) {
                        dentry = tmp;
                        break;
                }
        }

        return dentry;
}


dentry_t *
dentry_search_for_inode (inode_t *inode, ino_t par, const char *name)
{
        dentry_t *dentry = NULL;
        pthread_mutex_lock (&inode->table->lock);
        {
                dentry = __dentry_search_for_inode (inode, par, name);
        }
        pthread_mutex_unlock (&inode->table->lock);

        return dentry;
}


static dentry_t *
__dentry_search (inode_table_t *table, ino_t par, const char *name)
{
        int       hash = 0;
        dentry_t *dentry = NULL;
        dentry_t *tmp = NULL;

        hash = hash_name (par, name, table->hashsize);

        list_for_each_entry (tmp, &table->name_hash[hash], hash) {
                if (tmp->parent->ino == par && !strcmp (tmp->name, name)) {
                        dentry = tmp;
                        break;
                }
        }

        return dentry;
}

#ifndef JJH
static inode_t *
__inode_alloc (inode_table_t *table)
{
	inode_t *newi = NULL;

	if ( !list_empty(&table->free_inode)) {
		newi = list_entry(table->free_inode.next, inode_t, list);
		list_del_init(&newi->list);
		table->finode_size -- ;
	} else {
		newi = (void *) CALLOC (1, sizeof (*newi));
#ifndef WEIWEI_20120626
		if (!newi) {
			gf_log ("inode", GF_LOG_ERROR, "out of memory");
			return newi;
		}
#endif
	}       
	bzero(newi,sizeof(*newi));
	if ( newi ) {
		INIT_LIST_HEAD(&newi->list);
		newi->table = table;
	}

	return newi;
}
/* prealloc inode */
static void
__inode_prealloc(inode_table_t *table, int num)
{
        int i;
        inode_t *newi = NULL;

        for ( i=0; i< num; i++ ) {
                newi = (void *) CALLOC (1, sizeof (*newi));
                newi->table = table;

                /* add to free_inode */
                INIT_LIST_HEAD(&newi->list);
                list_add_tail(&newi->list,&table->free_inode);
                table->finode_size ++;

        }
        return;
}

static void
__inode_free(inode_t *inode)
{
	inode_table_t *table = inode->table;

        /* fuse_forget, passive ->unref->free? */



	/* add to tail */
        pthread_mutex_lock (&table->lock);	// WEIWEI

        __inode_unhash (inode);			// WEIWEI_20120329
	list_add_tail(&inode->list,&table->free_inode);
	table->finode_size ++;
	inode->_ctx = NULL;			// WEIWEI_20120329

        pthread_mutex_unlock (&table->lock);	// WEIWEI

	return;
}
#endif


static void
__inode_destroy (inode_t *inode)
{
        int          index = 0;
        xlator_t    *xl = NULL;
        xlator_t    *old_THIS = NULL;

        if (!inode->_ctx)
                goto noctx;

        for (index = 0; index < inode->table->xl->ctx->xl_count; index++) {
                if (inode->_ctx[index].key) {
                        xl = (xlator_t *)(long)inode->_ctx[index].key;
                        old_THIS = THIS;
                        THIS = xl;
                        if (xl->cbks->forget)
                                xl->cbks->forget (xl, inode);
                        THIS = old_THIS;
                }
        }

        FREE (inode->_ctx);
noctx:
        LOCK_DESTROY (&inode->lock);
        //  memset (inode, 0xb, sizeof (*inode));
#ifndef JJH
	__inode_free(inode);
#else
        FREE (inode);
#endif
}


static void
__inode_activate (inode_t *inode)
{
        list_move (&inode->list, &inode->table->active);
        inode->table->active_size++;
}


static void
__inode_passivate (inode_t *inode)
{
        dentry_t      *dentry = NULL;
        dentry_t      *t = NULL;
        inode_table_t *table = NULL;

        table = inode->table;

        list_move_tail (&inode->list, &inode->table->lru);
        inode->table->lru_size++;
	inode->inode_time = time(NULL);

        list_for_each_entry_safe (dentry, t, &inode->dentry_list, inode_list) {
                if (!__is_dentry_hashed (dentry))
                        __dentry_unset (dentry);
        }
}


static void
__inode_retire (inode_t *inode)
{
        dentry_t      *dentry = NULL;
        dentry_t      *t = NULL;
        inode_table_t *table = NULL;

        table = inode->table;

        list_move_tail (&inode->list, &inode->table->purge);
        inode->table->purge_size++;

        __inode_unhash (inode);

#ifndef HXB0315
        list_del_init (&inode->gen_hash);
#endif

        list_for_each_entry_safe (dentry, t, &inode->dentry_list, inode_list) {
                __dentry_unset (dentry);
        }
}


static inode_t *
__inode_unref (inode_t *inode)
{
        if (inode->ino == 1)
                return inode;

        assert (inode->ref);

        --inode->ref;

        if (!inode->ref) {
                inode->table->active_size--;

                if (inode->nlookup)
                        __inode_passivate (inode);
                else
                        __inode_retire (inode);
        }

        return inode;
}


static inode_t *
__inode_ref (inode_t *inode)
{
        if (!inode->ref) {
                inode->table->lru_size--;
                __inode_activate (inode);
        }
        inode->ref++;

        return inode;
}


#ifndef JJH
/* rename will call inode_link */
static void
__dentry_unset_relink (dentry_t *dentry,inode_t *new_inode)
{
	inode_t		*inode;
	dentry_t	*cdentry,*tmp;

	inode = dentry->inode;
	if ( !inode ) {
		__dentry_unset_one(dentry);
		return;
	}

	/* move dentry child to new_inode */
	__inode_ref(inode);
	list_for_each_entry_safe(cdentry,tmp,&inode->child_dentry_list,child_list){
        	list_del_init (&cdentry->child_list);
		__inode_unref(inode);
                cdentry->parent = __inode_ref (new_inode);
                list_add(&cdentry->child_list,&new_inode->child_dentry_list);
		
	}

	__dentry_unset_one(dentry);
	__inode_unref(inode);
	return;
}
#endif
inode_t *
inode_unref (inode_t *inode)
{
        inode_table_t *table = NULL;

        table = inode->table;

        pthread_mutex_lock (&table->lock);
        {
                inode = __inode_unref (inode);
        }
        pthread_mutex_unlock (&table->lock);

        inode_table_prune (table);

        return inode;
}


inode_t *
inode_ref (inode_t *inode)
{
        inode_table_t *table = NULL;

        table = inode->table;

        pthread_mutex_lock (&table->lock);
        {
                inode = __inode_ref (inode);
        }
        pthread_mutex_unlock (&table->lock);

        return inode;
}



static dentry_t *
__dentry_create (inode_t *inode, inode_t *parent, const char *name)
{
        dentry_t      *newd = NULL;

        newd = (void *) CALLOC (1, sizeof (*newd));
        if (newd == NULL) {
                gf_log ("inode", GF_LOG_ERROR, "out of memory");
                goto out;
        }

        INIT_LIST_HEAD (&newd->inode_list);
        INIT_LIST_HEAD (&newd->hash);
#ifndef WEIWEI
        INIT_LIST_HEAD (&newd->child_list);
#endif

        newd->name = strdup (name);
        if (newd->name == NULL) {
                gf_log ("inode", GF_LOG_ERROR, "out of memory");
                FREE (newd);
                newd = NULL;
                goto out;
        }
#ifndef WEIWEI
        if (parent) {
                newd->parent = __inode_ref (parent);
		list_add(&newd->child_list,&parent->child_dentry_list);
	}
#else
        if (parent)
                newd->parent = __inode_ref (parent);
#endif

        list_add (&newd->inode_list, &inode->dentry_list);
        newd->inode = inode;

out:
        return newd;
}

#ifndef HXB0315

uint64_t
__inode_cli_gen_new (inode_table_t *table)
{
        uint64_t new_gen;

        new_gen = ++table->gen_req;

        return new_gen;
}

int
__inode_cli_gen_set (inode_t *inode)
{
        /* itable->lock must be hold before
         * this 
         */
        inode->fuse_gen = __inode_cli_gen_new (inode->table);
        return 0;
}
uint64_t
inode_cli_gen_get (inode_t *inode)
{
        return inode->fuse_gen;
}

inode_t *
inode_get_by_gen (inode_table_t *table, uint64_t gen)
{
	int hash = 0;
	inode_t *inode = NULL, *tmp;
	if (table == NULL)
		return NULL;
         pthread_mutex_lock (&table->lock);
         hash = gen % table->hashsize;
         list_for_each_entry (tmp, &table->fuse_hash[hash], gen_hash) {
         	if (tmp->fuse_gen == gen) {
                          inode = tmp;
                          __inode_ref(inode);
                          break;
		}
         }
         pthread_mutex_unlock (&table->lock);
	return inode;
}
#endif

static inode_t *
__inode_create (inode_table_t *table)
{
        inode_t  *newi = NULL;

#ifndef JJH
	newi = __inode_alloc(table);
#else
        newi = (void *) CALLOC (1, sizeof (*newi));
#endif
        if (!newi) {
                gf_log ("inode", GF_LOG_ERROR, "out of memory");
                goto out;
        }

        newi->table = table;

        LOCK_INIT (&newi->lock);

        INIT_LIST_HEAD (&newi->fd_list);
        INIT_LIST_HEAD (&newi->list);
        INIT_LIST_HEAD (&newi->hash);
        INIT_LIST_HEAD (&newi->dentry_list);
#ifndef WEIWEI
        INIT_LIST_HEAD (&newi->child_dentry_list);
        INIT_LIST_HEAD (&newi->unset_list);
#endif
#ifndef HXB0315
        __inode_cli_gen_set(newi);
        INIT_LIST_HEAD (&newi->gen_hash);
#endif

        newi->_ctx = CALLOC (1, (sizeof (struct _inode_ctx) *
                                 table->xl->ctx->xl_count));
        if (newi->_ctx == NULL) {
                gf_log ("inode", GF_LOG_ERROR, "out of memory");
                LOCK_DESTROY (&newi->lock);
                FREE (newi);
                newi = NULL;
                goto out;
        }

        list_add (&newi->list, &table->lru);
        table->lru_size++;

out:
        return newi;
}


inode_t *
inode_new (inode_table_t *table)
{
        inode_t *inode = NULL;

        pthread_mutex_lock (&table->lock);
        {
                inode = __inode_create (table);
                if (inode != NULL) {
                        __inode_ref (inode);
                }
        }
        pthread_mutex_unlock (&table->lock);

        return inode;
}


static inode_t *
__inode_lookup (inode_t *inode)
{
        inode->nlookup++;

        return inode;
}


static inode_t *
__inode_forget (inode_t *inode, uint64_t nlookup)
{
        assert (inode->nlookup >= nlookup);

        inode->nlookup -= nlookup;

        if (!nlookup)
                inode->nlookup = 0;

        return inode;
}


inode_t *
inode_search (inode_table_t *table, ino_t ino, const char *name)
{
        inode_t  *inode = NULL;
        dentry_t *dentry = NULL;

        pthread_mutex_lock (&table->lock);
        {
                if (!name) {
                        inode = __inode_search (table, ino);
                } else {
                        dentry = __dentry_search (table, ino, name);

                        if (dentry)
                                inode = dentry->inode;
                }

                if (inode)
                        __inode_ref (inode);
        }
        pthread_mutex_unlock (&table->lock);

        return inode;
}


dentry_t *
__dentry_grep (inode_table_t *table, inode_t *parent, const char *name)
{
        int       hash = 0;
        dentry_t *dentry = NULL;
        dentry_t *tmp = NULL;

        hash = hash_dentry (parent, name, table->hashsize);

        list_for_each_entry (tmp, &table->name_hash[hash], hash) {
                if (tmp->parent == parent && !strcmp (tmp->name, name)) {
                        dentry = tmp;
                        break;
                }
        }

        return dentry;
}


inode_t *
inode_grep (inode_table_t *table, inode_t *parent, const char *name)
{
        inode_t   *inode = NULL;
        dentry_t  *dentry = NULL;

        pthread_mutex_lock (&table->lock);
        {
                dentry = __dentry_grep (table, parent, name);

                if (dentry)
                        inode = dentry->inode;

                if (inode)
                        __inode_ref (inode);
        }
        pthread_mutex_unlock (&table->lock);

        return inode;
}


inode_t *
__inode_get (inode_table_t *table, ino_t ino, uint64_t gen)
{
        inode_t   *inode = NULL;

        if (ino == 1) {
                inode = table->root;
                goto out;
        }

        inode = __inode_search (table, ino);

        if (gen) {
                if (!inode || inode->generation != gen) {
                        inode = __inode_search_attic (table, ino, gen);
                }
        }

out:
        return inode;
}


inode_t *
inode_get (inode_table_t *table, ino_t ino, uint64_t gen)
{
        inode_t   *inode = NULL;

        pthread_mutex_lock (&table->lock);
        {
                inode = __inode_get (table, ino, gen);
                if (inode)
                        __inode_ref (inode);
        }
        pthread_mutex_unlock (&table->lock);

        return inode;
}



uint64_t
inode_gen_from_stat (struct stat *stbuf)
{
        return (uint64_t) stbuf->st_dev;
}


static inode_t *
__inode_link (inode_t *inode, inode_t *parent, const char *name,
              struct stat *stbuf)
{
        dentry_t      *dentry = NULL;
        dentry_t      *old_dentry = NULL;
        inode_t       *old_inode = NULL;
        inode_table_t *table = NULL;
        inode_t       *link_inode = NULL;

        table = inode->table;

        link_inode = inode;

        if (!__is_inode_hashed (inode)) {
                inode->ino        = stbuf->st_ino;
                inode->st_mode    = stbuf->st_mode;
                inode->generation = inode_gen_from_stat (stbuf);

                old_inode = __inode_search (table, inode->ino);

                if (old_inode) {
#ifdef JJH	/* Fix Bug 167*/
                        if (old_inode->generation < inode->generation) {
#else
                        if (old_inode->generation != inode->generation) {
#endif
                                __inode_atticize (old_inode);
                                __inode_hash (inode);
                        } else {
                                link_inode = old_inode;
                        }
                } else {
                        __inode_hash (inode);
                }
        }

        /* use only link_inode beyond this point */
        if (parent) {
                old_dentry = __dentry_grep (table, parent, name);

                if (!old_dentry || old_dentry->inode != link_inode) {
                        dentry = __dentry_create (link_inode, parent, name);
                        __dentry_hash (dentry);

#ifndef JJH
                        if (old_dentry) {
				if ( table->lru_limit == 0 ) {
					/* client just relink */
                                	__dentry_unset_relink (old_dentry,link_inode);
				} else {
					/* server force to unset tree */
                                	__dentry_unset_real (old_dentry,1);
				}
			}
#else
                        if (old_dentry)
                                __dentry_unset (old_dentry);
#endif
                }
        }

        return link_inode;
}


inode_t *
inode_link (inode_t *inode, inode_t *parent, const char *name,
            struct stat *stbuf)
{
        inode_table_t *table = NULL;
        inode_t       *linked_inode = NULL;

        table = inode->table;

        pthread_mutex_lock (&table->lock);
        {
                linked_inode = __inode_link (inode, parent, name, stbuf);

                if (linked_inode)
                        __inode_ref (linked_inode);
        }
        pthread_mutex_unlock (&table->lock);

        inode_table_prune (table);

        return linked_inode;
}


int
inode_lookup (inode_t *inode)
{
        inode_table_t *table = NULL;

        table = inode->table;

        pthread_mutex_lock (&table->lock);
        {
                __inode_lookup (inode);
        }
        pthread_mutex_unlock (&table->lock);

        return 0;
}


int
inode_forget (inode_t *inode, uint64_t nlookup)
{
        inode_table_t *table = NULL;

        table = inode->table;

        pthread_mutex_lock (&table->lock);
        {
                __inode_forget (inode, nlookup);
        }
        pthread_mutex_unlock (&table->lock);

        inode_table_prune (table);

        return 0;
}


static void
__inode_unlink (inode_t *inode, inode_t *parent, const char *name)
{
        dentry_t *dentry = NULL;

        dentry = __dentry_search_for_inode (inode, parent->ino, name);

        /* dentry NULL for corrupted backend */
        if (dentry)
                __dentry_unset (dentry);
}


void
inode_unlink (inode_t *inode, inode_t *parent, const char *name)
{
        inode_table_t *table = NULL;

        if (!inode)
                return;

        table = inode->table;

        pthread_mutex_lock (&table->lock);
        {
                __inode_unlink (inode, parent, name);
        }
        pthread_mutex_unlock (&table->lock);

        inode_table_prune (table);
}


int
inode_rename (inode_table_t *table, inode_t *srcdir, const char *srcname,
              inode_t *dstdir, const char *dstname, inode_t *inode,
              struct stat *stbuf)
{
        table = inode->table;

        pthread_mutex_lock (&table->lock);
        {
                __inode_link (inode, dstdir, dstname, stbuf);
                __inode_unlink (inode, srcdir, srcname);
        }
        pthread_mutex_unlock (&table->lock);

        inode_table_prune (table);

        return 0;
}


static dentry_t *
__dentry_search_arbit (inode_t *inode)
{
        dentry_t *dentry = NULL;
        dentry_t *trav = NULL;

        if (!inode)
                return NULL;

        list_for_each_entry (trav, &inode->dentry_list, inode_list) {
                if (__is_dentry_hashed (trav)) {
                        dentry = trav;
                        break;
                }
        }

        if (!dentry) {
                list_for_each_entry (trav, &inode->dentry_list, inode_list) {
                        dentry = trav;
                        break;
                }
        }

        return dentry;
}


inode_t *
inode_parent (inode_t *inode, ino_t par, const char *name)
{
        inode_t       *parent = NULL;
        inode_table_t *table = NULL;
        dentry_t      *dentry = NULL;

        table = inode->table;

        pthread_mutex_lock (&table->lock);
        {
                if (par && name) {
                        dentry = __dentry_search_for_inode (inode, par, name);
                } else {
                        dentry = __dentry_search_arbit (inode);
                }

                if (dentry)
                        parent = dentry->parent;

                if (parent)
                        __inode_ref (parent);
        }
        pthread_mutex_unlock (&table->lock);

        return parent;
}


int
inode_path (inode_t *inode, const char *name, char **bufp)
{
        inode_table_t *table = NULL;
        dentry_t      *trav = NULL;
        size_t         i = 0, size = 0;
        int64_t        ret = 0;
        int            len = 0;
        char          *buf = NULL;

        table = inode->table;

        pthread_mutex_lock (&table->lock);
        {
                for (trav = __dentry_search_arbit (inode); trav;
                     trav = __dentry_search_arbit (trav->parent)) {
                        i ++; /* "/" */
                        i += strlen (trav->name);
                        if (i > PATH_MAX) {
                                gf_log ("inode", GF_LOG_CRITICAL,
                                        "possible infinite loop detected, "
                                        "forcing break. name=(%s)", name);
                                ret = -ENOENT;
                                goto unlock;
                        }
                }

                if ((inode->ino != 1) &&
                    (i == 0)) {
                        gf_log (table->name, GF_LOG_DEBUG,
                                "no dentry for non-root inode %"PRId64,
                                inode->ino);
                        ret = -ENOENT;
                        goto unlock;
                }

                if (name) {
                        i++;
                        i += strlen (name);
                }

                ret = i;
                size = i + 1;
                buf = CALLOC (size, sizeof (char));
                if (buf) {

                        buf[size - 1] = 0;

                        if (name) {
                                len = strlen (name);
                                strncpy (buf + (i - len), name, len);
                                buf[i-len-1] = '/';
                                i -= (len + 1);
                        }

                        for (trav = __dentry_search_arbit (inode); trav;
                             trav = __dentry_search_arbit (trav->parent)) {
                                len = strlen (trav->name);
                                strncpy (buf + (i - len), trav->name, len);
                                buf[i-len-1] = '/';
                                i -= (len + 1);
                        }
                        *bufp = buf;
                } else {
                        gf_log (table->name, GF_LOG_ERROR,
                                "out of memory");
                        ret = -ENOMEM;
                }
        }
unlock:
        pthread_mutex_unlock (&table->lock);

        if (inode->ino == 1 && !name) {
                ret = 1;
                if (buf) {
                        FREE (buf);
                }
                buf = CALLOC (ret + 1, sizeof (char));
                if (buf) {
                        strcpy (buf, "/");
                        *bufp = buf;
                } else {
                        gf_log (table->name, GF_LOG_ERROR,
                                "out of memory");
                        ret = -ENOMEM;
                }
        }

        return ret;
}

static int
inode_table_prune (inode_table_t *table)
{
        int               ret = 0;
        struct list_head  purge = {0, };
        inode_t          *del = NULL;
        inode_t          *tmp = NULL;
        inode_t          *entry = NULL;


        INIT_LIST_HEAD (&purge);

        pthread_mutex_lock (&table->lock);
        {
                while (table->lru_limit
                       && table->lru_size > (table->lru_limit)) {

                        entry = list_entry (table->lru.next, inode_t, list);

                        table->lru_size--;
                        __inode_retire (entry);

                        ret++;
                }

                list_splice_init (&table->purge, &purge);
                table->purge_size = 0;
        }
        pthread_mutex_unlock (&table->lock);

        {
                list_for_each_entry_safe (del, tmp, &purge, list) {
                        list_del_init (&del->list);
                        __inode_forget (del, 0);
                        __inode_destroy (del);
                }
        }

        return ret;
}


static void
__inode_table_init_root (inode_table_t *table)
{
        inode_t *root = NULL;
        struct stat stbuf = {0, };

        root = __inode_create (table);

        stbuf.st_ino = 1;
        stbuf.st_mode = S_IFDIR|0755;

        __inode_link (root, NULL, NULL, &stbuf);
        table->root = root;
}


inode_table_t *
inode_table_new (size_t lru_limit, xlator_t *xl)
{
        inode_table_t *new = NULL;
        int            ret = 0;
        int            i = 0;
#ifndef JJH
	inode_t		*newi = NULL;
#endif

        new = (void *)calloc (1, sizeof (*new));
        if (!new)
                return NULL;

        new->xl = xl;

        new->lru_limit = lru_limit;

        new->hashsize = 14057; /* TODO: Random Number?? */

        new->inode_hash = (void *)calloc (new->hashsize,
                                          sizeof (struct list_head));
        if (!new->inode_hash) {
                FREE (new);
                return NULL;
        }

#ifndef HXB0315
        new->fuse_hash = (void *)calloc (new->hashsize,
                                          sizeof (struct list_head));
        if (!new->fuse_hash) {
                FREE (new);
                return NULL;
        }

        for (i=0; i<new->hashsize; i++) {
                INIT_LIST_HEAD (&new->fuse_hash[i]);
        }
        new->gen_req = ((time(NULL)) << 32);
	
#endif
        new->name_hash = (void *)calloc (new->hashsize,
                                         sizeof (struct list_head));
        if (!new->name_hash) {
                FREE (new->inode_hash);
                FREE (new);
                return NULL;
        }

        for (i=0; i<new->hashsize; i++) {
                INIT_LIST_HEAD (&new->inode_hash[i]);
        }


        for (i=0; i<new->hashsize; i++) {
                INIT_LIST_HEAD (&new->name_hash[i]);
        }

        INIT_LIST_HEAD (&new->active);
        INIT_LIST_HEAD (&new->lru);
        INIT_LIST_HEAD (&new->purge);
        INIT_LIST_HEAD (&new->attic);
#ifndef JJH
	INIT_LIST_HEAD (&new->free_inode);
	for ( i = 0; i<2048; i++ ) {
		newi = (void *) CALLOC (1, sizeof (*newi));
		if ( !newi ) {
			break;
		}
		new->finode_size ++;
		INIT_LIST_HEAD(&newi->list);
		list_add(&newi->list, &new->free_inode);
	}
#endif

        ret = asprintf (&new->name, "%s/inode", xl->name);
        if (-1 == ret) {
                /* TODO: This should be ok to continue, check with avati */
                ;
        }

        __inode_table_init_root (new);

        pthread_mutex_init (&new->lock, NULL);

        return new;
}


inode_t *
inode_from_path (inode_table_t *itable, const char *path)
{
        inode_t  *inode = NULL;
        inode_t  *parent = NULL;
        inode_t  *root = NULL;
        inode_t  *curr = NULL;
        char     *pathname = NULL;
        char     *component = NULL, *next_component = NULL;
        char     *strtokptr = NULL;

        /* top-down approach */
        pathname = strdup (path);
        if (pathname == NULL) {
                gf_log ("inode", GF_LOG_ERROR, "out of memory");
                goto out;
        }

        root = itable->root;
        parent = inode_ref (root);
        component = strtok_r (pathname, "/", &strtokptr);

        if (component == NULL)
                /* root inode */
                inode = inode_ref (parent);

        while (component) {
                curr = inode_grep (itable, parent, component);

                if (curr == NULL) {
                        component = strtok_r (NULL, "/", &strtokptr);
                        break;
                }

                next_component = strtok_r (NULL, "/", &strtokptr);

                if (next_component) {
                        inode_unref (parent);
                        parent = curr;
                        curr = NULL;
                } else {
                        inode = curr;
                }

                component = next_component;
        }

        if (parent)
                inode_unref (parent);

        if (pathname)
                free (pathname);

out:
        return inode;
}


int
__inode_ctx_put2 (inode_t *inode, xlator_t *xlator, uint64_t value1,
                  uint64_t value2)
{
        int ret = 0;
        int index = 0;
        int put_idx = -1;

#ifndef WEIWEI_20101214
	if(inode->_ctx == NULL){
		ret = -1;
		gf_log("", GF_LOG_ERROR, "inode->_ctx is NULL!");
		goto out;
	}
#endif

        for (index = 0; index < xlator->ctx->xl_count; index++) {
                if (!inode->_ctx[index].key) {
                        if (put_idx == -1)
                                put_idx = index;
                        /* dont break, to check if key already exists
                           further on */
                }
                if (inode->_ctx[index].xl_key == xlator) {
                        put_idx = index;
                        break;
                }
        }

        if (put_idx == -1) {
                ret = -1;
                goto out;;
        }

        inode->_ctx[put_idx].xl_key = xlator;
        inode->_ctx[put_idx].value1 = value1;
        inode->_ctx[put_idx].value2 = value2;
out:
        return ret;
}


int
inode_ctx_put2 (inode_t *inode, xlator_t *xlator, uint64_t value1,
                uint64_t value2)
{
        int ret = 0;

        if (!inode || !xlator)
                return -1;

        LOCK (&inode->lock);
        {
                ret = __inode_ctx_put2 (inode, xlator, value1, value2);
        }
        UNLOCK (&inode->lock);

        return ret;
}


int
__inode_ctx_get2 (inode_t *inode, xlator_t *xlator, uint64_t *value1,
                  uint64_t *value2)
{
        int index = 0;
        int ret = 0;

#ifndef WEIWEI_20101209
	if(inode->_ctx == NULL){
		ret = -1;
		gf_log("", GF_LOG_ERROR, "inode->_ctx is NULL!");
		goto out;
	}
#endif

        for (index = 0; index < xlator->ctx->xl_count; index++) {
                if (inode->_ctx[index].xl_key == xlator)
                        break;
        }

        if (index == xlator->ctx->xl_count) {
                ret = -1;
                goto out;
        }

        if (value1)
                *value1 = inode->_ctx[index].value1;

        if (value2)
                *value2 = inode->_ctx[index].value2;

out:
        return ret;
}


int
inode_ctx_get2 (inode_t *inode, xlator_t *xlator, uint64_t *value1,
                uint64_t *value2)
{
        int ret = 0;

        if (!inode || !xlator)
                return -1;

        LOCK (&inode->lock);
        {
                ret = __inode_ctx_get2 (inode, xlator, value1, value2);
        }
        UNLOCK (&inode->lock);

        return ret;
}


int
inode_ctx_del2 (inode_t *inode, xlator_t *xlator, uint64_t *value1,
                uint64_t *value2)
{
        int index = 0;
        int ret = 0;

        if (!inode || !xlator)
                return -1;

        LOCK (&inode->lock);
        {
                for (index = 0; index < xlator->ctx->xl_count; index++) {
                        if (inode->_ctx[index].xl_key == xlator)
                                break;
                }

                if (index == xlator->ctx->xl_count) {
                        ret = -1;
                        goto unlock;
                }

                if (value1)
                        *value1 = inode->_ctx[index].value1;
                if (value2)
                        *value2 = inode->_ctx[index].value2;

                inode->_ctx[index].key    = 0;
                inode->_ctx[index].value1 = 0;
                inode->_ctx[index].value2 = 0;
        }
unlock:
        UNLOCK (&inode->lock);

        return ret;
}


int
__inode_ctx_put (inode_t *inode, xlator_t *key, uint64_t value)
{
        return __inode_ctx_put2 (inode, key, value, 0);
}


int
inode_ctx_put (inode_t *inode, xlator_t *key, uint64_t value)
{
        return inode_ctx_put2 (inode, key, value, 0);
}


int
__inode_ctx_get (inode_t *inode, xlator_t *key, uint64_t *value)
{
        return __inode_ctx_get2 (inode, key, value, 0);
}


int
inode_ctx_get (inode_t *inode, xlator_t *key, uint64_t *value)
{
        return inode_ctx_get2 (inode, key, value, 0);
}


int
inode_ctx_del (inode_t *inode, xlator_t *key, uint64_t *value)
{
        return inode_ctx_del2 (inode, key, value, 0);
}


void
inode_dump (inode_t *inode, char *prefix)
{
        char            key[GF_DUMP_MAX_BUF_LEN];
        int             ret = -1;
        xlator_t        *xl = NULL;
        int             i = 0;
#ifndef behe_100825
	dentry_t	*den = NULL;
	dentry_t	*tmp = NULL;
#endif

        if (!inode)
                return;

        ret = TRY_LOCK(&inode->lock);

        if (ret != 0) {
                gf_log("", GF_LOG_WARNING, "Unable to dump inode"
                       " errno: %d", errno);
                return;
        }

        gf_proc_dump_build_key(key, prefix, "nlookup");
        gf_proc_dump_write(key, "%ld", inode->nlookup);
        gf_proc_dump_build_key(key, prefix, "generation");
        gf_proc_dump_write(key, "%ld", inode->generation);
        gf_proc_dump_build_key(key, prefix, "ref");
        gf_proc_dump_write(key, "%u", inode->ref);
        gf_proc_dump_build_key(key, prefix, "ino");
        gf_proc_dump_write(key, "%ld", inode->ino);
        gf_proc_dump_build_key(key, prefix, "st_mode1");
        gf_proc_dump_write(key, "%d", inode->st_mode);
#ifndef behe_100825
	if (!list_empty(&inode->dentry_list)) {
		list_for_each_entry_safe (den, tmp, &inode->dentry_list, inode_list) {
			gf_proc_dump_build_key(key, prefix, "dentry");
			gf_proc_dump_write(key, "%s", den->name);
		}
	}
#endif
        UNLOCK(&inode->lock);
        if (!inode->_ctx)
                goto out;

        for (i = 0; i < inode->table->xl->ctx->xl_count; i++) {
                if (inode->_ctx[i].key) {
                        xl = (xlator_t *)(long)inode->_ctx[i].key;
                        if (xl->dumpops && xl->dumpops->inodectx)
                                xl->dumpops->inodectx (xl, inode);
                }
        }

out:
        return;
}

void
inode_table_dump (inode_table_t *itable, char *prefix)
{

        char    key[GF_DUMP_MAX_BUF_LEN];
        int     ret = 0;

        if (!itable)
                return;

        memset(key, 0, sizeof(key));
        ret = pthread_mutex_trylock(&itable->lock);

        if (ret != 0) {
                gf_log("", GF_LOG_WARNING, "Unable to dump inode table"
                       " errno: %d", errno);
                return;
        }

        gf_proc_dump_build_key(key, prefix, "hashsize");
        gf_proc_dump_write(key, "%d", itable->hashsize);
        gf_proc_dump_build_key(key, prefix, "name");
        gf_proc_dump_write(key, "%s", itable->name);

        gf_proc_dump_build_key(key, prefix, "lru_limit");
        gf_proc_dump_write(key, "%d", itable->lru_limit);
        gf_proc_dump_build_key(key, prefix, "active_size");
        gf_proc_dump_write(key, "%d", itable->active_size);
        gf_proc_dump_build_key(key, prefix, "lru_size");
        gf_proc_dump_write(key, "%d", itable->lru_size);
        gf_proc_dump_build_key(key, prefix, "purge_size");
        gf_proc_dump_write(key, "%d", itable->purge_size);

        INODE_DUMP_LIST(&itable->active, key, prefix, "active");
        INODE_DUMP_LIST(&itable->lru, key, prefix, "lru");
        INODE_DUMP_LIST(&itable->purge, key, prefix, "purge");

        pthread_mutex_unlock(&itable->lock);
}

#ifndef behe_100825
void set_posix_path (char *path, int path_len)
{
	posix_path = strdup (path);
	posix_path_len = path_len;
	gf_proc_dump_write ("set posix_path", "%s", path);
}

void get_posix_path (char **path, int *path_len)
{
	*path = strdup (posix_path);
	*path_len = posix_path_len;
	gf_proc_dump_write ("get posix_path", "%s", *path);
}
#if 1
void
dump_dentry_tree (dentry_t *dentry, char *prefix_path)
{
	int 	ret = 0;
	char	*child_path = NULL;
	inode_t *inode = dentry->inode;
	dentry_t	*child_dentry = NULL;
	dentry_t	*tmp_dentry = NULL;
	struct stat	statbuf;

	if (!list_empty(&inode->child_dentry_list)) {
	list_for_each_entry_safe (child_dentry, tmp_dentry, &inode->child_dentry_list, child_list)
	{
		gf_proc_dump_write("dentry_name", "%s", child_dentry->name);
		child_path = MALLOC (strlen(child_dentry->name) + strlen (prefix_path) + 2);
		strcpy (child_path, prefix_path);
		strcpy (&child_path[strlen(prefix_path)], "/");
		strcpy (&child_path[strlen(prefix_path) + 1], child_dentry->name);
		gf_proc_dump_write ("full_path", "%s", child_path);
		ret = sys_stat(child_path, &statbuf);
		if (ret == -1) {
			gf_proc_dump_write ("stat error", "%d", errno);
			if (errno == 2) {
				__dentry_unset(child_dentry);
			} else {
				dump_dentry_tree(child_dentry, child_path);
			}
		}
		FREE(child_path);
	}
	}
}

void
dump_itable_tree (inode_table_t *itable, char *prefix_path)
{
	int	ret = 0;
	inode_t *root = itable->root;
	dentry_t *root_dentry = list_entry(&root->dentry_list, dentry_t, inode_list);
	char	*child_path = NULL;
	dentry_t	*child_dentry = NULL;
	dentry_t	*tmp_dentry = NULL;
	struct stat	statbuf;

	gf_proc_dump_write("inum", "%d", root->ino);
	if (list_empty(&root->child_dentry_list)) {
		gf_proc_dump_write("empty root", "%s", "empty");
	}

	list_for_each_entry_safe (child_dentry, tmp_dentry, &root->child_dentry_list, child_list)
	{
		gf_proc_dump_write("dentry_name", "%s", child_dentry->name);
		child_path = MALLOC (strlen(child_dentry->name) + strlen (prefix_path) + 2);
		strcpy (child_path, prefix_path);
		strcpy (&child_path[strlen(prefix_path)], "/");
		strcpy (&child_path[strlen(prefix_path) + 1], child_dentry->name);
		gf_proc_dump_write ("full_path", "%s", child_path);
		ret = sys_stat(child_path, &statbuf);
		if (ret == -1) {
			gf_proc_dump_write ("stat error", "%d", errno);
			if (errno == 2) {
				__dentry_unset(child_dentry);
			} else {
				dump_dentry_tree(child_dentry, child_path);
			}
		}
		FREE(child_path);
	}
}
#endif

int
__inode_path (inode_t *inode, const char *name, char **bufp)
{
        inode_table_t *table = NULL;
        dentry_t      *trav = NULL;
        size_t         i = 0, size = 0;
        int64_t        ret = 0;
        int            len = 0;
        char          *buf = NULL;

        table = inode->table;

//        pthread_mutex_lock (&table->lock);
        {
                for (trav = __dentry_search_arbit (inode); trav;
                     trav = __dentry_search_arbit (trav->parent)) {
                        i ++; /* "/" */
                        i += strlen (trav->name);
                        if (i > PATH_MAX) {
                                gf_log ("inode", GF_LOG_CRITICAL,
                                        "possible infinite loop detected, "
                                        "forcing break. name=(%s)", name);
                                ret = -ENOENT;
                                goto unlock;
                        }
                }

                if ((inode->ino != 1) &&
                    (i == 0)) {
                        gf_log (table->name, GF_LOG_DEBUG,
                                "no dentry for non-root inode %"PRId64,
                                inode->ino);
                        ret = -ENOENT;
                        goto unlock;
                }

                if (name) {
                        i++;
                        i += strlen (name);
                }

                ret = i;
                size = i + 1;
                buf = CALLOC (size, sizeof (char));
                if (buf) {

                        buf[size - 1] = 0;

                        if (name) {
                                len = strlen (name);
                                strncpy (buf + (i - len), name, len);
                                buf[i-len-1] = '/';
                                i -= (len + 1);
                        }

                        for (trav = __dentry_search_arbit (inode); trav;
                             trav = __dentry_search_arbit (trav->parent)) {
                                len = strlen (trav->name);
                                strncpy (buf + (i - len), trav->name, len);
                                buf[i-len-1] = '/';
                                i -= (len + 1);
                        }
                        *bufp = buf;
                } else {
                        gf_log (table->name, GF_LOG_ERROR,
                                "out of memory");
                        ret = -ENOMEM;
                }
        }
unlock:
//        pthread_mutex_unlock (&table->lock);

        if (inode->ino == 1 && !name) {
                ret = 1;
                if (buf) {
                        FREE (buf);
                }
                buf = CALLOC (ret + 1, sizeof (char));
                if (buf) {
                        strcpy (buf, "/");
                        *bufp = buf;
                } else {
                        gf_log (table->name, GF_LOG_ERROR,
                                "out of memory");
                        ret = -ENOMEM;
                }
        }

        return ret;
}

void
dump_itablesize (inode_table_t *itable, char *prefix)
{
	char    key[GF_DUMP_MAX_BUF_LEN];
        int     ret = 0;
        if (!itable)
                return;

        ret = pthread_mutex_lock(&itable->lock);
        if (ret != 0) {
                gf_log("", GF_LOG_WARNING, "Unable to clean inode table"
                       " errno: %d", errno);
                return;
        }
	gf_proc_dump_build_key(key, "", "lru_size");
        gf_proc_dump_write(key, "%d", itable->lru_size);
	gf_proc_dump_build_key(key, "", "active_size");
        gf_proc_dump_write(key, "%d", itable->active_size);
        gf_proc_dump_write("=====", "");

	pthread_mutex_unlock(&itable->lock);
	return;
}

void
clean_itable (inode_table_t *itable, char *prefix)
{
	char    key[GF_DUMP_MAX_BUF_LEN];
        int     ret = 0;
	int	i = 1;
	inode_t 	*inode = NULL;
	inode_t		*tmp_i = NULL;
	char *inode_path_name = NULL;
	char *real_path_name = NULL;
	dentry_t	*dentry = NULL;
	dentry_t	*trav = NULL;
	struct stat	statbuf;

        if (!itable)
                return;

	while (!ret) {
        	ret = pthread_mutex_lock(&itable->lock);
        	if (ret != 0) {
                	gf_log("", GF_LOG_WARNING, "Unable to clean inode table"
                       		" errno: %d", errno);
                	return;
        	}	

		inode = NULL;
		tmp_i = NULL;
		if ((itable->lru_size > 100)) {
			list_for_each_entry_safe (inode, tmp_i, &itable->lru, list) {
#if 0
				if ((((uint64_t)(time(NULL))) - 
					((uint64_t)(inode->inode_time))) > 600) {
					itable->lru_size--;
					__inode_retire(inode);
				} else 	{
					ret = 1; /* the inode is really fresh, or ... */
				}	
#else
				itable->lru_size--;
				__inode_retire(inode);
#endif
				break;
			}
		} else {
			ret = 1; /* ... the lru is really small */
		}

		pthread_mutex_unlock(&itable->lock);
	}
	return;
#if 0
        memset(key, 0, sizeof(key));
        ret = pthread_mutex_trylock(&itable->lock);
        if (ret != 0) {
                gf_log("", GF_LOG_WARNING, "Unable to clean inode table"
                       " errno: %d", errno);
                return;
        }
	list_for_each_entry_safe (inode, tmp_i, &itable->lru, list) {
		__inode_path (inode, NULL, &inode_path_name);
		if (inode_path_name) {
			real_path_name = MALLOC (strlen(prefix) + strlen(inode_path_name) + 2);
			strcpy (real_path_name, prefix);
			strcpy (&real_path_name[strlen(prefix)], inode_path_name);
			gf_log ("path_name", GF_LOG_ERROR, "%s", real_path_name);
			gf_log ("life time", GF_LOG_ERROR, "%d", ((uint64_t)(time(NULL))) - ((uint64_t)(inode->inode_time)));
			ret = sys_stat(real_path_name, &statbuf);
			if (ret == -1) {
				gf_log ("stat error", GF_LOG_ERROR, "%d", errno);
				if (errno == 2) {
					itable->lru_size--;
					__inode_retire(inode);
				}		
			}	
			FREE (real_path_name);
		}
	}
	pthread_mutex_unlock(&itable->lock);
#endif
}
#endif
