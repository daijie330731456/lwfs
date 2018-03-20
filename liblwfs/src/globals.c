/*
   Copyright (c) 2009 LW, Inc. <http://www.lw.com>
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
#endif /* !_CONFIG_H */

#include <pthread.h>

#include "globals.h"
#include "lwfs.h"
#include "xlator.h"


/* CTX */
static lwfs_ctx_t *lwfs_ctx;


int
lwfs_ctx_init ()
{
        int  ret = 0;

        if (lwfs_ctx)
                goto out;

        lwfs_ctx = CALLOC (1, sizeof (*lwfs_ctx));
        if (!lwfs_ctx) {
                ret = -1;
                goto out;
        }

        ret = pthread_mutex_init (&lwfs_ctx->lock, NULL);

out:
        return ret;
}


lwfs_ctx_t *
lwfs_ctx_get ()
{
        return lwfs_ctx;

}


/* THIS */

xlator_t global_xlator;
static pthread_key_t this_xlator_key;

void
lwfs_this_destroy (void *ptr)
{
        if (ptr)
                FREE (ptr);
}


int
lwfs_this_init ()
{
        int  ret = 0;

        ret = pthread_key_create (&this_xlator_key, lwfs_this_destroy);
        if (ret != 0) {
                return ret;
        }

        global_xlator.name = "lwfs";
        global_xlator.type = "global";

        return ret;
}


xlator_t **
__lwfs_this_location ()
{
        xlator_t **this_location = NULL;
        int        ret = 0;

        this_location = pthread_getspecific (this_xlator_key);

        if (!this_location) {
                this_location = CALLOC (1, sizeof (*this_location));
                if (!this_location)
                        goto out;

                ret = pthread_setspecific (this_xlator_key, this_location);
                if (ret != 0) {
                        FREE (this_location);
                        this_location = NULL;
                        goto out;
                }
        }
out:
        if (this_location) {
                if (!*this_location)
                        *this_location = &global_xlator;
        }
        return this_location;
}


xlator_t *
lwfs_this_get ()
{
        xlator_t **this_location = NULL;

        this_location = __lwfs_this_location ();
        if (!this_location)
                return &global_xlator;

        return *this_location;
}


int
lwfs_this_set (xlator_t *this)
{
        xlator_t **this_location = NULL;

        this_location = __lwfs_this_location ();
        if (!this_location)
                return -ENOMEM;

        *this_location = this;

        return 0;
}


/* IS_CENTRAL_LOG */

static pthread_key_t central_log_flag_key;

void
lwfs_central_log_flag_destroy (void *ptr)
{
        if (ptr)
                FREE (ptr);
}


int
lwfs_central_log_flag_init ()
{
        int ret = 0;

        ret = pthread_key_create (&central_log_flag_key, 
                                  lwfs_central_log_flag_destroy);

        if (ret != 0) {
                return ret;
        }

        pthread_setspecific (central_log_flag_key, (void *) 0);

        return ret;
}


void
lwfs_central_log_flag_set ()
{
        pthread_setspecific (central_log_flag_key, (void *) 1);
}


long
lwfs_central_log_flag_get ()
{
        long flag = 0;

        flag = (long) pthread_getspecific (central_log_flag_key);
        
        return flag;
}


void
lwfs_central_log_flag_unset ()
{
        pthread_setspecific (central_log_flag_key, (void *) 0);
}


int
lwfs_globals_init ()
{
        int ret = 0;

        ret = lwfs_ctx_init ();
        if (ret)
                goto out;

        ret = lwfs_this_init ();
        if (ret)
                goto out;

        ret = lwfs_central_log_flag_init ();
        if (ret)
                goto out;
out:
        return ret;
}
