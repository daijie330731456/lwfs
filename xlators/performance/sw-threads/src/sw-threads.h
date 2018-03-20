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

#ifndef __SWT_H
#define __SWT_H

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif


#include "compat-errno.h"
#include "lwfs.h"
#include "logging.h"
#include "dict.h"
#include "xlator.h"
#include "common-utils.h"
#include "list.h"
#include <stdlib.h>
#include "locking.h"
#include <semaphore.h>


struct swt_conf;

#define MAX_IDLE_SKEW                   4       /* In secs */
#define skew_sec_idle_time(sec)         ((sec) + (random () % MAX_IDLE_SKEW))
#define SWT_DEFAULT_IDLE                120     /* In secs. */

#define SWT_MIN_THREADS         1
#define SWT_DEFAULT_THREADS     16
#define SWT_MAX_THREADS         64


#define SWT_THREAD_STACK_SIZE   ((size_t)(1024*1024))


typedef enum {
        SWT_PRI_HI = 0, /* low latency */
        SWT_PRI_NORMAL, /* normal */
#ifndef WEIWEI_20130201
        SWT_PRI_LO1,     /* Small bulk */
#endif
        SWT_PRI_LO,     /* bulk */
        SWT_PRI_MAX,
} swt_pri_t;


struct swt_conf {
        pthread_mutex_t      mutex;
        pthread_cond_t       cond;

        int32_t              max_count;   /* configured maximum */
        int32_t              curr_count;  /* actual number of threads running */
        int32_t              sleep_count;

        int32_t              idle_time;   /* in seconds */

        struct list_head     reqs[SWT_PRI_MAX];

        int                  queue_size;
        pthread_attr_t       w_attr;

        xlator_t            *this;
};

typedef struct swt_conf swt_conf_t;

#ifndef WEIWEI_20130201
#define MAX_RW_NUM 0x4
struct worker_arg {
    int         wa_id;
    swt_conf_t *wa_conf;
};
typedef struct worker_arg swt_arg_t;
#endif

#endif /* __SWT_H */
