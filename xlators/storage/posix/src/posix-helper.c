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
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <ftw.h>


#include "xlator.h"
#include "logging.h"
#include "posix.h"
#include "lustre_quota.h"


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

int is_quota_overflow(call_frame_t *frame, xlator_t *this)
{
        uid_t uid;
		gid_t gid;
        int ret = 0, have_entry = 0;
		struct quota_entry *tmp_entry, *new_entry = NULL;

        uid = frame->root->uid;
        gid = frame->root->gid;


	LOCK(&quota_pool.lock);
	list_for_each_entry (tmp_entry, &quota_pool.quota_list, list) {
		if (tmp_entry->uid == uid && tmp_entry->gid == gid) {
			if (tmp_entry->status > 0) {
				ret = tmp_entry->status;
				goto unlock;
			}
			have_entry = 1;
		}
	}
	if (!have_entry) {
		new_entry = CALLOC(1, sizeof(struct quota_entry));
		if (new_entry == NULL) {
			gf_log("posix_quota", GF_LOG_ERROR, "Out of Memory");
			goto unlock;
		}
		new_entry->uid = uid;
		new_entry->gid = gid;
		new_entry->status = 0;
		INIT_LIST_HEAD(&new_entry->list);
		list_add(&new_entry->list, &quota_pool.quota_list);
		quota_pool.count++;
		ret = 0;
	}
unlock:
	UNLOCK(&quota_pool.lock);
	gf_log ("posix_quota", GF_LOG_TRACE, "quota check for usr[%d] grp[%d] return status %d",
		uid, gid, ret);
	return ret;
}


int __update_user_quota(uid_t uid, gid_t gid)
{
        int ret = 0;
        int usr_i = 0, usr_s = 0, grp_i = 0, grp_s = 0;

        struct if_quotactl uqctl = { .qc_cmd = SWGFS_Q_GETQUOTA,
                                     .qc_type = 0x1};
        struct if_quotactl gqctl = { .qc_cmd = SWGFS_Q_GETQUOTA,
                                     .qc_type = 0x2};

        struct obd_dqblk *udq, *gdq;

        udq = &uqctl.qc_dqblk;
        gdq = &gqctl.qc_dqblk;

        uqctl.qc_cmd = SWGFS_Q_GETQUOTA;
        uqctl.qc_type = USRQUOTA;
        uqctl.qc_id = uid;

        ret = llapi_quotactl (mnt, &uqctl);
        if (ret && (errno != ESRCH)) {
                gf_log ("quota-update", GF_LOG_ERROR,
                        "get quota for user %d failed: %s",
                         uid, strerror(errno));
                return -1;
        } else if (errno != ESRCH) {
                gf_log ("quota-update", GF_LOG_TRACE,
                        "quota for user(%d) is: curspace[%"PRId64"], bhardlimit[%"PRId64"], curinodes[%"PRId64"], ihardlimit[%"PRId64"]",
                        uid, toqb(udq->dqb_curspace), udq->dqb_bhardlimit,
                        udq->dqb_curinodes, udq->dqb_ihardlimit);
                if (udq->dqb_bhardlimit && (toqb(udq->dqb_curspace) + 4 >= udq->dqb_bhardlimit))
                        usr_s = 1;
                else
                        usr_s = 0;
                if (udq->dqb_ihardlimit && (udq->dqb_curinodes >= udq->dqb_ihardlimit))
                        usr_i = 1;
                else
                        usr_i = 0;
        }

        gqctl.qc_cmd = SWGFS_Q_GETQUOTA;
        gqctl.qc_type = GRPQUOTA;
        gqctl.qc_id = gid;

        ret = llapi_quotactl (mnt, &gqctl);
        if (ret && (errno != ESRCH)) {
                gf_log ("quota-update", GF_LOG_ERROR,
                        "get quota for group %d failed: %s",
                         gid, strerror(errno));
                return -1;
        } else if (errno != ESRCH) {
                gf_log ("quota-update", GF_LOG_TRACE,
                        "quota for group(%d) is: curspace[%"PRId64"], bhardlimit[%"PRId64"], curinodes[%"PRId64"], ihardlimit[%"PRId64"]",
                        gid, gdq->dqb_curspace, gdq->dqb_bhardlimit,
                        gdq->dqb_curinodes, gdq->dqb_ihardlimit);
                if (gdq->dqb_bhardlimit && (toqb(gdq->dqb_curspace) + 4 >= gdq->dqb_bhardlimit))
                        grp_s = 1;
                else
                        grp_s = 0;

                if (gdq->dqb_ihardlimit && (gdq->dqb_curinodes >= gdq->dqb_ihardlimit))
                        grp_i = 1;
                else
                        grp_i = 0;
        }

        if (usr_s || grp_s)
                return 1;

        if (usr_i || grp_i)
                return 2;

        return 0;
}

int quota_update(void *data)
{
	struct quota_entry *tmp_entry;
	int sleep_lap = 60 * 3; /* sleep 60seconds(1minutes) after updata user quota*/
	mnt = (char *)data;
	LOCK_INIT (&quota_pool.lock);
	INIT_LIST_HEAD(&quota_pool.quota_list);
	
	quota_pool.count = 0;

	while (1) {
		sleep(sleep_lap);
		LOCK(&quota_pool.lock);
		{
		        list_for_each_entry (tmp_entry, &quota_pool.quota_list, list) {
				tmp_entry->status = __update_user_quota(tmp_entry->uid,
						tmp_entry->gid);
				if (tmp_entry->status == -1) {
					gf_log("posix_quota", GF_LOG_ERROR,
							"update quota error");
					tmp_entry->status == 0;
					}
				gf_log ("quota-update", GF_LOG_TRACE,
					"quota status %d for (user:%d,grp:%d)",
					tmp_entry->status, tmp_entry->uid, tmp_entry->gid);
			}
		}
		UNLOCK(&quota_pool.lock);
	}
	return 0;
}
