#ifndef IOCTL /* wanghy add */
#ifndef _LWFS_IOCTL_H_
#define _LWFS_IOCTL_H_

#include <linux/ioctl.h>

/* hexb@20100505*/
/* define LWFS ioctl cmd */
#define LWFS_CLIENT_BIT			0x1
#define LWFS_SERVER_BIT			0x2

#define LWFS_TYPE			'f'     
#define LWFS_IOC_DATA_TYPE      	long

/* cmd */
#define LWFS_IOC_SETDB			_IOW('f',0x10,long) /* set debug level */
#define LWFS_IOC_GETDB			_IOR('f',0x20,long) /* get debug level */
#define LWFS_IOC_SETOP			_IOW('f',0x30,long) /* set op mask */
#define LWFS_IOC_GETOP			_IOR('f',0x40,long) /* get op mask */
#define LWFS_IOC_GETST			_IOR('f',0x50,long) /* get op mask */
#define LWFS_IOC_SETTAG			_IOW('f',0x60,long) /* send tag mess to server */
#define LWFS_IOC_OPENREC    		_IO('f',0x70) /* start rec op */
#define LWFS_IOC_CLOSEREC   		_IO('f',0x80) /* stop rec op */

/* behe_100825 */
#define LWFS_IOC_CLEAN_ITABLE		1074292241
//#define LWFS_IOC_CLEAN_ITABLE 	_IOWR('f', 0x11, long)
#define LWFS_IOC_DUMP_ITABLE_SIZE 	_IOWR('f', 0x12, long)

#define IS_CLIENT_BIT(cmd)      	(_IOC_NR(cmd)&LWFS_CLIENT_BIT)
#define IS_SERVER_BIT(cmd)      	(_IOC_NR(cmd)&LWFS_SERVER_BIT)
#define SET_CLIENT_BIT(cmd)      	(_IOC_NR(cmd)|LWFS_CLIENT_BIT)
#define SET_SERVER_BIT(cmd)      	(_IOC_NR(cmd)|LWFS_SERVER_BIT)
#define GET_CLIENT_CMD(cmd)      	(_IOC_NR(cmd)^LWFS_CLIENT_BIT)
#define GET_SERVER_CMD(cmd)      	(_IOC_NR(cmd)^LWFS_SERVER_BIT)
/* hexb@20100505 end*/

#define LOV_MAX_STRIPE_COUNT  		160   /* until bug 4424 is fixed */
#define O_LOV_DELAY_CREATE 		0100000000 /* hopefully this does not conflict */
#define LOV_MAGIC         		LOV_USER_MAGIC_V1
#define LOV_USER_MAGIC_V1 		0x0BD10BD0
#define LOV_USER_MAGIC_V3 		0x0BD30BD0
#define IOC_MDC_TYPE         		'i'
#define LL_IOC_LOV_SETSTRIPE            _IOW ('f', 154, long)
#define LL_IOC_LOV_GETSTRIPE            _IOW ('f', 155, long)
#define IOC_MDC_GETFILESTRIPE   	_IOWR(IOC_MDC_TYPE, 21, struct lov_user_md *)
#define OBD_NOT_FOUND           	dd(-1)
#define LOV_MAXPOOLNAME 		16

typedef unsigned long 	__u64;
typedef unsigned int  	__u32;
typedef unsigned short 	__u16;

#define lov_user_ost_data lov_user_ost_data_v1
struct lov_user_ost_data_v1 {     /* per-stripe data structure */
        __u64 l_object_id;        /* OST object ID */
        __u64 l_object_gr;        /* OST object group (creating MDS number) */
        __u32 l_ost_gen;          /* generation of this OST index */
        __u32 l_ost_idx;          /* OST index in LOV */
} __attribute__((packed));

#define lov_user_md lov_user_md_v1
struct lov_user_md_v1 {           /* LOV EA user data (host-endian) */
        __u32 lmm_magic;          /* magic number = LOV_USER_MAGIC_V1 */
        __u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u64 lmm_object_gr;      /* LOV object group */
        __u32 lmm_stripe_size;    /* size of stripe in bytes */
        __u16 lmm_stripe_count;   /* num stripes in use for this object */
        __u16 lmm_stripe_offset;  /* starting stripe offset in lmm_objects */
        struct lov_user_ost_data_v1 lmm_objects[0]; /* per-stripe data */
} __attribute__((packed));

struct lov_user_md_v3 {           /* LOV EA user data (host-endian) */
        __u32 lmm_magic;          /* magic number = LOV_USER_MAGIC_V1 */
        __u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u64 lmm_object_gr;      /* LOV object group */
        __u32 lmm_stripe_size;    /* size of stripe in bytes */
        __u16 lmm_stripe_count;   /* num stripes in use for this object */
        __u16 lmm_stripe_offset;  /* starting stripe offset in lmm_objects */
        char lmm_pool_name[LOV_MAXPOOLNAME]; /* pool name */
        struct lov_user_ost_data_v1 lmm_objects[0]; /* per-stripe data */
} __attribute__((packed));

/* Identifier for a single log object */
struct llog_logid {
        __u64                   lgl_oid;
        __u64                   lgl_ogr;
        __u32                   lgl_ogen;
} __attribute__((packed));

struct lov_user_ost_data_join {   /* per-stripe data structure */
        __u64 l_extent_start;     /* extent start*/
        __u64 l_extent_end;       /* extent end*/
        __u64 l_object_id;        /* OST object ID */
        __u64 l_object_gr;        /* OST object group (creating MDS number) */
        __u32 l_ost_gen;          /* generation of this OST index */
        __u32 l_ost_idx;          /* OST index in LOV */
} __attribute__((packed));

struct lov_user_md_join {         /* LOV EA user data (host-endian) */
        __u32 lmm_magic;          /* magic number = LOV_MAGIC_JOIN */
        __u32 lmm_pattern;        /* LOV_PATTERN_RAID0, LOV_PATTERN_RAID1 */
        __u64 lmm_object_id;      /* LOV object ID */
        __u64 lmm_object_gr;      /* LOV object group */
        __u32 lmm_stripe_size;    /* size of stripe in bytes */
        __u32 lmm_stripe_count;   /* num stripes in use for this object */
        __u32 lmm_extent_count;   /* extent count of lmm*/
        __u64 lmm_tree_id;        /* mds tree object id */
        __u64 lmm_tree_gen;       /* mds tree object gen */
        struct llog_logid lmm_array_id; /* mds extent desc llog object id */
        struct lov_user_ost_data_join lmm_objects[0]; /* per-stripe data */
} __attribute__((packed));

#endif
#endif

