#include <sys/types.h>
#include <stdio.h>
#include <dirent.h>

#ifndef LUSTRE_QUOTA
#define LUSTRE_QUOTA
#endif
/* liblustreapi message severity level */
enum llapi_message_level {
        LLAPI_MSG_OFF    = 0,
        LLAPI_MSG_FATAL  = 1,
        LLAPI_MSG_ERROR  = 2,
        LLAPI_MSG_WARN   = 3,
        LLAPI_MSG_NORMAL = 4,
        LLAPI_MSG_INFO   = 5,
        LLAPI_MSG_DEBUG  = 6,
        LLAPI_MSG_MAX
};

 
#define USER 0
#define GROUP 1

#ifndef QUOTABLOCK_BITS
#define QUOTABLOCK_BITS 10
#endif

#ifndef QUOTABLOCK_SIZE
#define QUOTABLOCK_SIZE (1 << QUOTABLOCK_BITS)
#endif

/* the bottom three bits reserved for llapi_message_level */
#define LLAPI_MSG_MASK          0x00000007
#define LLAPI_MSG_NO_ERRNO      0x00000010
//static int llapi_msg_level = LLAPI_MSG_MAX;

#define _IOC_NRBITS     8
#define _IOC_TYPEBITS   8
#define _IOC_SIZEBITS   14
#define _IOC_DIRBITS    2
#define _IOC_NRSHIFT    0
#define _IOC_TYPESHIFT  (_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT  (_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT   (_IOC_SIZESHIFT+_IOC_SIZEBITS)
#define _IOC_NONE       0U
#define _IOC_WRITE      1U
#define _IOC_READ       2U
#define _IOC(dir,type,nr,size) (((dir)  << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | ((nr)   << _IOC_NRSHIFT) | ((size) << _IOC_SIZESHIFT))
//#define _IOWR(type,nr,size)     _IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))
#define LL_IOC_QUOTACTL                 _IOWR('f', 162, struct if_quotactl *)
//typedef unsigned int __u32;
//typedef unsigned long long __u64;
#define SWGFS_Q_GETQUOTA   0x800007     /* get user quota structure */
#define SWGFS_Q_SETQUOTA   0x800008     /* set user quota structure */
#ifndef USRQUOTA
#define USRQUOTA 0
#endif

#ifndef GRPQUOTA
#define GRPQUOTA 1
#endif

#ifndef QIF_BLIMITS
#define QIF_BLIMITS     1
#define QIF_SPACE       2
#define QIF_ILIMITS     4
#define QIF_INODES      8
#define QIF_BTIME       16
#define QIF_ITIME       32
#define QIF_LIMITS      (QIF_BLIMITS | QIF_ILIMITS)
#define QIF_USAGE       (QIF_SPACE | QIF_INODES)
#define QIF_TIMES       (QIF_BTIME | QIF_ITIME)
#define QIF_ALL         (QIF_LIMITS | QIF_USAGE | QIF_TIMES)
#endif

#define toqb(x) (((x) + QUOTABLOCK_SIZE - 1) >> QUOTABLOCK_BITS)
typedef __u64 qsize_t; 

struct obd_uuid {
        char uuid[40];
};

struct obd_dqinfo {
        __u64 dqi_bgrace;
        __u64 dqi_igrace;
        __u32 dqi_flags;
        __u32 dqi_valid;
};

struct obd_dqblk {
        __u64 dqb_bhardlimit;
        __u64 dqb_bsoftlimit;
        __u64 dqb_curspace;
        __u64 dqb_ihardlimit;
        __u64 dqb_isoftlimit;
        __u64 dqb_curinodes;
        __u64 dqb_btime;
        __u64 dqb_itime;
        __u32 dqb_valid;
        __u32 padding;
};

struct if_quotactl {
        __u32                   qc_cmd;
        __u32                   qc_type;
        __u32                   qc_id;
        __u32                   qc_stat;
        struct obd_dqinfo       qc_dqinfo;
        struct obd_dqblk        qc_dqblk;
        char                    obd_type[16];
        struct obd_uuid         obd_uuid;
};

/*
void llapi_err(int level, char *fmt, ...)
{
        va_list args;
        int tmp_errno = abs(errno);

        if ((level & LLAPI_MSG_MASK) > llapi_msg_level)
                return;

        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);

        if (level & LLAPI_MSG_NO_ERRNO)
                fprintf(stderr, "\n");
        else
                fprintf(stderr, ": %s (%d)\n", strerror(tmp_errno), tmp_errno);
}
*/
#define HAVE_LLAPI_IS_SWGFS_MNT
extern int llapi_quotactl(char *mnt, struct if_quotactl *qctl);
int llapi_quotactl(char *mnt, struct if_quotactl *qctl)
{
        DIR *root;
        int rc;

        root = opendir(mnt);
        if (!root) {
                fprintf(stdout, "open %s failed", mnt);
                return -1;
        }

        rc = ioctl(dirfd(root), LL_IOC_QUOTACTL, qctl);

        closedir(root);
        return rc;
}
