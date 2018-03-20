#include <ctype.h>
#include <sys/uio.h>

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "lwfs.h"
#include "xlator.h"
#include "logging.h"

#include "access-control.h"
#include <pwd.h>
#include "tree.h"

//int getUserAttr(const char *username ,char *attr);
int getUserAttr(int uid, char* attr);

static int32_t attraccess(call_frame_t *frame,
				void *cookie,
				xlator_t *this,
				int32_t op_ret,
				int32_t op_errno,
				dict_t *dict);

static ac_local_t * ac_alloc_local(call_frame_t* frame, xlator_t* this, lwfs_fop_t fop)
{
	ac_local_t* local;
	
	local = CALLOC(1 , sizeof(*local));
	if(!local){
		gf_log(this->name, GF_LOG_ERROR, "out of memory");
		return NULL;	
	}
	local->fop = fop;

	frame->local = local; 

	return local;
}

/****************************************************************************
普通文件相关的权限控制，集中在以下几个函数：
open、unlink、rename、truncate
由于很多函数的参数是fd，比方说readv,writev，而要想获取fd首先就要调用open;
所以如果能够在open上加以权限控制，间接就控制了这些函数的调用
*****************************************************************************/
static int32_t
ac_open_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
		  fd_t *fd)
{
	ac_local_t* local = frame->local;
	
	//下面这部分用于时间测试，在en_open中记录开始时间，在此处记录结束时间	
	/*	
	gettimeofday(&local->end_time, NULL);
	int diftime = (local->end_time.tv_sec - local->start_time.tv_sec)*1000000 + (local->end_time.tv_usec - local->start_time.tv_usec);
	gf_log("abac", GF_LOG_TRACE, "use time:%dus", diftime);
	
	FILE* time_file = fopen("/home/lwfs/time_result_abac", "a");
	fwrite(local->loc->path, strlen(local->loc->path), 1, time_file);
	fwrite(":", 1, 1, time_file);
	//fwrite(&diftime, sizeof(int), 1, time_file);
	char str[10];
	memset(str, 0, 10);
	sprintf(str, "%d", diftime);
	fwrite(str, strlen(str), 1, time_file);
	fwrite("\n", 1, 1, time_file);

	fclose(time_file);
	*/

	if(local->fd)
		fd_unref(local->fd);
	if(local->loc){
		loc_wipe(local->loc);
		FREE(local->loc);
	}

	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      fd);
	return 0;
}

int32_t
ac_open (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *loc,
	      int32_t flags, fd_t *fd,
              int32_t wbflags)
{
	gf_log(this->name, GF_LOG_TRACE, "enter ac_open");
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	ac_local_t* local ;	

	local = ac_alloc_local(frame, this, GF_FOP_OPEN);
	if(!local){
		op_errno = 12;
		goto error;	
	}
	local->loc = CALLOC(1, sizeof(*loc));
	if(!local->loc){
		op_errno = 12;
		goto error;	
	}
	memset(local->loc, 0, sizeof(*local->loc));
	op_ret = loc_copy(local->loc, loc);
	if (op_ret) {
		FREE(local->loc);
		op_errno = 12;
		goto error;
	}
	
	local->fd = fd_ref(fd);
	local->flags = flags;
	local->wbflags = wbflags;
	
	//gettimeofday(&local->start_time, NULL);

	//读取策略扩展属性
	STACK_WIND(frame, 
		attraccess, 
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->getxattr,
		local->loc,
		POLICY_XATTR);
	return 0;

error:
	STACK_UNWIND_STRICT(open, frame, -1, op_errno, NULL);
	return 0;
}

static int32_t
ac_unlink_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
                    struct stat *preparent,
                    struct stat *postparent)
{
	ac_local_t* local = frame->local;
	if(local->loc){
		loc_wipe(local->loc);
		FREE(local->loc);	
	}
	
	STACK_UNWIND (frame, op_ret, op_errno, preparent, postparent);
	return 0;
}

int32_t
ac_unlink (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc)
{
	gf_log(this->name, GF_LOG_TRACE, "enter ac_unlink");
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	ac_local_t* local ;	

	local = ac_alloc_local(frame, this, GF_FOP_UNLINK);
	if(!local){
		op_errno = 12;
		goto error;	
	}
	local->loc = CALLOC(1, sizeof(*loc));
	if(!local->loc){
		op_errno = 12;
		goto error;	
	}
	memset(local->loc, 0, sizeof(*local->loc));
	op_ret = loc_copy(local->loc, loc);
	if (op_ret) {
		FREE(local->loc);
		op_errno = 12;
		goto error;
	}
	
	//读取策略扩展属性
	STACK_WIND(frame, 
		attraccess, 
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->getxattr,
		local->loc,
		POLICY_XATTR);
	return 0;

error:
	STACK_UNWIND_STRICT(unlink, frame, op_ret, op_errno, NULL, NULL);
	return 0;
}

static int32_t
ac_rename_cbk (call_frame_t *frame,
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
	ac_local_t* local = frame->local;
	if(local->loc){
		loc_wipe(local->loc);
		FREE(local->loc);
	}
	if(local->newloc){
		loc_wipe(local->newloc);
		FREE(local->newloc);
	}
	STACK_UNWIND (frame, op_ret, op_errno, buf, preoldparent, postoldparent,
                      prenewparent, postnewparent);
	return 0;
}

int32_t
ac_rename (call_frame_t *frame,
		xlator_t *this,
		loc_t *oldloc,
		loc_t *newloc)
{
	gf_log(this->name, GF_LOG_TRACE, "enter ac_rename");
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	ac_local_t* local;	

	local = ac_alloc_local(frame, this, GF_FOP_RENAME);
	if(!local){
		op_errno = 12;
		goto error;	
	}
	local->loc = CALLOC(1, sizeof(*oldloc));
	if(!local->loc){
		op_errno = 12;
		goto error;	
	}
	local->newloc = CALLOC(1, sizeof(*newloc));
	if(!local->newloc){
		op_errno = 12;
		FREE(local->loc);
		goto error;
	}
	memset(local->loc, 0, sizeof(*local->loc));
	memset(local->newloc, 0, sizeof(*local->newloc));

	op_ret = loc_copy(local->loc, oldloc);
	if (op_ret) {
		FREE(local->loc);
		FREE(local->newloc);
		op_errno = 12;
		goto error;
	}
	op_ret = loc_copy(local->newloc, newloc);
	if (op_ret) {
		FREE(local->loc);
		FREE(local->newloc);
		op_errno = 12;
		goto error;
	}
	
	//读取策略扩展属性
	STACK_WIND(frame, 
		attraccess, 
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->getxattr,
		local->loc,
		POLICY_XATTR);
	return 0;

error:
	STACK_UNWIND_STRICT(rename, frame, op_ret, op_errno, NULL, NULL, NULL, NULL, NULL);
	return 0;	
}

static int32_t
ac_truncate_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno,
		      struct stat *prebuf,
                      struct stat *postbuf)
{
	ac_local_t* local = frame->local;
	if(local->loc){
		loc_wipe(local->loc);
		FREE(local->loc);
	}
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      prebuf,
                      postbuf);
	return 0;
}

int32_t
ac_truncate (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  off_t offset)
{
	gf_log(this->name, GF_LOG_TRACE, "enter ac_truncate");
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	ac_local_t* local ;	

	local = ac_alloc_local(frame, this, GF_FOP_TRUNCATE);
	if(!local){
		op_errno = 12;
		goto error;	
	}
	local->loc = CALLOC(1, sizeof(*loc));
	if(!local->loc){
		op_errno = 12;
		goto error;	
	}
	memset(local->loc, 0, sizeof(*local->loc));
	op_ret = loc_copy(local->loc, loc);
	if (op_ret) {
		FREE(local->loc);
		op_errno = 12;
		goto error;
	}
	local->offset = offset;
	
	//读取策略扩展属性
	STACK_WIND(frame, 
		attraccess, 
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->getxattr,
		local->loc,
		POLICY_XATTR);
	return 0;

error:
	STACK_UNWIND_STRICT(truncate, frame, op_ret, op_errno, NULL, NULL);
	return 0;
}

/******************************************************************************
目录项相关的权限控制，集中在以下两个函数：
opendir、rmdir
******************************************************************************/
static int32_t
ac_opendir_cbk (call_frame_t *frame,
		     void *cookie,
		     xlator_t *this,
		     int32_t op_ret,
		     int32_t op_errno,
		     fd_t *fd)
{
	ac_local_t* local = frame->local;
	fd_unref(local->fd);
	if(local->loc){
		loc_wipe(local->loc);
		FREE(local->loc);
	}
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      fd);
	return 0;
}

int32_t
ac_opendir (call_frame_t *frame,
		 xlator_t *this,
		 loc_t *loc, fd_t *fd)
{
	//gf_log(this->name, GF_LOG_TRACE, "enter ac_opendir");
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	ac_local_t* local ;	

	local = ac_alloc_local(frame, this, GF_FOP_OPENDIR);
	if(!local){
		op_errno = 12;
		goto error;	
	}
	local->loc = CALLOC(1, sizeof(*loc));
	if(!local->loc){
		op_errno = 12;
		goto error;	
	}
	memset(local->loc, 0, sizeof(*local->loc));
	op_ret = loc_copy(local->loc, loc);
	if (op_ret) {
		FREE(local->loc);
		op_errno = 12;
		goto error;
	}
	
	local->fd = fd_ref(fd);
	
	//读取策略扩展属性
	STACK_WIND(frame, 
		attraccess, 
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->getxattr,
		local->loc,
		POLICY_XATTR);
	return 0;

error:
	STACK_UNWIND_STRICT(opendir, frame, -1, op_errno, NULL);
	return 0;
}

static int32_t
ac_rmdir_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
                   struct stat *preparent,
                   struct stat *postparent)
{
	ac_local_t* local = frame->local;
	if(local->loc){
		loc_wipe(local->loc);
		FREE(local->loc);
	}
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
                      preparent,
                      postparent);
	return 0;
}

int32_t
ac_rmdir (call_frame_t *frame,
	       xlator_t *this,
	       loc_t *loc)
{
	gf_log(this->name, GF_LOG_TRACE, "enter ac_rmdir");
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	ac_local_t* local ;	

	local = ac_alloc_local(frame, this, GF_FOP_RMDIR);
	if(!local){
		op_errno = 12;
		goto error;	
	}
	local->loc = CALLOC(1, sizeof(*loc));
	if(!local->loc){
		op_errno = 12;
		goto error;	
	}
	memset(local->loc, 0, sizeof(*local->loc));
	op_ret = loc_copy(local->loc, loc);
	if (op_ret) {
		FREE(local->loc);
		op_errno = 12;
		goto error;
	}
	
	//读取策略扩展属性
	STACK_WIND(frame, 
		attraccess, 
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->getxattr,
		local->loc,
		POLICY_XATTR);
	return 0;

error:
	STACK_UNWIND_STRICT(rmdir, frame, op_ret, op_errno, NULL, NULL);
	return 0;
}

/********************************************************************************
扩展属性相关的权限控制，集中在以下两个函数：
setxattr、removexattr
但是，只有当用户想要更改访问策略相关扩展属性的时候才需要进行控制；其他扩展属性应当开放
需要控制的扩展属性：user.policy
********************************************************************************/


//注：default(非user.policy)扩展属性的cbk必须单独出来（不然会错误释放内存报错）
//    因为default情况是直接wind,并没有创建local
//    也可以对于default设置local,但是这样会造成不必要的资源浪费
static int32_t
ac_setxattr_default_cbk (call_frame_t *frame,
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

static int32_t
ac_setxattr_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno)
{
	ac_local_t* local = frame->local;
	if(local->dict)
		dict_unref(local->dict);
	if(local->loc){
		loc_wipe(local->loc);
		FREE(local->loc);
	}
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno);
	return 0;
}

int32_t
ac_setxattr (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  dict_t *dict,
		  int32_t flags)
{
	
	data_t* data = dict_get(dict, "user.policy");
	if(!data)
		goto wind;	
	//如果是对user.policy扩展属性进行修改，就需要进行访问控制
	gf_log("access control", GF_LOG_TRACE, "set user.policy , should be access-controlled");
	
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	ac_local_t* local ;	

	local = ac_alloc_local(frame, this, GF_FOP_SETXATTR);
	if(!local){
		op_errno = 12;
		goto error;	
	}
	local->loc = CALLOC(1, sizeof(*loc));
	if(!local->loc){
		op_errno = 12;
		goto error;	
	}
	memset(local->loc, 0, sizeof(*local->loc));
	op_ret = loc_copy(local->loc, loc);
	if (op_ret) {
		FREE(local->loc);
		op_errno = 12;
		goto error;
	}
	local->dict = dict_ref(dict);
	local->flags = flags;
	
	//读取策略扩展属性
	STACK_WIND(frame, 
		attraccess, 
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->getxattr,
		local->loc,
		POLICY_XATTR);
	return 0;
	
	
wind:
	STACK_WIND (frame,
		    ac_setxattr_default_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->setxattr,
		    loc, dict, flags);
	return 0;

error:
	STACK_UNWIND_STRICT(setxattr, frame, -1, op_errno);
	return 0;
}

static int32_t
ac_removexattr_default_cbk (call_frame_t *frame,
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

static int32_t
ac_removexattr_cbk (call_frame_t *frame,
			 void *cookie,
			 xlator_t *this,
			 int32_t op_ret,
			 int32_t op_errno)
{
	ac_local_t* local = frame->local;
	if(local->loc){
		loc_wipe(local->loc);
		FREE(local->loc);
	}
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno);
	return 0;
}

int32_t
ac_removexattr (call_frame_t *frame,
		     xlator_t *this,
		     loc_t *loc,
		     const char *name)
{
	//gf_log("access control", GF_LOG_TRACE, "enter removexattr");
	if(strncmp(name, "user.policy", 11))
		goto wind;

	//如果是对user.policy扩展属性进行删除，就需要进行访问控制
	gf_log("access control", GF_LOG_TRACE, "remove user.policy , should be access-controlled");
	
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	ac_local_t* local ;	

	local = ac_alloc_local(frame, this, GF_FOP_REMOVEXATTR);
	if(!local){
		op_errno = 12;
		goto error;	
	}
	local->loc = CALLOC(1, sizeof(*loc));
	if(!local->loc){
		op_errno = 12;
		goto error;	
	}
	memset(local->loc, 0, sizeof(*local->loc));
	op_ret = loc_copy(local->loc, loc);
	if (op_ret) {
		FREE(local->loc);
		op_errno = 12;
		goto error;
	}
	local->name = name;
	
	//读取策略扩展属性
	STACK_WIND(frame, 
		attraccess,
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->getxattr,
		local->loc,
		POLICY_XATTR);
	return 0;
	
wind:
	STACK_WIND (frame,
		    ac_removexattr_default_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->removexattr,
		    loc,name);
	return 0;

error:
	STACK_UNWIND_STRICT(removexattr, frame, -1, op_errno);
	return 0;

}


/*******************************************************************
功能：getxattr的cbk, 判断权限并且进行wind
*******************************************************************/
static int32_t attraccess(call_frame_t *frame,
				void *cookie,
				xlator_t *this,
				int32_t op_ret,
				int32_t op_errno,
				dict_t *dict)
{
	data_t* data;
	ac_local_t* local = frame->local;

	if(op_ret < 0){
		goto error;
	}
	data = dict_get(dict, POLICY_XATTR);
	if(!data){
		//gf_log(this->name, GF_LOG_TRACE, "%s does not have policy, can be visited straightly",
								//local->loc->path);
		goto wind;
	}
	gf_log("access control", GF_LOG_TRACE, "%s 's policy :%s", local->loc->path, data_to_str(data));
	//root权限的进程不需要进行访问控制
	if(frame->root->uid == 0){
		gf_log("access control", GF_LOG_TRACE, "root process needn't check authority");
		goto wind;
	}

	//gf_log("access control", GF_LOG_TRACE, "uid:%d", frame->root->uid);
	//struct passwd *uMessage = getpwuid(frame->root->uid);
	/*根据用户的个人信息取出该用户的属性值
	 *此处后面需要改为ldap接口	
	*/
	//挂载分离式的lwfs，传过来的信息只有一个uid，怎么控制？？

	//gf_log("access control", GF_LOG_TRACE, "name:%s", uMessage->pw_name);

	char attr[LENGEST_ATTR_LENGTH];
	if(!getUserAttr(frame->root->uid, attr))
	{
		op_errno = 61;
		goto error;
	}
	gf_log("access control", GF_LOG_TRACE, "%d's attr:%s", frame->root->uid, attr);

	/*根据获取的Policy和取得的attr进行权限判断*/			
	Node* policy_root= generateTree(data_to_str(data));
	if(!match(policy_root,attr))
	{
		free_tree(policy_root);
		op_errno = 13;
		goto error;
	}
	free_tree(policy_root);
wind:
	switch(local->fop){
		case GF_FOP_OPEN:
			STACK_WIND (frame,
				ac_open_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->open,
				local->loc,
				local->flags,
				local->fd,
				local->wbflags);
			break;
		case GF_FOP_UNLINK:
			STACK_WIND(frame,
				ac_unlink_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->unlink,
				local->loc);
			break;
		case GF_FOP_RENAME:
			STACK_WIND(frame,
				ac_rename_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->rename,
				local->loc,
				local->newloc);
			break;
		case GF_FOP_TRUNCATE:
			STACK_WIND(frame,
				ac_truncate_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->truncate,
				local->loc,
				local->offset);
			break;
		case GF_FOP_OPENDIR:
			STACK_WIND(frame,
				ac_opendir_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->opendir,
				local->loc,
				local->fd);
			break;
		case GF_FOP_RMDIR:
			STACK_WIND(frame,
				ac_rmdir_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->rmdir,
				local->loc);
			break;
		case GF_FOP_SETXATTR:
			STACK_WIND(frame,
				ac_setxattr_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->setxattr,
				local->loc,
				local->dict,
				local->flags);
			break;
		case GF_FOP_REMOVEXATTR:
			STACK_WIND(frame,
				ac_removexattr_cbk,
				FIRST_CHILD(this),
				FIRST_CHILD(this)->fops->removexattr,
				local->loc,
				local->name);
			break;
		default:
			gf_log(this->name, GF_LOG_WARNING,
					"Improper file operation %d", local->fop);
	}
	return 0;

error:
	if(local->loc){
		loc_wipe(local->loc);
		FREE(local->loc);
	}
	switch(local->fop){
		case GF_FOP_OPEN:
			fd_unref(local->fd);
			STACK_UNWIND_STRICT(open, frame, -1, op_errno, NULL);
			break;
		case GF_FOP_UNLINK:
			STACK_UNWIND_STRICT(unlink, frame, -1, op_errno, NULL, NULL);
			break;
		case GF_FOP_RENAME:
			if(local->newloc){
				loc_wipe(local->newloc);
				FREE(local->newloc);
			}
			STACK_UNWIND_STRICT(rename, frame, -1, op_errno, NULL, NULL, NULL, NULL, NULL);
			break;
		case GF_FOP_TRUNCATE:
			STACK_UNWIND_STRICT(truncate, frame, -1, op_errno, NULL, NULL);
			break;
		case GF_FOP_OPENDIR:
			fd_unref(local->fd);
			STACK_UNWIND_STRICT(opendir, frame, -1, op_errno, NULL);
			break;
		case GF_FOP_RMDIR:
			STACK_UNWIND_STRICT(rmdir, frame, -1, op_errno, NULL, NULL);
			break;
		case GF_FOP_SETXATTR:
			if(local->dict)
				dict_unref(local->dict);
			STACK_UNWIND_STRICT(setxattr, frame, -1, op_errno);
			break;
		case GF_FOP_REMOVEXATTR:
			STACK_UNWIND_STRICT(removexattr, frame, -1, op_errno);			
			break;
		default:
			gf_log(this->name, GF_LOG_WARNING,
					"Improper file operation %d", local->fop);
	}
	return 0;	
}

/****************************************************
功能：获取一个指定用户的属性值
输入：用户名
输出：属性值
返回：成功返回1，失败返回0
说明：假设系统所有的属性值存储在/home/lwfs/userAttr文件中
****************************************************/
//int getUserAttr(const char *username ,char *attr)
int getUserAttr(int uid, char* attr)
{
	char line[128];
	memset(line,0,sizeof(line));

	char str[5];
	memset(str, 0 , 5);
	sprintf(str, "%d", uid);

	FILE *attrFp= NULL;
	if(!(attrFp=fopen("/home/lwfs/userAttr","r")))
		return 0;
	while(!feof(attrFp))
	{
		if(NULL == fgets(line,sizeof(line),attrFp))
		{
			break;
		}
		if(strstr(line,str))
		{
			char *ptr = line+strlen(str)+1;
			int i=0;
			while(*ptr!='\n')
			{
				attr[i]=*ptr;
				++ptr;
				++i;
			}
			attr[i]='\0';
			break;
		}
		else 
		{
			continue;
		}
	}
	if(strlen(attr)==0)
		return 0;

	fclose(attrFp);
	return 1;
}



int32_t
init (xlator_t *this)
{
	int ret = 0;
	
	if (!this->children || this->children->next) {
		gf_log ("ac", GF_LOG_ERROR, 
			"FATAL: ac should have exactly one child");
		ret = -1;		
		goto out;
	}

	if (!this->parents) {
		gf_log (this->name, GF_LOG_WARNING,
			"dangling volume. check volfile ");
	}

	umask(000);
	
	/*
	priv = CALLOC (sizeof (struct ac_private), 1);
	if(!priv){
		gf_log(this->name, GF_LOG_ERROR, "out of memory");
		ret = -1;
		goto out;
	}*/

	gf_log ("ac", GF_LOG_DEBUG, "ac xlator loaded");
	return 0;

out:
	return ret;
}

void 
fini (xlator_t *this)
{
	//struct ac_private *priv = this->private;
	
	//FREE (priv);
	
	return;
}

struct xlator_fops fops = {
	.open		 =  ac_open,
	.unlink	 =  ac_unlink,
	.rename	 =  ac_rename,
	.truncate 	 =  ac_truncate,
	.opendir	 =  ac_opendir,
	.rmdir	 =  ac_rmdir,
	.setxattr	 =  ac_setxattr,
	.removexattr =  ac_removexattr 
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key  = {NULL} },
};
