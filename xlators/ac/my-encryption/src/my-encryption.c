#include <ctype.h>
#include <sys/uio.h>
#include <stdbool.h>

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "lwfs.h"
#include "xlator.h"
#include "logging.h"

#include "my-encryption.h"
#include "defaults.c"

/*
所有的操作针对于加密和非加密的文件都需要分开处理
	非加密文件默认处理，加密文件特殊处理
*/

int CRYPT_BLOCK_SIZE;
int PTHREAD_COUNT;
bswabe_pub_t* pub;

extern struct aes_key_cache_from_priv key_cache;

static int32_t load_file_size(call_frame_t* frame, void* cookie,
					xlator_t* this, int32_t op_ret, int32_t op_errno,
					dict_t* dict);

static void update_local_file_params(call_frame_t* frame,
						xlator_t* this,
						struct stat* prebuf,
						struct stat* postbuf);

//static int32_t crypt_writev_done(call_frame_t *frame, void *cookie,
						 //xlator_t *this, int32_t op_ret, int32_t op_errno);


inline bool is_AES(char* str)
{
	return ((str[0] == 'A') && (str[1] == 'E') && (str[2] == 'S'));
}

inline bool is_ABE(char* str)
{
	return ((str[0] == 'A') && (str[1] == 'B') && (str[2] == 'E'));
}

static en_local_t * en_alloc_local(call_frame_t* frame, xlator_t* this, lwfs_fop_t fop)
{
	en_local_t* local;
	
	local = CALLOC(1 , sizeof(*local));
	if(!local){
		gf_log(this->name, GF_LOG_ERROR, "out of memory");
		return NULL;	
	}
	local->fop = fop;

	frame->local = local; 

	return local;
}

static int32_t load_file_size(call_frame_t* frame, void* cookie,
					xlator_t* this, int32_t op_ret, int32_t op_errno,
					dict_t* dict)
{
	data_t *data;
	en_local_t *local = frame->local;

	if (op_ret < 0)
		goto unwind;
	/*
	 * load regular file size
	 */
	data = dict_get(dict, FSIZE_XATTR_PREFIX);
	if (!data) {
		gf_log(this->name, GF_LOG_WARNING, "%s 's Regular file size not found",local->loc->path);
		op_ret = -1;
		op_errno = 61;
		goto unwind;
	}
	//st_size为off_t类型
	
	if(sizeof(off_t) == 4)
		local->buf.st_size = data_to_uint32(data);
	else
		local->buf.st_size = data_to_uint64(data);

	gf_log(this->name, GF_LOG_DEBUG,
	       "FOP %d: Translate regular file to %llu",
	       local->fop,
	       (unsigned long long)local->buf.st_size);
 unwind:
	if (local->fd)
		fd_unref(local->fd);
	if (local->loc) {
		loc_wipe(local->loc);
		FREE(local->loc);
	}
	switch (local->fop) {
	case GF_FOP_FSTAT:
		STACK_UNWIND_STRICT(fstat,
				    frame,
				    op_ret >= 0 ? 0 : -1,	//此处不修正文件系统会报错
				    op_errno,
				    op_ret >= 0 ? &local->buf : NULL);
		break;
	case GF_FOP_STAT:
		STACK_UNWIND_STRICT(stat,
				    frame,
				    op_ret >= 0 ? 0 : -1,	//此处不修正文件系统会报错
				    op_errno,
				    op_ret >= 0 ? &local->buf : NULL);
		break;
	case GF_FOP_LOOKUP:
		STACK_UNWIND_STRICT(lookup,
				    frame,
				    op_ret,
				    op_errno,
				    op_ret >= 0 ? local->inode : NULL,
				    op_ret >= 0 ? &local->buf : NULL,
				     NULL,
				    op_ret >= 0 ? &local->postbuf : NULL);
		break;
	case GF_FOP_READ:	
		STACK_UNWIND_STRICT(readv,
				    frame,
				    op_ret >= 0 ? 0 : -1,
				    op_errno,
				    NULL,
				    0,
				    op_ret >= 0 ? &local->buf : NULL,
				    NULL);
		break;
	default:
		gf_log(this->name, GF_LOG_WARNING,
		       "Improper file operation %d", local->fop);
	}
	return 0;
}

static void update_local_file_params(call_frame_t* frame,
						xlator_t* this,
						struct stat* prebuf,
						struct stat* postbuf)
{
	en_local_t* local = frame->local;
	
	local->prebuf = *prebuf;
	local->postbuf = *postbuf;

	local->prebuf.st_size = local->cur_file_size;
	local->postbuf.st_size = local->new_file_size;

	local->cur_file_size = local->new_file_size;
}

static int32_t crypt_stat_common_cbk(call_frame_t *frame,
				     void *cookie,
				     xlator_t *this,
				     int32_t op_ret,
				     int32_t op_errno,
				     struct stat *buf)
{
	en_local_t *local = frame->local;
	
	//对于非普通文件和stat失败的文件，直接调用UNWIND
	if (op_ret < 0)
		goto unwind;
	if (!S_ISREG(buf->st_mode))
		goto unwind;

	local->buf = *buf;

	//gf_log("-----", GF_LOG_TRACE, "%d,GF_FOP_STAT%d,GF_FOP_FSTAT%d", local->fop, GF_FOP_STAT, GF_FOP_FSTAT);
	switch (local->fop) {
	case GF_FOP_FSTAT:
		STACK_WIND(frame,
			   load_file_size,
			   FIRST_CHILD(this),
			   FIRST_CHILD(this)->fops->fgetxattr,
			   local->fd,
			   FSIZE_XATTR_PREFIX);
		break;
	case GF_FOP_STAT:
		STACK_WIND(frame,
			   load_file_size,
			   FIRST_CHILD(this),
			   FIRST_CHILD(this)->fops->getxattr,
			   local->loc,
			   FSIZE_XATTR_PREFIX);
		break;
	default:
		gf_log (this->name, GF_LOG_WARNING,
			"Improper file operation %d", local->fop);
	}
	return 0;

 unwind:
	if (local->fd)
		fd_unref(local->fd);
	if (local->loc) {
		loc_wipe(local->loc);
		FREE(local->loc);
	}
	switch (local->fop) {
	case GF_FOP_FSTAT:
		STACK_UNWIND_STRICT(fstat,
				    frame,
				    op_ret,
				    op_errno,
				    op_ret >= 0 ? buf : NULL);
		break;
	case GF_FOP_STAT:
		STACK_UNWIND_STRICT(stat,
				    frame,
				    op_ret,
				    op_errno,
				    op_ret >= 0 ? buf : NULL);
		break;
	default:
		gf_log (this->name, GF_LOG_WARNING,
			"Improper file operation %d", local->fop);
	}
	return 0;
}

static int32_t
def_stat_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
		  struct stat *buf)
{
	en_local_t* local = frame->local;
	if(local->loc){
		loc_wipe(local->loc);
		//gf_log("---def",GF_LOG_TRACE, "----");
		free(local->loc);
	}
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      buf);
	return 0;
}

static int32_t do_stat(call_frame_t *frame,
			      void *cookie,
			      xlator_t *this,
			      int32_t op_ret,
			      int32_t op_errno,
			      dict_t *dict)
{
	
	en_local_t* local = frame->local;

	if(op_ret < 0)
	{
		goto error;
	}
	
	data_t* data = dict_get(dict, ENCRYPT_XATTR);
	if(!data){		//没有加密的文件正常处理
		gf_log(this->name, GF_LOG_TRACE, "not encrypted file, WIND default:%s",local->loc->path);
		goto def;	
	}

	gf_log(this->name, GF_LOG_TRACE	, "encrypted file bengin to stat:%s",local->loc->path);
	
	STACK_WIND(frame, 
		crypt_stat_common_cbk,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->stat,
		local->loc);
	return 0;

def:
	
	STACK_WIND (frame,
		    def_stat_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->stat,
		    local->loc);
	return 0;

error:
	if(local->loc){
		loc_wipe(local->loc);
		free(local->loc);
	}
	STACK_UNWIND_STRICT(stat, frame, op_ret, op_errno, NULL);
	return 0;
}

int32_t
en_stat (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *loc)
{
	//gf_log(this->name, GF_LOG_TRACE, "%s",loc->path);

	int32_t op_ret = -1;
	int32_t op_errno = 1;
	en_local_t* local;
	
	local = en_alloc_local(frame, this, GF_FOP_STAT);
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
	if(op_ret){
		op_errno = 12;
		FREE(local->loc);
		goto error;
	}
	
	//判断是否为加密文件
	STACK_WIND(frame,
			do_stat,
			FIRST_CHILD(this),
			FIRST_CHILD(this)->fops->getxattr,
			loc,
			ENCRYPT_XATTR);
	return 0;

error:
	STACK_UNWIND_STRICT(stat, frame, op_ret, op_errno, NULL);
	return 0;
}

static int32_t
def_fstat_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct stat *buf)
{
	en_local_t* local = frame->local;
	
	fd_unref(local->fd);
	
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      buf);
	return 0;
}

static int32_t do_fstat(call_frame_t *frame,
			      void *cookie,
			      xlator_t *this,
			      int32_t op_ret,
			      int32_t op_errno,
			      dict_t *dict)
{
	
	en_local_t* local = frame->local;

	if(op_ret < 0)
	{
		goto error;
	}
	
	data_t* data = dict_get(dict, ENCRYPT_XATTR);
	if(!data){		//没有加密的文件正常处理
		//gf_log(this->name, GF_LOG_TRACE, "not encrypted file, WIND default");
		goto def;	
	}

	gf_log(this->name, GF_LOG_TRACE, "encrypted file bengin to fstat!");
	
	STACK_WIND(frame, 
		crypt_stat_common_cbk,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->fstat,
		local->fd);
	return 0;

def:
	STACK_WIND (frame,
		    def_fstat_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fstat,
		    local->fd);

	return 0;

error:
	if(local->fd)
		fd_unref(local->fd);
	STACK_UNWIND_STRICT(fstat, frame, op_ret, op_errno, NULL);
	return 0;
}

int32_t
en_fstat (call_frame_t *frame,
	       xlator_t *this,
	       fd_t *fd)
{
	int op_ret = -1;
	int op_errno = 1;
	
	en_local_t *local;
	local = en_alloc_local(frame, this, GF_FOP_FSTAT);
	if(!local){
		op_errno = 12;
		goto error;	
	}
	
	local->fd = fd_ref(fd);
	
	STACK_WIND (frame,
		    do_fstat,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fgetxattr,
		    fd,
		    ENCRYPT_XATTR);
	return 0;

error:
 	STACK_UNWIND_STRICT(fstat, frame, op_ret, op_errno, NULL);
	return 0;
}


int32_t
en_access (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc,
		int32_t mask)
{
	//gf_log(this->name, GF_LOG_TRACE, "path:%s, mask:%d", loc->path, mask);
	STACK_WIND (frame,
		    default_access_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->access,
		    loc,
		    mask);
	return 0;
}

int32_t
en_setxattr (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  dict_t *dict,
		  int32_t flags)
{
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	char* real_path = NULL;
	//char* pub_path = NULL;
	char* priv_path = NULL;

	data_t* data = dict_get(dict, ENCRYPT_XATTR);
	//对user.encrypt扩展属性的修改，表示需要更改该文件底层的存储方式
	if(!data)
		goto def;
	gf_log(this->name, GF_LOG_TRACE, "%swill setxattr encrypt: %s",  loc->path, data->data);
	
	MAKE_REAL_PATH (real_path, this, loc->path);
	//MAKE_PUB_PATH (pub_path, this);
	MAKE_PRIV_PATH (priv_path, this);


	//先看文件是否已经被加密，如果是，则需要先按照相应的方式解密
	//就算前后设置加密属性相同，也需要先解密，因为有可能更改了policy，则加密密钥也需要更改
	char enc_policy[4];
	memset(enc_policy, 0, 4*sizeof(char));
	int res = lgetxattr(real_path, ENCRYPT_XATTR, enc_policy, 4*sizeof(char));
	if(res != -1)
	{
		if(is_AES(enc_policy))
		{
			aes_decrypt_file(real_path);
		}
		else if(is_ABE(enc_policy))
		{
			if(cpabe_decrypt_file(real_path, priv_path) == -1)
			{
				gf_log(this->name, GF_LOG_WARNING, "the priv can not decrypt!");
				op_errno = 13;				
				goto error;
			}
		}
		else
		{
			op_errno = 61;
			goto error;	
		}
	}

	//测试专用
	
	en_local_t *local;
	local = en_alloc_local(frame, this, GF_FOP_FSETXATTR);
	if(!local){
		op_errno = 12;
		goto error;	
	}
	gettimeofday(&local->start_time, NULL);
	//*/

	//加密之前先保存文件的原始长度
	struct stat file_stat;
	stat(real_path, &file_stat);
	

	//执行加密
	if(is_AES(data->data))
	{
		aes_encrypt_file(real_path);
	}
	else if(is_ABE(data->data))
	{
		char policy[LONGEST_POLICY_LENGTH];
		memset(policy, 0, LONGEST_POLICY_LENGTH * sizeof(char));
		res = lgetxattr(real_path, "user.policy", policy, LONGEST_POLICY_LENGTH*sizeof(char));
		if(res == -1)
		{
			gf_log(this->name, GF_LOG_WARNING, "can not get policy!");
			op_errno = 61;
			goto error;
		}
		//gf_log(this->name, GF_LOG_TRACE, "the policy used for cpabe encryption: %d%d%d%d%d%d", policy[0], policy[1], policy[2], policy[3], policy[4], policy[5]);
		gf_log(this->name, GF_LOG_TRACE, "real_path:%s", real_path);
		if(cpabe_encrypt_file(real_path, policy) == -1)
		{
			gf_log(this->name, GF_LOG_WARNING, "the policy cannot gennerate aeskey!");
			op_errno = 22;				
			goto error;
		}
	}
	else
	{
		gf_log(this->name, GF_LOG_ERROR, "Only two encryption methods are currently supported!");
		op_errno = 22;
		goto error;
	}
	
	//加密完成之后保存文件长度扩展属性
	data_t *len_data = data_from_uint64(file_stat.st_size);
	gf_log("-----", GF_LOG_TRACE, "will setxattr length: %d %s", data_to_uint64(len_data), len_data->data);	
	if(lsetxattr(real_path, FSIZE_XATTR_PREFIX, len_data->data, len_data->len, 0) == -1)
	{
		gf_log(this->name, GF_LOG_ERROR, "set xattr error!");
		goto error;
	}
	/*
	int len = file_stat.st_size;
	if(lsetxattr(real_path, FSIZE_XATTR_PREFIX, &len, sizeof(off_t), 0) == -1)
	{
		gf_log(this->name, GF_LOG_ERROR, "set xattr error!");
		goto error;
	}
	*/

	///*测试
	gettimeofday(&local->end_time, NULL);
	int diftime = (local->end_time.tv_sec - local->start_time.tv_sec)*1000000 + (local->end_time.tv_usec - local->start_time.tv_usec);
    gf_log("encrypt", GF_LOG_TRACE, "encrypt totally use time:%dus", diftime);

    FILE* time_file = fopen("/home/lwfs/time_result_enc", "a");
    fwrite(loc->path, strlen(loc->path), 1, time_file);
    fwrite(":", 1, 1, time_file);
    char str[10];
    memset(str, 0, 10);
    sprintf(str, "%d", diftime);
    fwrite(str, strlen(str), 1, time_file);
    fwrite("\n", 1, 1, time_file);

    fclose(time_file);
	//*/

def:
	STACK_WIND (frame,
		    default_setxattr_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->setxattr,
		    loc,
		    dict,
		    flags);
	return 0;

error:
	STACK_UNWIND_STRICT(setxattr, frame, op_ret, op_errno);
	return 0;
}


int32_t
en_removexattr (call_frame_t *frame,
		     xlator_t *this,
		     loc_t *loc,
		     const char *name)
{
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	char* real_path = NULL;
	//char* pub_path = NULL;
	char* priv_path = NULL;

	//对user.encrypt扩展属性的移除，需要将底层的密文存储还原成明文
	if(strcmp(name, ENCRYPT_XATTR))
		goto def;
	gf_log(this->name, GF_LOG_TRACE, "will removexattr : ENCRYPT_XATTR, begin to decrypt file!");
	
	MAKE_REAL_PATH (real_path, this, loc->path);
	//MAKE_PUB_PATH (pub_path, this);
	MAKE_PRIV_PATH (priv_path, this);
	
	char enc_policy[4];
	memset(enc_policy, 0, 4*sizeof(char));
	int res = lgetxattr(real_path, ENCRYPT_XATTR, enc_policy, 4*sizeof(char));
	if(res != -1)
	{
		if(is_AES(enc_policy))
		{
			aes_decrypt_file(real_path);
		}
		else if(is_ABE(enc_policy))
		{
			if(cpabe_decrypt_file(real_path, priv_path) == -1)
			{
				gf_log(this->name, GF_LOG_WARNING, "the priv can not decrypt!");
				op_errno = 13;				
				goto error;
			}
		}
		else
		{
			op_errno = 61;
			goto error;	
		}
		
		//删除长度扩展属性
		if(lremovexattr(real_path, FSIZE_XATTR_PREFIX) == -1)
		{
			gf_log(this->name, GF_LOG_ERROR, "remove size attr error!");
			goto error;
		}
	}
	else
	{
		gf_log(this->name, GF_LOG_WARNING, "not be encrypted, can remove straightly!");
		goto def;
	}

def:
	STACK_WIND (frame,
		    default_removexattr_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->removexattr,
		    loc,
		    name);
	return 0;

error:
	STACK_UNWIND_STRICT(removexattr, frame, op_ret, op_errno);
	return 0;
}


static int32_t crypt_readv_done(call_frame_t *frame,
				  xlator_t *this)
{
	en_local_t *local = frame->local;
	fd_t *local_fd = local->fd;


	struct iobref *iobref = local->iobref;
	struct iobref *iobref_data = local->iobref_data;
	struct iovec* avec = local->iovec_to_decrypt;

	gf_log("crypt", GF_LOG_DEBUG,
	       "readv: ret_to_user: %d, iovec len: %d, st_size: %llu",
	       (int)(local->rw_count > 0 ? local->rw_count : local->op_ret),
	       (int)(local->rw_count > 0 ? iov_length(avec, local->iovec_count) : 0),
	       (unsigned long long)local->buf.st_size);

	STACK_UNWIND_STRICT(readv,
			    frame,
			    local->rw_count > 0 ? local->rw_count : local->op_ret,
			    local->op_errno,
			    avec,
			    avec ? local->iovec_count : 0,
			    &local->buf,
			    local->iobref);

	fd_unref(local_fd);
	if (iobref)
		iobref_unref(iobref);
	if (iobref_data)
		iobref_unref(iobref_data);
	return 0;
}

static int32_t
en_readv_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct iovec *vector,
		   int32_t count,
		   struct stat *stbuf,
                   struct iobref *iobref)
{
	en_local_t* local = frame->local;
	struct avec_config_read* conf = &local->data_conf;
	
	uint32_t i;
	uint32_t to_vec;
	uint32_t to_user;

	local->op_ret = op_ret;
	local->op_errno = op_errno;
	local->iobref = iobref_ref(iobref);
	
	local->iovec_to_decrypt = vector;
	local->iovec_count = count;

	local->buf = *stbuf;
	local->buf.st_size = local->cur_file_size;
	
	if(op_ret <= 0 || count == 0 || vector[0].iov_len == 0)
		goto readv_done;

	if (conf->orig_offset >= local->cur_file_size) {
		local->op_ret = 0;
		goto readv_done;
	}

	if(conf->orig_offset + conf->orig_size > local->cur_file_size)
		conf->orig_size = local->cur_file_size - conf->orig_offset;

	//to_user表示要返回给用户的长度
	to_user = op_ret;
	if (conf->aligned_offset + to_user <= conf->orig_offset) {
		gf_log(this->name, GF_LOG_WARNING, "Incomplete read");
		local->op_ret = -1;
		local->op_errno = EIO;
		goto readv_done;
	}
	to_user -= (conf->aligned_offset - conf->orig_offset);
	
	if(to_user > conf->orig_size)
		to_user = conf->orig_size;

	local->rw_count = to_user;
	
	//测试专用
	gettimeofday(&local->start_time, NULL);

	if(local->encrypt_type == 1)
		decrypt_aes_vec(frame, this, local->iovec_to_decrypt, count);
	else if(local->encrypt_type == 2)
		decrypt_abe_vec(frame, this, local->iovec_to_decrypt, count);
	else{
		op_ret = -1;
		op_errno = 61;
		goto readv_done;
	}

	///*测试
	gettimeofday(&local->end_time, NULL);
	int diftime = (local->end_time.tv_sec - local->start_time.tv_sec)*1000000 + (local->end_time.tv_usec - local->start_time.tv_usec);
    gf_log("crypt", GF_LOG_TRACE, "use time:%dus", diftime);

    FILE* time_file = fopen("/home/lwfs/time_result_dec", "a");

   	char str[10];
   	memset(str, 0, 10);
   	sprintf(str, "%d", local->fd);

    fwrite(str, strlen(str), 1, time_file);
    fwrite(":", 1, 1, time_file);
    
    sprintf(str, "%d", diftime);
    fwrite(str, strlen(str), 1, time_file);
    fwrite("\n", 1, 1, time_file);

    fclose(time_file);
	//*/

	if(local->op_ret == -1){
		local->rw_count = -1;
		goto readv_done;	
	}

	gf_log("--debug--readv_cbk", GF_LOG_TRACE, "op_ret:%d, to_user:%d", op_ret, to_user);

	local->iovec_to_decrypt[0].iov_base += conf->expanded_head;
	local->iovec_to_decrypt[0].iov_len -= conf->expanded_head;
	
	to_vec = to_user;
	for (i = 0; i < count; i++) {
		if (local->iovec_to_decrypt[i].iov_len > to_vec)
			local->iovec_to_decrypt[i].iov_len = to_vec;
		to_vec -= local->iovec_to_decrypt[i].iov_len;
	}

readv_done:
	crypt_readv_done(frame, this);
	return 0;	
}

static int32_t do_readv(call_frame_t *frame,
			void *cookie,
			xlator_t *this,
			int32_t op_ret,
			int32_t op_errno,
			dict_t *dict)
{
	data_t *data;
	en_local_t *local = frame->local;

	if (op_ret < 0){		
		goto error;
	}
	/*
	 * extract regular file size
	 */
	data = dict_get(dict, FSIZE_XATTR_PREFIX);
	if (!data) {
		gf_log("crypt", GF_LOG_WARNING, "Regular file size not found");
		op_errno = 61;
		goto error;
	}
	local->cur_file_size = data_to_uint64(data);

	STACK_WIND(frame,
		   en_readv_cbk,
		   FIRST_CHILD (this),
		   FIRST_CHILD (this)->fops->readv,
		   local->fd,
		   local->data_conf.expanded_size,
		   local->data_conf.aligned_offset);
	return 0;

 error:
	local->op_ret = -1;
	local->op_errno = op_errno;

	if(local->fd)
		fd_unref(local->fd);

	STACK_UNWIND_STRICT(readv,
				frame,
				-1,
				op_errno,
				NULL,
				0,
				NULL,
				NULL);
	return 0;
}


//readv的size为0,等效于调用fstat
static int32_t readv_trivial_completion(call_frame_t *frame,
					void *cookie,
					xlator_t *this,
					int32_t op_ret,
					int32_t op_errno,
					struct stat *buf)
{
	en_local_t *local = frame->local;

	local->op_ret = op_ret;
	local->op_errno = op_errno;

	if (op_ret < 0) {
		gf_log(this->name, GF_LOG_WARNING, "stat failed (%d)", op_errno);
		goto error;
	}
	local->buf = *buf;
	STACK_WIND(frame,
		   load_file_size,
		   FIRST_CHILD(this),
		   FIRST_CHILD(this)->fops->fgetxattr,
		   local->fd,
		   FSIZE_XATTR_PREFIX);
	return 0;
 error:
	if(local->fd)
		fd_unref(local->fd);
	STACK_UNWIND_STRICT(readv, frame, op_ret, op_errno,
			    NULL, 0, NULL, NULL);
	return 0;
}


static int32_t
def_readv_cbk (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct iovec *vector,
		   int32_t count,
		   struct stat *stbuf,
                   struct iobref *iobref)
{
	en_local_t* local = frame->local;
	fd_unref(local->fd);

	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      vector,
		      count,
		      stbuf,
                      iobref);
	return 0;
}

static int32_t readv_get_encrypt_type(call_frame_t *frame,
			      void *cookie,
			      xlator_t *this,
			      int32_t op_ret,
			      int32_t op_errno,
			      dict_t *dict)
{
	en_local_t* local = frame->local;
	
	if(op_ret < 0)
	{
		goto error;
	}

	data_t* data = dict_get(dict, ENCRYPT_XATTR);
	if(!data){		//没有加密的文件正常处理
	//	gf_log(this->name, GF_LOG_TRACE, "not encrypted file, WIND default");
		goto def;	
	}
	gf_log(this->name, GF_LOG_TRACE, "will read encryped file,encrypt way : %s", data->data);
	if(is_AES(data->data))
		local->encrypt_type = 1;
	else if(is_ABE(data->data))
		local->encrypt_type = 2;
	else
		goto error;
	
	gf_log("crypt", GF_LOG_DEBUG, "reading %d bytes from offset %llu",
					(int)local->size, (long long)local->offset);
	if (parent_is_crypt_xlator(frame, this))
		gf_log("crypt", GF_LOG_DEBUG, "parent is crypt");
	
	if(local->size == 0)
		goto trivial;

	set_readv_config_offsets(frame, this, local->offset, local->size);
	
	STACK_WIND(frame,
		do_readv,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->fgetxattr,
		local->fd,
		FSIZE_XATTR_PREFIX);	
	return 0;

trivial:
	STACK_WIND(frame,
		readv_trivial_completion,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->fstat,
		local->fd);

	return 0;	

def:
	STACK_WIND (frame,
		def_readv_cbk,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->readv,
		local->fd,
		local->size,
		local->offset);
	return 0;

error:
	if(local->fd)
		fd_unref(local->fd);
	STACK_UNWIND_STRICT(readv, frame, -1, op_errno, NULL, 0, NULL, NULL);
	return 0;
}

int32_t
en_readv (call_frame_t *frame,
	       xlator_t *this,
	       fd_t *fd,
	       size_t size,
	       off_t offset)
{
	//gf_log("-------", GF_LOG_TRACE, "------fd:%p, fd->pid:%d,flags:%d,key:%d,value:%d,inode_list:%p,_inode:%p", fd, fd->pid,fd->flags,fd->_ctx->key,fd->_ctx->value,&(fd->inode_list), fd->inode);
	int32_t op_errno = 1;
	en_local_t *local;	

	local = en_alloc_local(frame, this, GF_FOP_READ);
	if(!local){
		op_errno = 12;
		goto error;
	}
	//gf_log("crypt", GF_LOG_DEBUG, "reading %d bytes from offset %llu",
				//	(int)size, (long long)offset);

	local->fd = fd_ref(fd);
	local->size = size;
	local->offset = offset;
	
	STACK_WIND (frame,
		    readv_get_encrypt_type,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fgetxattr,
		    fd,
		    ENCRYPT_XATTR);
	return 0;

error:
	STACK_UNWIND_STRICT(readv, frame, -1, op_errno, NULL, 0, NULL, NULL);
	return 0;
}

static int32_t
def_writev_cbk (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
                    struct stat *prebuf,
		    struct stat *postbuf)
{
	en_local_t* local = frame->local;
	if(local->fd)
		fd_unref(local->fd);
	if (local->iobref)
		iobref_unref(local->iobref);

	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
                      prebuf,
		      postbuf);
	return 0;
}

static int32_t writev_trivial_completion(call_frame_t *frame,
					 void *cookie,
					 xlator_t *this,
					 int32_t op_ret,
					 int32_t op_errno,
					 struct stat *buf)
{
	en_local_t *local = frame->local;

	local->prebuf = *buf;
	local->postbuf = *buf;

	local->prebuf.st_size = local->cur_file_size;
	local->postbuf.st_size = local->cur_file_size;

	if(local->fd)
		fd_unref(local->fd);
	if(local->iobref)
		iobref_unref(local->iobref);
	
	STACK_UNWIND_STRICT(writev,
				frame,
				op_ret < 0 ? -1 : 0,
				op_errno,
				op_ret < 0 ? NULL : &local->prebuf,
				op_ret < 0 ? NULL : &local->postbuf);
	return 0;
}

static int32_t crypt_writev_done(call_frame_t *frame,
				 void *cookie,
				 xlator_t *this,
				 int32_t op_ret,
				 int32_t op_errno)
{
	en_local_t* local = frame->local;
	
	//int32_t ret_to_user;

	if(local->xattr)
		dict_unref(local->xattr);

	if(local->iobref)
		iobref_unref(local->iobref);
	if(local->head_avec)
		FREE(local->head_avec);	//只有一个pool可以直接free
	if(local->full_avec)
		FREE(local->full_avec);
	if(local->tail_avec)
		FREE(local->tail_avec);
	fd_unref(local->fd);

	gf_log(this->name, GF_LOG_TRACE, "have success write: %d bytes", local->write_count);

	STACK_UNWIND_STRICT(writev,
				frame,
				local->write_count,
				local->op_errno,
				&local->prebuf,
				&local->postbuf);
	return 0;
	
}

static int32_t
end_writeback_tail (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
                    struct stat *prebuf,
		    struct stat *postbuf)
{
	en_local_t* local = frame->local;
	
	//如果前面有submit操作，就不需要更新prebuf
	if(local->submit_conf.head_size == 0 && local->submit_conf.full_size == 0){
		local->prebuf = *prebuf;
		local->prebuf.st_size = local->cur_file_size;
	}	
	
	local->postbuf = *postbuf;
	local->postbuf.st_size = local->new_file_size;

	local->cur_file_size = local->new_file_size;

	local->op_ret = op_ret;
	local->op_errno = op_errno;
	
	if(op_ret > 0){	//默认此时头部写入成功
		local->write_count += local->submit_conf.tail_size;	
	}	
	gf_log(this->name, GF_LOG_TRACE, "submit tail cbk");

	return 0;
}

static int32_t
readv_before_submit_tail (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct iovec *vector,
		   int32_t count,
		   struct stat *stbuf,
                   struct iobref *iobref)
{
	en_local_t* local = frame->local;
	struct avec_config_write* conf = &(local->submit_conf);
	size_t was_read = 0;
	
	if(op_ret < 0)
		goto exit;
	
	int avec_len;
	int length_before_encrypt;

	int32_t write_done_offset = conf->tail_offset + conf->tail_size;
	int should_read = 0;
	if(local->cur_file_size > write_done_offset){
		should_read = 1;
		
		was_read = op_ret;
		
		if(local->cur_file_size - conf->tail_offset >= CRYPT_BLOCK_SIZE){
			avec_len = CRYPT_BLOCK_SIZE;
			length_before_encrypt = CRYPT_BLOCK_SIZE;
			if(was_read != CRYPT_BLOCK_SIZE){
				gf_log(this->name, GF_LOG_ERROR, "read too few");
				local->op_ret = -1;
				local->op_errno = 61;
				goto exit;
			}
			gf_log("submit_tail", GF_LOG_TRACE, "avec_len:%d", avec_len);
		}else{	//读到文件末尾即可
			int tmp = local->cur_file_size - conf->tail_offset;
			if(was_read != tmp){
				gf_log(this->name, GF_LOG_ERROR, "read too few");
				local->op_ret = -1;
				local->op_errno = 61;
				goto exit;
			}
			//对齐到128bits位
			avec_len = tmp % 16 == 0 ? tmp : (tmp / 16 + 1) * 16 ;
			length_before_encrypt = tmp;
			gf_log("submit_tail", GF_LOG_TRACE, "avec_len:%d", avec_len);			
		}
	}else{
		length_before_encrypt = conf->tail_size;
		avec_len = conf->tail_size % 16 == 0 ? conf->tail_size : (conf->tail_size / 16 + 1) * 16 ;
		local->new_file_size = write_done_offset;
	}

	struct iovec* avec;
	char *pool;
	
	avec = CALLOC(1, sizeof(*avec));
	if(!avec){
		local->op_ret = -1;
		local->op_errno = 12;
		goto exit;
	}
	pool = CALLOC(1, avec_len * sizeof(char));
	if(!pool){
		FREE(avec);
		local->op_ret = -1;
		local->op_errno = 12;
		goto exit;
	}
	avec->iov_base = pool;
	avec->iov_len = avec_len;

	local->tail_avec = avec;		
		
	int32_t i;
	int32_t copied = 0;
	int to_gap;	
	//如果需要读，就将读到的内容拷贝到tail_avec中
	if(should_read){
		to_gap = was_read;
		//拷贝读到的内容
		for (i = 0; i < count && copied < to_gap; i++) {
			int32_t to_copy;

			to_copy = vector[i].iov_len;
			if (to_copy > to_gap - copied)
				to_copy = to_gap - copied;

			memcpy(local->tail_avec->iov_base + copied, vector[i].iov_base, to_copy);
			copied += to_copy;
		}
		gf_log("submit tail", GF_LOG_TRACE, "has copyed from readv:%d", copied);

	}

	copied = 0;
	to_gap = conf->tail_size;
	//从要读的vector中拷贝相应的内容

	int32_t begin_offset = local->has_write_offset;

	for(i = local->has_write_count; i < local->count && copied < to_gap; i++){
		int32_t to_copy;

		to_copy = local->vector[i].iov_len - begin_offset;
		if (to_copy > to_gap - copied)
			to_copy = to_gap - copied;

		memcpy(local->tail_avec->iov_base + copied, local->vector[i].iov_base + begin_offset, to_copy);
		copied += to_copy;
			
		if(copied == to_gap){
			break;
		}
		begin_offset = 0;
	}

	gf_log("submit tail", GF_LOG_TRACE, "has copyed from local->vector:%d", copied);

	//gf_log("submit tail", GF_LOG_TRACE, "will submit: %s(before encrypt)", local->tail_avec->iov_base);

	//将avec加密
	if(local->encrypt_type == 1){
	
		AES_KEY KEY;
		aes_key_init_by_char(1, &KEY);

		do_encrypt_buf(local->tail_avec->iov_base, length_before_encrypt, &KEY);
	}
	else if(local->encrypt_type == 2){
		get_aes_key_from_priv(frame, this);

		AES_KEY KEY;

		if(local->op_ret != -1){
			aes_key_init_by_element(key_cache.m, 1 ,&KEY);
			do_encrypt_buf(local->tail_avec->iov_base, length_before_encrypt, &KEY);
		}else{
			goto exit;
		}
	}
	else{
		gf_log(this->name, GF_LOG_ERROR, "false encrypt_type");
		local->op_ret = -1;
		local->op_errno = 11;
		goto exit;
	}

	STACK_WIND(frame,
		end_writeback_tail,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->writev,
		local->fd,
		local->tail_avec,
		1,
		conf->tail_offset,
		local->iobref);
	gf_log("submit tail", GF_LOG_TRACE, "submit tail: %d bytes from %d offset", avec_len, conf->tail_offset);

exit:
	return 0;
}

void submit_tail(call_frame_t* frame, xlator_t* this)
{
	en_local_t* local = frame->local;

	struct avec_config_write* conf = &(local->submit_conf);
	
	//首先判断是否需要读额外的字节
	//如果写完tail后面还有字节则需要额外读
	//如果写完tail的offset > file_size， 则不需要读直接覆盖即可

	int32_t write_done_offset = conf->tail_offset + conf->tail_size;
	if(local->cur_file_size > write_done_offset){
		gf_log("submit tail", GF_LOG_TRACE, "need read extra bytes");
		STACK_WIND(frame,
			readv_before_submit_tail,
			this,
			this->fops->readv,
			local->fd,
			CRYPT_BLOCK_SIZE,
			conf->tail_offset);
	}else{
		gf_log("submit tail", GF_LOG_TRACE, "don't need read, submit straightly");
		readv_before_submit_tail(frame, NULL, this, 0, 0, NULL, 0, NULL, NULL);
	}
}

static int32_t
end_writeback_full (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
                    struct stat *prebuf,
		    struct stat *postbuf)
{
	en_local_t* local = frame->local;

	//如果先前有submit头部，就不需要更新prebuf值
	if(local->submit_conf.head_size == 0){
		local->prebuf = *prebuf;
		local->prebuf.st_size = local->cur_file_size;
	}
	local->postbuf = *postbuf;
	local->postbuf.st_size = local->new_file_size;

	local->cur_file_size = local->new_file_size;

	local->op_ret = op_ret;
	local->op_errno = op_errno;
	
	if(op_ret > 0){	//默认此时满块写入成功
		local->write_count += local->submit_conf.full_size;	
	}	
	gf_log(this->name, GF_LOG_TRACE, "submit full cbk");

	return 0;
}

//写满块的时候，不需要额外读，直接都是加密单位大小
void submit_full(call_frame_t* frame, xlator_t* this)
{
	en_local_t* local = frame->local;
	
	struct avec_config_write* conf = &(local->submit_conf);

	struct iovec* avec;
	char *pool;
	
	avec = CALLOC(1, sizeof(*avec));
	if(!avec){
		local->op_ret = -1;
		local->op_errno = 12;
		goto exit;
	}
	pool = CALLOC(1, conf->full_size * sizeof(char));
	if(!pool){
		FREE(avec);
		local->op_ret = -1;
		local->op_errno = 12;
		goto exit;
	}
	avec->iov_base = pool;
	avec->iov_len = conf->full_size;

	local->full_avec = avec;		
	gf_log("submit full", GF_LOG_TRACE, "new avec len:%ld", avec->iov_len);

	int32_t i;
	int32_t copied = 0;
	int to_gap = conf->full_size;
	//从要读的vector中拷贝相应的内容

	int32_t begin_offset = local->has_write_offset;

	for(i = local->has_write_count; i < local->count && copied < to_gap; i++){
		int32_t to_copy;

		to_copy = local->vector[i].iov_len - begin_offset;
		if (to_copy > to_gap - copied)
			to_copy = to_gap - copied;

		memcpy(local->full_avec->iov_base + copied, local->vector[i].iov_base + begin_offset, to_copy);
		copied += to_copy;
			
		if(copied == to_gap){
			if(begin_offset + to_copy == local->vector[i].iov_len){
				local->has_write_count = i + 1;
				local->has_write_offset = 0;
			}else{
				local->has_write_count = i;
				local->has_write_offset = begin_offset + to_copy;
			}
			break;
		}
		begin_offset = 0;
	}
	gf_log("submit full", GF_LOG_TRACE, "has copyed from local->vector:%d", copied);

	//gf_log("submit full", GF_LOG_TRACE, "will submit full: %s(before encrypt)", local->full_avec->iov_base);


	//计算文件长度
	if(conf->full_offset + conf->full_size > local->cur_file_size)
		local->new_file_size = conf->full_offset + conf->full_size;

	//将avec加密
	if(local->encrypt_type == 1){
	
		AES_KEY KEY;
		aes_key_init_by_char(1, &KEY);

		do_encrypt_buf(local->full_avec->iov_base, conf->full_size, &KEY);
	}
	else if(local->encrypt_type == 2){
		get_aes_key_from_priv(frame, this);

		AES_KEY KEY;

		if(local->op_ret != -1){
			aes_key_init_by_element(key_cache.m, 1 ,&KEY);
			do_encrypt_buf(local->full_avec->iov_base, conf->full_size, &KEY);
		}else{
			goto exit;
		}
	}
	else{
		gf_log(this->name, GF_LOG_ERROR, "false encrypt_type");
		local->op_ret = -1;
		local->op_errno = 11;
		goto exit;
	}

	STACK_WIND(frame,
		end_writeback_full,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->writev,
		local->fd,
		local->full_avec,
		1,
		conf->full_offset,
		local->iobref);
	gf_log("submit full", GF_LOG_TRACE, "submit full: %d bytes from %d offset", 
									conf->full_size, conf->full_offset);

exit:
	return;	

}

static int32_t
end_writeback_head (call_frame_t *frame,
		    void *cookie,
		    xlator_t *this,
		    int32_t op_ret,
		    int32_t op_errno,
                    struct stat *prebuf,
		    struct stat *postbuf)
{
	en_local_t* local = frame->local;

	local->prebuf = *prebuf;
	local->postbuf = *postbuf;

	local->prebuf.st_size = local->cur_file_size;
	local->postbuf.st_size = local->new_file_size;

	local->cur_file_size = local->new_file_size;

	local->op_ret = op_ret;
	local->op_errno = op_errno;
	
	if(op_ret > 0){	//默认此时头部写入成功
		local->write_count += local->submit_conf.head_size;	
	}	
	gf_log(this->name, GF_LOG_TRACE, "submit head cbk");

	return 0;
}

static int32_t
readv_before_submit_head (call_frame_t *frame,
		   void *cookie,
		   xlator_t *this,
		   int32_t op_ret,
		   int32_t op_errno,
		   struct iovec *vector,
		   int32_t count,
		   struct stat *stbuf,
                   struct iobref *iobref)
{
	en_local_t* local = frame->local;
	size_t was_read = 0;
	
	local->op_ret = op_ret;
	local->op_errno = op_errno;
	
	if(op_ret < 0)
		goto exit;

	was_read = op_ret;

	if(was_read < local->submit_conf.head_offset){
		gf_log(this->name, GF_LOG_ERROR, "read too few");
		local->op_ret = -1;
		local->op_errno = 61;
		goto exit;	
	}
	
	//给head_avec分配内存
	
	//计算avec长度，应当为加密块大小或者对齐128bits后的长度
	int avec_len;
	int64_t head_pre_offset = (local->submit_conf.head_offset / CRYPT_BLOCK_SIZE) * CRYPT_BLOCK_SIZE;
	int64_t head_behind_offset = head_pre_offset + CRYPT_BLOCK_SIZE;

	int head_write = local->submit_conf.head_offset + local->submit_conf.head_size; 
	
	int length_before_encrypt = CRYPT_BLOCK_SIZE;

	if(head_write % CRYPT_BLOCK_SIZE == 0)	//后面还有要写的部分
		avec_len =  CRYPT_BLOCK_SIZE;	
	else if(local->cur_file_size >= head_behind_offset){	//文件大小大于当前密文块
		avec_len =  CRYPT_BLOCK_SIZE;
	}
	else if(local->cur_file_size >= head_write){	//不增加文件长度
		int tmp = local->cur_file_size - head_pre_offset;
		avec_len = tmp % 16 == 0 ? tmp : (tmp / 16 + 1) * 16 ;
		length_before_encrypt = tmp;
	}
	else{	//有文件扩展
		int tmp = head_write - head_pre_offset;
		avec_len = tmp % 16 == 0 ? tmp : (tmp / 16 + 1) * 16 ;
		length_before_encrypt = tmp;
		gf_log("submit head", GF_LOG_TRACE, "the file is expanded to: %d", head_write);
		local->new_file_size = head_write;
	}	
	struct iovec* avec;
	char *pool;
	
	avec = CALLOC(1, sizeof(*avec));
	if(!avec){
		local->op_ret = -1;
		local->op_errno = 12;
		goto exit;
	}
	pool = CALLOC(1, avec_len * sizeof(char));
	if(!pool){
		FREE(avec);
		local->op_ret = -1;
		local->op_errno = 12;
		goto exit;
	}
	avec->iov_base = pool;
	avec->iov_len = avec_len;

	local->head_avec = avec;		
	gf_log("submit head", GF_LOG_TRACE, "new avec len:%ld", avec->iov_len);

	int32_t i;
	int32_t copied = 0;
	int to_gap = was_read;
	//拷贝读到的内容
	for (i = 0; i < count && copied < to_gap; i++) {
		int32_t to_copy;

		to_copy = vector[i].iov_len;
		if (to_copy > to_gap - copied)
			to_copy = to_gap - copied;

		memcpy(local->head_avec->iov_base + copied, vector[i].iov_base, to_copy);
		copied += to_copy;
	}
	gf_log("submit head", GF_LOG_TRACE, "has copyed from readv:%d", copied);

	//拷贝覆盖要更新的密文
	copied = 0;
	to_gap = local->submit_conf.head_size;

	int32_t begin_offset = local->has_write_offset;

	for(i = local->has_write_count; i < local->count && copied < to_gap; i++){
		int32_t to_copy;

		to_copy = local->vector[i].iov_len;
		if (to_copy > to_gap - copied)
			to_copy = to_gap - copied;

		memcpy(local->head_avec->iov_base + local->submit_conf.head_offset % CRYPT_BLOCK_SIZE + copied,
								 local->vector[i].iov_base + begin_offset, to_copy);
		copied += to_copy;

		if(copied == to_gap){
			if(begin_offset + to_copy == local->vector[i].iov_len){
				local->has_write_count = i + 1;
				local->has_write_offset = 0;
			}else{
				local->has_write_count = i;
				local->has_write_offset = begin_offset + to_copy;
			}
			break;
		}
		begin_offset = 0;
	}
	gf_log("submit head", GF_LOG_TRACE, "has copyed from local->vector:%d", copied);

	//gf_log("submit head", GF_LOG_TRACE, "will submit: %s(before encrypt)", local->head_avec->iov_base);

	//将avec加密
	if(local->encrypt_type == 1){
	
		AES_KEY KEY;
		aes_key_init_by_char(1, &KEY);

		do_encrypt_buf(local->head_avec->iov_base, length_before_encrypt, &KEY);
	}
	else if(local->encrypt_type == 2){
		get_aes_key_from_priv(frame, this);

		AES_KEY KEY;

		if(local->op_ret != -1){
			aes_key_init_by_element(key_cache.m, 1 ,&KEY);
			do_encrypt_buf(local->head_avec->iov_base, length_before_encrypt, &KEY);
		}else{
			goto exit;
		}
	}
	else{
		gf_log(this->name, GF_LOG_ERROR, "false encrypt_type");
		local->op_ret = -1;
		local->op_errno = 11;
		goto exit;
	}
	off_t new_offset = (local->submit_conf.head_offset / CRYPT_BLOCK_SIZE) * CRYPT_BLOCK_SIZE;

	STACK_WIND(frame,
		end_writeback_head,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->writev,
		local->fd,
		local->head_avec,
		1,
		new_offset,
		local->iobref);
	gf_log("submit head", GF_LOG_TRACE, "submit head: %d bytes from %d offset", avec_len, new_offset);

exit:	
	return 0;
}

void submit_head(call_frame_t* frame, xlator_t* this)
{
	en_local_t* local = frame->local;

	struct avec_config_write* conf = &(local->submit_conf);
	
	off_t new_offset = (conf->head_offset / CRYPT_BLOCK_SIZE) * CRYPT_BLOCK_SIZE;
	
	STACK_WIND(frame,
		readv_before_submit_head,
		this,
		this->fops->readv,
		local->fd,
		CRYPT_BLOCK_SIZE,
		new_offset);
}

static void submit_data(call_frame_t* frame, xlator_t* this)
{
	en_local_t* local = frame->local;

	struct avec_config_write* conf = &(local->submit_conf);

	local->write_count = 0;
	local->has_write_count = 0;
	local->has_write_offset = 0;
	
	if (conf->head_size != 0){
		submit_head(frame, this);
		if(local->op_ret < 0)
			goto error;
	}

	if (conf->full_size != 0){
		submit_full(frame, this);
		if(local->op_ret < 0)
			goto error;	
	}
	
	if (conf->tail_size != 0){
		submit_tail(frame, this);
		if(local->op_ret < 0)
			goto error;
	}

	//。。。。。writev_cbk
	gf_log(this->name, GF_LOG_TRACE, "submit success");

	if(local->cur_file_size != local->old_file_size){	//文件的长度有变化，需要更新文件扩展属性
		int32_t ret;
		local->xattr = dict_new();
		ret = dict_set(local->xattr, FSIZE_XATTR_PREFIX, data_from_uint64(local->cur_file_size));
		if (ret) {
			gf_log("crypt", GF_LOG_WARNING, "can not set key to update file size");
			crypt_writev_done(frame, NULL, this, 0, 0);
			return;
		}
		gf_log("crypt", GF_LOG_DEBUG, "Updating disk file size to %llu",
			  (unsigned long long)local->cur_file_size);
		STACK_WIND(frame,
			crypt_writev_done,
			FIRST_CHILD(this),
			FIRST_CHILD(this)->fops->fsetxattr,
			local->fd,
			local->xattr, 
			0);
	}else{
		crypt_writev_done(frame, NULL, this, 0, 0);
	}
	return;

error:
	if(local->iobref)
		iobref_unref(local->iobref);
	if(local->fd)
		fd_unref(local->fd);
	if(local->head_avec)
		FREE(local->head_avec);	//只有一个pool可以直接free
	if(local->full_avec)
		FREE(local->full_avec);
	if(local->tail_avec)
		FREE(local->tail_avec);

	STACK_UNWIND_STRICT(writev, frame, -1, local->op_errno, NULL, NULL);
	return;
}

static int32_t do_writev(call_frame_t *frame,
			      void *cookie,
			      xlator_t *this,
			      int32_t op_ret,
			      int32_t op_errno,
			      dict_t *dict)
{
	data_t *data;
	en_local_t *local = frame->local;

	if (op_ret < 0)
		goto error;
	/*
	 * extract regular file size
	 */
	data = dict_get(dict, FSIZE_XATTR_PREFIX);
	if (!data) {
		gf_log(this->name, GF_LOG_WARNING, "Regular file size not found");
		op_errno = 61;
		goto error;
	}
	local->old_file_size = local->cur_file_size = data_to_uint64(data);
	local->new_file_size = local->cur_file_size;	//看new_file_size有没有更新
	
	if(iov_length(local->vector, local->count) == 0)
		goto trivial;

	//set_readv_config_offsets(frame, this, local->offset, local->size);

	set_writev_config_offsets(frame, this, local->offset, iov_length(local->vector, local->count));

	if(local->cur_file_size < local->offset)
	{
		gf_log(this->name, GF_LOG_ERROR, "want to create file with hole, but the function is unrealized");
		op_errno = 38;
		goto error;
	}
	
	gf_log("calculate submit conf", GF_LOG_TRACE, "head_offset:%ld, head_size:%ld, \
						full_offset:%ld, full_size:%ld,tail_offset:%ld, tail_size:%ld",
						local->submit_conf.head_offset, local->submit_conf.head_size,
						local->submit_conf.full_offset, local->submit_conf.full_size,
						local->submit_conf.tail_offset, local->submit_conf.tail_size);
	submit_data(frame, this);
	
	return 0;
	
trivial:
	STACK_WIND(frame,
		writev_trivial_completion,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->fstat,
		local->fd);
	return 0;	

error:
	if(local->iobref)
		iobref_unref(local->iobref);
	if(local->fd)
		fd_unref(local->fd);
	STACK_UNWIND_STRICT(writev, frame, -1, op_errno, NULL, NULL);
	return 0;
}

static int32_t writev_get_encrypt_type(call_frame_t *frame,
			      void *cookie,
			      xlator_t *this,
			      int32_t op_ret,
			      int32_t op_errno,
			      dict_t *dict)
{
	en_local_t* local = frame->local;
	
	if(op_ret < 0)
	{
		goto error;
	}

	data_t* data = dict_get(dict, ENCRYPT_XATTR);
	if(!data){		//没有加密的文件正常处理
		//gf_log(this->name, GF_LOG_TRACE, "not encrypted file, WIND default");
		goto def;	
	}
	gf_log(this->name, GF_LOG_TRACE, "will write encryped file,encrypt way : %s", data->data);
	if(is_AES(data->data))
		local->encrypt_type = 1;
	else if(is_ABE(data->data))
		local->encrypt_type = 2;
	else{
		op_errno = 61;
		goto error;
	}	

	gf_log("en_writev", GF_LOG_TRACE, "writing %d bytes from off %llu",
		(int)iov_length(local->vector, local->count), (long long)local->offset);
	
	if (parent_is_crypt_xlator(frame, this))
		gf_log("crypt", GF_LOG_DEBUG, "parent is crypt");
	
	STACK_WIND(frame,
		do_writev,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->fgetxattr,
		local->fd,
		FSIZE_XATTR_PREFIX);	
	return 0;

def:
	STACK_WIND (frame,
		def_writev_cbk,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->writev,
		local->fd,
		local->vector,
		local->count,
		local->offset,
		local->iobref);
	return 0;

error:
	if(local->fd)
		fd_unref(local->fd);
	if (local && local->iobref)
		iobref_unref(local->iobref);
	STACK_UNWIND_STRICT(writev, frame, -1, op_errno, NULL, NULL);
	return 0;
}

int32_t
en_writev (call_frame_t *frame,
		xlator_t *this,
		fd_t *fd,
		struct iovec *vector,
		int32_t count,
		off_t off,
                struct iobref *iobref)
{
	int32_t op_errno = 1;
	en_local_t* local;
	
	local = en_alloc_local(frame, this, GF_FOP_WRITE);
	if(!local){
		op_errno = 12;
		goto error;
	}

	local->fd = fd_ref(fd);
	if(iobref)
		local->iobref = iobref_ref(iobref);
	local->offset = off;
	local->vector = vector;
	local->count = count;

	STACK_WIND (frame,
		    writev_get_encrypt_type,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->fgetxattr,
		    fd,
		    ENCRYPT_XATTR);
	return 0;

error:
	if(local && local->fd)
		fd_unref(fd);
	if(local && local->iobref)
		iobref_unref(iobref);

	STACK_UNWIND_STRICT(writev, frame, -1, op_errno, NULL, NULL);
	return 0;	
}

int32_t
en_readlink (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  size_t size)
{
	STACK_WIND (frame,
		    default_readlink_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->readlink,
		    loc,
		    size);
	return 0;
}

static int32_t ftruncate_trivial_completion(call_frame_t *frame,
					    void *cookie,
					    xlator_t *this,
					    int32_t op_ret,
					    int32_t op_errno,
					    struct stat *buf)
{
	en_local_t *local = frame->local;

	local->op_ret = op_ret;
	local->op_errno = op_errno;
	local->prebuf = *buf;
	local->postbuf = *buf;

	local->prebuf.st_size = local->cur_file_size;
	local->postbuf.st_size = local->cur_file_size;
	
	if(local->fd)
		fd_unref(local->fd);

	STACK_UNWIND_STRICT(ftruncate,
				frame,
				op_ret < 0 ? -1: 0,
				op_errno,
				&local->prebuf,
				&local->postbuf);
	return 0;
}

static int32_t crypt_ftruncate_done(call_frame_t *frame,
				 void *cookie,
				 xlator_t *this,
				 int32_t op_ret,
				 int32_t op_errno)
{
	en_local_t* local = frame->local;
	
	//int32_t ret_to_user;

	if(local->xattr)
		dict_unref(local->xattr);

	if(local->iobref)
		iobref_unref(local->iobref);
	if(local->vector)
		FREE(local->tail_avec);
	fd_unref(local->fd);
	
	
	local->prebuf.st_size = local->old_file_size;
	gf_log("prune", GF_LOG_TRACE, "ftruncate, return to user: presize=%llu, postsize=%llu",
	       (unsigned long long)local->prebuf.st_size,
	       (unsigned long long)local->postbuf.st_size);

	STACK_UNWIND_STRICT(ftruncate,
				frame,
				local->op_ret < 0 ? -1 : 0,
				local->op_errno,
				&local->prebuf,
				&local->postbuf);
	return 0;
	
}

static int32_t prune_complete(call_frame_t *frame,
			      void *cookie,
			      xlator_t *this,
			      int32_t op_ret,
			      int32_t op_errno,
			      struct stat *prebuf,
			      struct stat *postbuf)
{
	en_local_t *local = frame->local;

	local->op_ret = op_ret;
	local->op_errno = op_errno;

	if(op_ret >= 0)
		update_local_file_params(frame, this, prebuf, postbuf);

	if(local->old_file_size != local->cur_file_size){
		int32_t ret;
		local->xattr = dict_new();
		ret = dict_set(local->xattr, FSIZE_XATTR_PREFIX, data_from_uint64(local->cur_file_size));
		if (ret) {
			gf_log("prune", GF_LOG_WARNING, "can not set key to update file size");
			crypt_ftruncate_done(frame, NULL, this, 0, 0);
			return 0;
		}
		gf_log("prune", GF_LOG_DEBUG, "Updating disk file size to %llu",
			  (unsigned long long)local->cur_file_size);
		STACK_WIND(frame,
			crypt_ftruncate_done,
			FIRST_CHILD(this),
			FIRST_CHILD(this)->fops->fsetxattr,
			local->fd,
			local->xattr, 
			0);
		
	}else{
		gf_log("prune", GF_LOG_WARNING, "the file size not chang , there must be some errors");
		local->op_errno = 22;
		goto error;
	}
	return 0;

error:
	fd_unref(local->fd);
	if(local->vector)
		FREE(local->vector);

	STACK_UNWIND_STRICT(ftruncate, frame, -1, local->op_errno, NULL, NULL);
	return 0;
}

static int32_t prune_submit_file_tail(call_frame_t *frame,
				      void *cookie,
				      xlator_t *this,
				      int32_t op_ret,
				      int32_t op_errno,
				      struct stat *prebuf,
				      struct stat *postbuf)
{
	en_local_t *local = frame->local;
	struct avec_config_read *conf = &local->data_conf;

	if (op_ret < 0)
		goto error;

	//update时, local->new_file_size = conf->aligned_offset
	update_local_file_params(frame, this, prebuf, postbuf);
	local->new_file_size = conf->orig_offset;

	//手动加密local->vector

	if(local->encrypt_type == 1){
	
		AES_KEY KEY;
		aes_key_init_by_char(1, &KEY);

		do_encrypt_buf(local->vector->iov_base, conf->expanded_head, &KEY);
	}
	else if(local->encrypt_type == 2){
		get_aes_key_from_priv(frame, this);

		AES_KEY KEY;

		if(local->op_ret != -1){
			aes_key_init_by_element(key_cache.m, 1 ,&KEY);
			do_encrypt_buf(local->vector->iov_base, conf->expanded_head, &KEY);
		}else{
			goto error;
		}
	}
	else{
		gf_log(this->name, GF_LOG_ERROR, "false encrypt_type");
		local->op_ret = -1;
		local->op_errno = 11;
		goto error;
	}

	STACK_WIND(frame,
		prune_complete,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->writev,
		local->fd,
		local->vector,
		1,
		conf->aligned_offset,
		local->iobref);
	
	gf_log("prune submit", GF_LOG_TRACE, "prune submit: %d bytes from %d offset",
						 conf->expanded_head, conf->aligned_offset);
	return 0;

 error:
	fd_unref(local->fd);
	if(local->vector)
		FREE(local->vector);

	STACK_UNWIND_STRICT(ftruncate, frame, -1, local->op_errno, NULL, NULL);
	return 0;
}

static int32_t prune_write(call_frame_t *frame,
			   void *cookie,
			   xlator_t *this,
			   int32_t op_ret,
			   int32_t op_errno,
			   struct iovec *vector,
			   int32_t count,
			   struct stat *stbuf,
			   struct iobref *iobref)
{
	int32_t i;
	size_t to_copy;
	size_t copied = 0;
	en_local_t *local = frame->local;
	struct avec_config_read *conf = &local->data_conf;

	local->op_ret = op_ret;
	local->op_errno = op_errno;
	if (op_ret == -1)
		goto error;

	/*
	 * At first, uptodate head block
	 */
	if (iov_length(vector, count) < conf->expanded_head) {
		gf_log(this->name, GF_LOG_WARNING,
		       "Failed to uptodate head block for prune, read too few!");
		local->op_ret = -1;
		op_errno = 61;
		goto error;
	}
	//对齐到128bits
	int avec_len = (conf->expanded_head % 16 == 0) ?
						 conf->expanded_head : (conf->expanded_head / 16 + 1) * 16;
	struct iovec* avec;
	char *pool;
	
	avec = CALLOC(1, sizeof(*avec));
	if(!avec){
		local->op_ret = -1;
		local->op_errno = 12;
		goto error;
	}
	pool = CALLOC(1, avec_len * sizeof(char));
	if(!pool){
		FREE(avec);
		local->op_ret = -1;
		local->op_errno = 12;
		goto error;
	}
	avec->iov_base = pool;
	avec->iov_len = avec_len;

	local->vector = avec;

	for (i = 0; i < count; i++) {
		to_copy = vector[i].iov_len;
		if (to_copy > conf->expanded_head - copied)
			to_copy = conf->expanded_head - copied;

		memcpy((char *)local->vector->iov_base + copied, vector[i].iov_base, to_copy);
		copied += to_copy;
		if (copied == conf->expanded_head)
			break;
	}
	/*
	 * perform prune with aligned offset
	 * (i.e. at this step we prune a bit
	 * more then it is needed
	 */
	STACK_WIND(frame,
		   prune_submit_file_tail,
		   FIRST_CHILD(this),
		   FIRST_CHILD(this)->fops->ftruncate,
		   local->fd,
		   conf->aligned_offset);
	return 0;

error:
	fd_unref(local->fd);
	STACK_UNWIND_STRICT(ftruncate, frame, -1, op_errno, NULL, NULL);
	return 0;
}

void set_local_io_params_ftruncate(call_frame_t *frame)
{
	uint32_t resid;
	en_local_t *local = frame->local;
	struct avec_config_read *conf = &local->data_conf;

	resid = conf->orig_offset & (CRYPT_BLOCK_SIZE - 1);
	if (resid) {
		local->new_file_size = conf->aligned_offset;
		//local->update_disk_file_size = 0;
		/*
		 * file size will be updated
		 * in the ->writev() stack,
		 * when submitting file tail
		 */
	} else {
		local->new_file_size = conf->orig_offset;
		//local->update_disk_file_size = 1;
		/*
		 * file size will be updated
		 * in this ->ftruncate stack
		 */
	}
}

int32_t prune_file(call_frame_t* frame, xlator_t* this, uint64_t offset)
{
	//对齐offset
	set_readv_config_offsets(frame, this, offset, 0);
	
	en_local_t* local = frame->local;
	struct avec_config_read* conf = &local->data_conf;

	//设置新文件的属性信息
	set_local_io_params_ftruncate(frame);

	//定位在加密块边界的偏移量可以直接ftruncate
	if((conf->orig_offset & (CRYPT_BLOCK_SIZE - 1)) == 0){
		gf_log("prune file", GF_LOG_TRACE, "prune straightly:%llu", 
						(unsigned long long)conf->orig_offset);
		STACK_WIND(frame,
			prune_complete,
			FIRST_CHILD(this),
			FIRST_CHILD(this)->fops->ftruncate,
			local->fd,
			conf->orig_offset);
		return 0;
	}

	gf_log("prune file", GF_LOG_TRACE, "need readv before prune:%llu",
						(unsigned long long)conf->orig_offset);

	STACK_WIND(frame,
		prune_write,
		this,
		this->fops->readv,
		local->fd,
		CRYPT_BLOCK_SIZE,
		conf->aligned_offset);

	return 0;
}

static int32_t do_ftruncate(call_frame_t *frame,
			      	void *cookie,
				xlator_t *this,
				int32_t op_ret,
				int32_t op_errno,
				dict_t *dict)
{
	data_t *data;
	en_local_t *local = frame->local;

	if (op_ret < 0)
		goto error;
	/*
	 * extract regular file size
	 */
	data = dict_get(dict, FSIZE_XATTR_PREFIX);
	if (!data) {
		gf_log(this->name, GF_LOG_WARNING, "Regular file size not found");
		op_errno = 61;
		goto error;
	}
	local->old_file_size = local->cur_file_size = data_to_uint64(data);
	
	//offset为文件尾
	if (local->data_conf.orig_offset == local->cur_file_size) {
		gf_log("crypt", GF_LOG_TRACE,
		       "trivial ftruncate (current file size %llu)",
		       (unsigned long long)local->cur_file_size);
		goto trivial;
	}
	//文件截断
	else if (local->data_conf.orig_offset < local->cur_file_size) {
		gf_log("crypt", GF_LOG_TRACE, "prune from %llu to %llu",
		       (unsigned long long)local->cur_file_size,
		       (unsigned long long)local->data_conf.orig_offset);

		op_errno = prune_file(frame, this, local->data_conf.orig_offset);
	}
	//文件增长
	else {
		gf_log("crypt", GF_LOG_DEBUG, "expand from %llu to %llu",
		       (unsigned long long)local->cur_file_size,
		       (unsigned long long)local->data_conf.orig_offset);
		//op_errno = expand_file(frame, this, local->data_conf.orig_offset);
	}
	if (op_errno)
		goto error;
	return 0;
 
trivial:
	//更新prebuf和postbuf
	STACK_WIND(frame,
		   ftruncate_trivial_completion,
		   FIRST_CHILD(this),
		   FIRST_CHILD(this)->fops->fstat,
		   local->fd);
	
	return 0;
 
error:
	fd_unref(local->fd);
	STACK_UNWIND_STRICT(ftruncate, frame, -1, op_errno, NULL, NULL);
	return 0;
}

static int32_t
def_ftruncate_cbk (call_frame_t *frame,
		       void *cookie,
		       xlator_t *this,
		       int32_t op_ret,
		       int32_t op_errno,
		       struct stat *prebuf,
                       struct stat *postbuf)
{
	en_local_t* local = frame->local;
	if(local->fd)
		fd_unref(local->fd);
		
	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      prebuf,
                      postbuf);
	return 0;
}

static int32_t get_file_size_before_ftruncate(call_frame_t *frame,
			      void *cookie,
			      xlator_t *this,
			      int32_t op_ret,
			      int32_t op_errno,
			      dict_t *dict)
{
	
	en_local_t* local = frame->local;

	if(op_ret < 0)
	{
		goto error;
	}
	
	data_t* data = dict_get(dict, ENCRYPT_XATTR);
	if(!data){		//没有加密的文件正常处理
		gf_log(this->name, GF_LOG_TRACE, "not encrypted file, WIND default");
		goto def;	
	}

	gf_log(this->name, GF_LOG_TRACE, "encrypted file bengin to ftruncate!");
	if(is_AES(data->data)){
		local->encrypt_type = 1;
	}
	else if(is_ABE(data->data)){
		local->encrypt_type = 2;
	}else{
		goto error;
	}

	STACK_WIND(frame, 
		do_ftruncate,
		FIRST_CHILD(this),
		FIRST_CHILD(this)->fops->fgetxattr,
		local->fd,
		FSIZE_XATTR_PREFIX);
	return 0;

def:
	STACK_WIND (frame,
		    def_ftruncate_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->ftruncate,
		    local->fd, 
		    local->data_conf.orig_offset);
	return 0;
error:
	fd_unref(local->fd);
	STACK_UNWIND_STRICT(ftruncate, frame, -1, op_errno, NULL, NULL);
	return 0;
}

/*
两步：	1.获取文件长度
	2.增加或者减少文件内容
*/
int32_t
en_ftruncate (call_frame_t *frame, 
		   xlator_t *this,
		   fd_t *fd,
		   off_t offset)
{
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	en_local_t* local;
	
	local = en_alloc_local(frame, this, GF_FOP_FTRUNCATE);
	if(!local){
		errno = 12;
		goto error;
	}
	local->fd = fd_ref(fd);
	local->data_conf.orig_offset = offset;
	
	//读取扩展属性，看文件是否加密
	STACK_WIND(frame, 
		get_file_size_before_ftruncate, 
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->fgetxattr,
		fd,
		ENCRYPT_XATTR);
	return 0;

error:
	if(local && local->fd)
		fd_unref(fd);

	STACK_UNWIND_STRICT(ftruncate, frame, op_ret, op_errno, NULL, NULL);
	return 0;
}


/* ->flush_cbk() */
int32_t truncate_end(call_frame_t *frame,
		     void *cookie,
		     xlator_t *this,
		     int32_t op_ret,
		     int32_t op_errno)
{
	en_local_t *local = frame->local;

	STACK_UNWIND_STRICT(truncate,
			    frame,
			    op_ret,
			    op_errno,
			    &local->prebuf,
			    &local->postbuf);
	return 0;
}

//ftruncate_cbk()
int32_t truncate_flush(call_frame_t *frame,
		       void *cookie,
		       xlator_t *this,
		       int32_t op_ret,
		       int32_t op_errno,
		       struct stat *prebuf,
		       struct stat *postbuf)
{
	en_local_t *local = frame->local;
	fd_t *fd = local->fd;
	local->prebuf = *prebuf;
	local->postbuf = *postbuf;

	STACK_WIND(frame,
		   truncate_end,
		   FIRST_CHILD(this),
		   FIRST_CHILD(this)->fops->flush,
		   fd);
	fd_unref(fd);
	return 0;
}

static int32_t truncate_begin(call_frame_t *frame,
			      void *cookie,
			      xlator_t *this,
			      int32_t op_ret,
			      int32_t op_errno,
			      fd_t *fd)
{
	en_local_t *local = frame->local;

	if (op_ret < 0) {
		fd_unref(fd);
		STACK_UNWIND_STRICT(truncate,
				    frame,
				    op_ret,
				    op_errno, NULL, NULL);
		return 0;
	} else {
	        fd_bind (fd);
        }
	/*
	 * crypt_truncate() is implemented via crypt_ftruncate(),
	 * so the crypt xlator does STACK_WIND to itself here
	 */
	STACK_WIND(frame,
		   truncate_flush,
		   this,
		   this->fops->ftruncate, /* crypt_ftruncate */
		   fd,
		   local->offset);
	return 0;
}

static int32_t
def_truncate_cbk (call_frame_t *frame,
		      void *cookie,
		      xlator_t *this,
		      int32_t op_ret,
		      int32_t op_errno,
		      struct stat *prebuf,
                      struct stat *postbuf)
{
	en_local_t* local = frame->local;
	if (local->loc) {
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

static int32_t do_truncate(call_frame_t *frame,
			      void *cookie,
			      xlator_t *this,
			      int32_t op_ret,
			      int32_t op_errno,
			      dict_t *dict)
{
	data_t *data;
	en_local_t* local = frame->local;
	
	if(op_ret < 0)
	{
		goto error;
	}
	
	data = dict_get(dict, ENCRYPT_XATTR);
	if(!data){		//没有加密的文件正常处理
		gf_log(this->name, GF_LOG_TRACE, "not encrypted file, WIND default:%s",local->loc->path);
		goto def;	
	}

	gf_log(this->name, GF_LOG_TRACE, "encrypted file bengin to truncate:%s",local->loc->path);

	fd_t *fd = fd_create(local->loc->inode, frame->root->pid);
	if(!fd){
		gf_log(this->name, GF_LOG_ERROR, "can not create fd");
		goto error;	
	}
	local->fd = fd;	

	STACK_WIND(frame, 
		truncate_begin,
		this,
		this->fops->open,
		local->loc,
		O_RDWR,
		local->fd,
		0);
	return 0;

def:
	STACK_WIND (frame,
		    def_truncate_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->truncate,
		    local->loc, 
		    local->offset);
	return 0;

error:
	STACK_UNWIND_STRICT(truncate, frame, op_ret, op_errno, NULL, NULL);
	return 0;
}


int32_t
en_truncate (call_frame_t *frame,
		  xlator_t *this,
		  loc_t *loc,
		  off_t offset)
{
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	
	
	en_local_t *local;

	gf_log(this->name, GF_LOG_TRACE, "truncate file %s at off_set %llu", 
			loc->path, (unsigned long long)offset);
	local = en_alloc_local(frame, this, GF_FOP_TRUNCATE);
	if(!local){
		op_errno = 12;
		goto error;	
	}

	local->offset = offset;
	
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

	//读取扩展属性，看文件是否加密
	STACK_WIND(frame, 
		do_truncate, 
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->getxattr,
		local->loc,
		ENCRYPT_XATTR);
	return 0;

error:
	STACK_UNWIND_STRICT(truncate, frame, op_ret, op_errno, NULL, NULL);
	return 0;
}

static int32_t
def_open_cbk (call_frame_t *frame,
		  void *cookie,
		  xlator_t *this,
		  int32_t op_ret,
		  int32_t op_errno,
		  fd_t *fd)
{
	en_local_t * local = frame->local;
	fd_unref(local->fd);
	if (local->loc) {
		loc_wipe(local->loc);
		FREE(local->loc);
	}

	STACK_UNWIND (frame,
		      op_ret,
		      op_errno,
		      fd);
	return 0;
}

static int32_t do_open(call_frame_t *frame,
			      void *cookie,
			      xlator_t *this,
			      int32_t op_ret,
			      int32_t op_errno,
			      dict_t *dict)
{

	data_t *data;
	en_local_t* local = frame->local;

	fd_t *fd = local->fd;
	
	if(op_ret < 0)
	{
		goto error;
	}
	
	data = dict_get(dict, ENCRYPT_XATTR);
	if(!data){		//没有加密的文件正常处理
		gf_log(this->name, GF_LOG_TRACE, "not encrypted file, WIND default:%s",local->loc->path);
		goto def;	
	}

	if ((local->flags & O_ACCMODE) == O_WRONLY)
		/*
		 * we can't open O_WRONLY, because
		 * we need to do read-modify-write
		 */
		local->flags = (local->flags & ~O_ACCMODE) | O_RDWR;
	/*
	 * Make sure that out translated offsets
	 * and counts won't be ignored
	 */
	local->flags &= ~O_APPEND;

def:
	STACK_WIND (frame,
		    def_open_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->open,
		    local->loc, 
		    local->flags, 
		    fd, 
		    local->wbflags);
	return 0;

error:
	if (local->fd)
		fd_unref(local->fd);
	if (local->loc) {
		loc_wipe(local->loc);
		FREE(local->loc);
	}
	STACK_UNWIND_STRICT(open, frame, op_ret, op_errno, NULL);
	return 0;

}

//open函数主要需要将文件路径等信息记录到local中，并改flags
int32_t
en_open (call_frame_t *frame,
	      xlator_t *this,
	      loc_t *loc,
	      int32_t flags, fd_t *fd,
              int32_t wbflags)
{

	gf_log(this->name, GF_LOG_TRACE, "enter en_open");
	int32_t op_ret = -1;
	int32_t op_errno = 1;
	en_local_t* local ;	

	local = en_alloc_local(frame, this, GF_FOP_OPEN);
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
	
	//读取扩展属性，看文件是否加密
	STACK_WIND(frame, 
		do_open, 
		FIRST_CHILD(this), 
		FIRST_CHILD(this)->fops->getxattr,
		local->loc,
		ENCRYPT_XATTR);
	return 0;

error:
	STACK_UNWIND_STRICT(open, frame, op_ret, op_errno, NULL);
	return 0;
}

int32_t
en_lookup (call_frame_t *frame,
		xlator_t *this,
		loc_t *loc,
		dict_t *xattr_req)
{
	STACK_WIND (frame,
		    default_lookup_cbk,
		    FIRST_CHILD(this),
		    FIRST_CHILD(this)->fops->lookup,
		    loc,
		    xattr_req);
	return 0;
}

int32_t
init (xlator_t *this)
{
	int ret = 0;
	int op_ret = -1;
	struct stat buf = {0,};
	data_t *dir_data = NULL;
	struct en_private *priv = NULL;

	if (!this->children || this->children->next) {
		gf_log ("en", GF_LOG_ERROR, 
			"FATAL: en should have exactly one child");
		ret = -1;		
		goto out;
	}

	if (!this->parents) {
		gf_log (this->name, GF_LOG_WARNING,
			"dangling volume. check volfile ");
	}

	dir_data = dict_get (this->options, "directory");
	if(!dir_data){
		gf_log(this->name, GF_LOG_CRITICAL, "Export directory not specified in volume file.");
		ret = -1;
		goto out;	
	}

	umask(000);
	
	/*check whether the directory exists*/
	op_ret = stat (dir_data->data, &buf);
      if ((op_ret != 0) || !S_ISDIR (buf.st_mode)) {
                gf_log (this->name, GF_LOG_ERROR,
                        "Directory '%s' doesn't exist, exiting.",
		dir_data->data);
                ret = -1;
                goto out;
        }
	
	priv = CALLOC (1, sizeof (struct en_private));
	if(!priv){
		gf_log(this->name, GF_LOG_ERROR, "out of memory");
		ret = -1;
		goto out;
	}
	priv->base_path = strdup(dir_data->data);
	priv->base_path_length = strlen(priv->base_path);
	
	dir_data = dict_get (this->options, "block_size");
	if(!dir_data){
		gf_log(this->name, GF_LOG_CRITICAL, "Export block_size not specified in volume file.");
		ret = -1;
		goto out;	
	}
	priv->block_size = data_to_int32(dict_get(this->options, "block_size"));
	CRYPT_BLOCK_SIZE = priv->block_size;

	dir_data = dict_get(this->options, "pthread_count");
	if(!dir_data){
		gf_log(this->name, GF_LOG_CRITICAL, "Export pthread_count.");
		ret = -1;
		goto out;	
	}
	PTHREAD_COUNT = data_to_int32(dict_get(this->options, "pthread_count"));

	char* pubkeyName = alloca(8 + priv->base_path_length + 2);
	strcpy (pubkeyName, priv->base_path);
    strcpy (&pubkeyName[priv->base_path_length], "/pub_key");
	pub = bswabe_pub_unserialize(suck_file(pubkeyName), 0);

	
	this->private = priv;
	gf_log ("en", GF_LOG_DEBUG, "en xlator loaded");
	return 0;

out:
	return ret;

}

void 
fini (xlator_t *this)
{
	struct en_private *priv = this->private;
	
	FREE (priv);

	bswabe_pub_free(pub);
	
	return;
}

struct xlator_fops fops = {
	.stat          = en_stat,
	.fstat	   	   = en_fstat,
	.access	   = en_access,
	.setxattr	   = en_setxattr,
	.removexattr   = en_removexattr,
	.readv	   	   = en_readv,
	.writev	   = en_writev,
	.readlink	   = en_readlink,
	.truncate	   = en_truncate,
	.ftruncate	   = en_ftruncate,
	.open		   = en_open,
	.lookup	   = en_lookup
};

struct xlator_mops mops = {
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key  = {"directory"}, 
	  .type = GF_OPTION_TYPE_PATH,
	  .description = "the mount path in the server node"
	},
	{ .key  = {"block_size"}, 
	  .type = GF_OPTION_TYPE_SIZET,
	  .description = "Atom size (bits) default value : 1024",
	  .min = 1024,
	  .max = 131072,
	},
	{
	  .key = {"pthread_count"},
	  .type = GF_OPTION_TYPE_SIZET,
	  .description = "should use how much threads, best be remainder of 128"
	},
	{ .key  = {NULL} },
};
