#include "my-encryption.h"

extern int CRYPT_BLOCK_SIZE;
extern const char iv[];

//全局变量缓存对称密钥
struct aes_key_cache_from_priv key_cache;


void do_decrypt(struct iovec *vec, int32_t count, AES_KEY* KEY)
{
	int i;
	
	for(i = 0; i < count; ++i){
		do_crypt_buf_pthread(vec[i].iov_base, vec[i].iov_len, KEY, 0);
	}
}

void read_cph_done(call_frame_t* frame, xlator_t* this)
{
	//测试
	struct timeval start, end;

	en_local_t *local = frame->local;
	
	int32_t op_errno = 1;
	
	char* pub_path = NULL;
	char* priv_path = NULL;
	MAKE_PUB_PATH (pub_path, this);
	MAKE_PRIV_PATH (priv_path, this);

	bswabe_pub_t* pub;
	bswabe_prv_t* prv;
	//element_t m;
	bswabe_cph_t* cph;

	gettimeofday(&start, NULL);

	//后面的1为free位，选择读后自动free
	pub = bswabe_pub_unserialize(suck_file(pub_path), 1);
	prv = bswabe_prv_unserialize(pub, suck_file(priv_path), 1);

	gettimeofday(&end, NULL);
	gf_log("dec", GF_LOG_TRACE, "unserialize pub and prv use time:%d",
		(end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec));
	
	//gf_log("getkey", GF_LOG_TRACE, "read cph success!");

	//free为1，自动释放local->cph_buf
	cph = bswabe_cph_unserialize(pub, local->cph_buf, 1);

	gettimeofday(&start, NULL);
	if(!bswabe_dec(pub, prv, cph, key_cache.m))
	{
		gf_log("getkey", GF_LOG_WARNING, "has no autority to get aes key");
		op_errno = 13;
		goto error;
	}

	gettimeofday(&end, NULL);
        gf_log("dec", GF_LOG_TRACE, "bswabe_dec use time:%d",
                (end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec));

	//gf_log("crypt-common", GF_LOG_TRACE, "success generate aes key");

	time_t t = time(NULL);
	key_cache.time = t;
	//key_cache.m = m;
	key_cache.uid = frame->root->uid;
	key_cache.inode = local->fd->inode;

	//element_clear(m);

	return;

error:
	
	local->op_ret = -1;	
	local->op_errno = op_errno;
	return;
}

static int32_t get_cph_loop(call_frame_t* frame,
			void* cookie,
			xlator_t* this,
			int32_t op_ret,
			int32_t op_errno,
			dict_t *dict)
{
	data_t *data;
	en_local_t *local = frame->local;

	if (op_ret < 0){
		op_errno = 61;
		goto error;	
	}
	int i = 0;
	char str[MAX_CP_BUF_LEN_BITS];
	
	//循环获取多个策略密文块
	for(; i < local->cph_blocks; ++i)
	{
		memset(str, 0, MAX_CP_BUF_LEN_BITS * sizeof(char));
		sprintf(str, "user.cpabe_cph%d", i);
		data = dict_get(dict, str);
		if(data){
			//gf_log("getkey", GF_LOG_TRACE, "get cph: %s", str);

			memcpy((local->cph_buf->data) + i * MAX_XTTR_LENGTH, data->data, data->len);
			local->has_read_blocks++;		
		}
	}
	if(local->has_read_blocks == local->cph_blocks){
		local->cph_blocks = 0;	
		local->has_read_blocks = 0;

		read_cph_done(frame,this);	
	}
	return 0;

error:
	if(local->cph_buf){
		local->cph_buf = NULL;	
	}
	local->cph_blocks = 0;	
	local->has_read_blocks = 0;

	local->op_ret = -1;	
	local->op_errno = op_errno;
	return 0;
}


static int32_t get_cph(call_frame_t* frame,
			void* cookie,
			xlator_t* this,
			int32_t op_ret,
			int32_t op_errno,
			dict_t *dict)
{
	data_t *data;
	en_local_t *local = frame->local;

	if (op_ret < 0){
		op_errno = 61;
		goto error;	
	}
	data = dict_get(dict, "user.cpabe_cph_length");
	if(!data){		
		op_errno = 61;
		goto error;
	}
	local->cph_buf = g_byte_array_new();	

	int len = data_to_uint32(data);
	//gf_log("getkey", GF_LOG_TRACE, "will get cph len: %d", len);

	g_byte_array_set_size(local->cph_buf, len);	//分配内存
	
	int cph_blocks = len/MAX_XTTR_LENGTH + (len % MAX_XTTR_LENGTH == 0 ? 0 : 1);
	local->cph_blocks = cph_blocks;
	local->has_read_blocks = 0;
	int i = 0;
	char str[MAX_CP_BUF_LEN_BITS];
	
	//循环获取多个策略密文块
	for(; i < cph_blocks; ++i)
	{
		memset(str, 0, MAX_CP_BUF_LEN_BITS * sizeof(char));
		sprintf(str, "user.cpabe_cph%d", i);
		STACK_WIND(frame,
			get_cph_loop,
			FIRST_CHILD(this),
			FIRST_CHILD(this)->fops->fgetxattr,
			local->fd,
			str);
	}
	return 0;	
	
error:
	
	local->op_ret = -1;	
	local->op_errno = op_errno;
	
	return 0;
}


void get_cph_length(call_frame_t* frame, xlator_t* this)
{
	en_local_t *local = frame->local;
	
	STACK_WIND(frame,
			get_cph,
			FIRST_CHILD(this),
			FIRST_CHILD(this)->fops->fgetxattr,
			local->fd,
			"user.cpabe_cph_length");
	
}

void set_readv_config_offsets(call_frame_t *frame,
			xlator_t *this,
			uint64_t offset,
			uint64_t size)
{
	en_local_t *local;
	local = frame->local;
	
	size_t expanded_size;
	off_t aligned_offset;

	size_t expanded_head = 0;
	size_t expanded_tail = 0;
	
	int off = (offset + size) % CRYPT_BLOCK_SIZE;
	expanded_tail = (off == 0) ? 0 : (CRYPT_BLOCK_SIZE - off);
	
	int32_t blocks = offset / CRYPT_BLOCK_SIZE;
	aligned_offset = blocks * CRYPT_BLOCK_SIZE;
	expanded_head = offset - aligned_offset;

	expanded_size = size + expanded_head + expanded_tail;
	

	local->data_conf.orig_size = size;
	local->data_conf.orig_offset = offset;
	local->data_conf.expanded_size = expanded_size;
	local->data_conf.aligned_offset = aligned_offset;

	local->data_conf.expanded_head = expanded_head;
	local->data_conf.expanded_tail = expanded_tail;
}


void decrypt_aes_vec(call_frame_t* frame, xlator_t* this, struct iovec *vec, int32_t count)
{
	gf_log("crypt-common", GF_LOG_TRACE, "before aes decrypt, count:%d, vec[0]length:%d",
								count, vec[0].iov_len);

	AES_KEY KEY;
	aes_key_init_by_char(0, &KEY);
	do_decrypt(vec, count, &KEY);

	//......
}

void get_aes_key_from_priv(call_frame_t* frame, xlator_t* this)
{
	gf_log("crypt-common", GF_LOG_TRACE, "will get aes key");

	en_local_t *local;
	local = frame->local;
	
	time_t t = time(NULL);
	//同一用户在短时间内对同一个ABE密文解密可以直接取KEY缓存，减少计算开销
	//gf_log("-----debug", GF_LOG_TRACE, "aes_cache->time:%ld t:%ld",key_cache.time, t);
	//gf_log("-----debug", GF_LOG_TRACE, "aes_cache->uid:%d frame->root->uid:%ld",key_cache.uid, frame->root->uid);
	//gf_log("-----debug", GF_LOG_TRACE, "aes_cache->fd:%p local->fd:%p",key_cache.fd, local->fd);

	//不同文件fd有可能相同，但是不同文件fd的inode地址肯定不同
	if(t - key_cache.time <= CACHE_EFFECTIVE_TIME && 
			key_cache.uid == frame->root->uid &&
			key_cache.inode == local->fd->inode ){
		gf_log("abe_decrypt", GF_LOG_TRACE, "cache can be used, fd:%p", local->fd->inode);
		key_cache.time = t;
		
		return;
	}else{
		get_cph_length(frame, this);
	} 	
}

void decrypt_abe_vec(call_frame_t* frame, xlator_t* this, struct iovec *vec, int32_t count)
{
	gf_log("crypt-common", GF_LOG_TRACE, "before abe decrypt, count:%d, vec[0]length:%d",
								count, vec[0].iov_len);

	en_local_t* local = frame->local;

	get_aes_key_from_priv(frame, this);

	AES_KEY KEY;

	struct timeval start, end;
	gettimeofday(&start, NULL);

	if(local->op_ret != -1){
		aes_key_init_by_element(key_cache.m, 0 ,&KEY);
		do_decrypt(local->iovec_to_decrypt, local->iovec_count, &KEY);
	}
	
	gettimeofday(&end, NULL);
	gf_log("dec", GF_LOG_TRACE, "do aes dec use time:%d",
		(end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec));	

}

void set_writev_config_offsets(call_frame_t *frame,
			xlator_t *this,
			uint64_t offset,
			uint64_t size)
{
	en_local_t *local;
	local = frame->local;

	local->submit_conf.head_size = 0;
	local->submit_conf.full_size = 0;
	local->submit_conf.tail_size = 0;
	
	local->submit_conf.orig_size = size;
	local->submit_conf.orig_offset = offset;	

	int aligned = offset % CRYPT_BLOCK_SIZE;

	if(aligned != 0){
		local->submit_conf.head_offset = offset;
		if(size < CRYPT_BLOCK_SIZE - aligned){
			local->submit_conf.head_size = size;
			return;
		}		
		else{
			local->submit_conf.head_size = CRYPT_BLOCK_SIZE - aligned;
			size -= local->submit_conf.head_size;
		}
	}
	if(size >= CRYPT_BLOCK_SIZE){
		int32_t blocks = size / CRYPT_BLOCK_SIZE;
		if(aligned != 0){
			local->submit_conf.full_offset = (offset / CRYPT_BLOCK_SIZE  + 1) * CRYPT_BLOCK_SIZE;
		}
		else{
			local->submit_conf.full_offset = offset;
		}
		local->submit_conf.full_size = blocks * CRYPT_BLOCK_SIZE;

		size -= local->submit_conf.full_size;
	}

	if(size > 0){
		local->submit_conf.tail_offset = ((local->submit_conf.orig_offset + local->submit_conf.orig_size) /
						 CRYPT_BLOCK_SIZE) * CRYPT_BLOCK_SIZE;
		local->submit_conf.tail_size = size;
	}
	
}

