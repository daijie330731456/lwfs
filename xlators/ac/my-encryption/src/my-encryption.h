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

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>

#include "xlator.h"

#include "crypt.h"
#include <time.h>


struct en_private{
	char* base_path;
	int32_t base_path_length;
	int32_t block_size;
};

struct avec_config_read{
	size_t orig_size;
	off_t orig_offset;
	size_t expanded_size;
	off_t aligned_offset;

	size_t expanded_head;
	size_t expanded_tail;
	
};

struct avec_config_write{
	size_t orig_size;
	off_t orig_offset;

	off_t head_offset;
	size_t head_size;
	
	off_t full_offset;
	size_t full_size;
	
	off_t tail_offset;
	size_t tail_size;
};

//缓存从PRIV计算得到的对称密钥
struct aes_key_cache_from_priv{
	element_t m;
	uid_t uid;
	time_t time;
	struct _inode* inode;
};

typedef struct{
	lwfs_fop_t fop;
	fd_t* fd;
	inode_t* inode;
	loc_t* loc;
	loc_t* newloc;
	int32_t flags;
	int32_t wbflags;
	struct iobref* iobref;
	struct iobref* iobref_data;
	off_t offset;
	size_t size;

	uint64_t old_file_size;
	uint64_t cur_file_size;
	uint64_t new_file_size;

	int32_t nr_calls;

	struct avec_config_read data_conf;

	struct avec_config_write submit_conf;
	struct iovec* head_avec;
	struct iovec* full_avec;
	struct iovec* tail_avec;

	struct stat buf;
	struct stat prebuf;
	struct stat postbuf;

	int32_t op_ret;
	int32_t op_errno;
	int32_t rw_count;
	unsigned char* format;
	uint32_t format_size;
	uint32_t msgflags;

	struct iovec* vector;
	int32_t count;

	dict_t *xattr;	//用于更新文件长度扩展属性

	int32_t write_count;	//记录写入的字节数
	
	//将write分解为好几部分，所以要记录write到哪个地方	
	int32_t has_write_count;
	int32_t has_write_offset;

	int32_t encrypt_type;	//0：不加密，1：aes加密,2：abe加密
		
	int has_read_blocks;
	int cph_blocks;	
	GByteArray* cph_buf;

	//uint32_t update_disk_file_size:1;

	//struct aes_key_cache_from_priv* key_cache; 不能在local里面，每次read会刷新值
	
	struct  iovec* iovec_to_decrypt;
	int32_t iovec_count;

	//测试专用
	struct timeval start_time;
	struct timeval end_time;

}en_local_t;


#define EN_BASE_PATH(this) (((struct en_private *)this->private)->base_path)

#define EN_BASE_PATH_LEN(this) (((struct en_private *)this->private)->base_path_length)

#define MAKE_REAL_PATH(var, this, path) do {                            \
		var = alloca (strlen (path) + EN_BASE_PATH_LEN(this) + 2); \
                strcpy (var, EN_BASE_PATH(this));			\
                strcpy (&var[EN_BASE_PATH_LEN(this)], path);		\
        } while (0)

//base_path + "/pub_key"
#define MAKE_PUB_PATH(var, this) do {                            \
		var = alloca (8 + EN_BASE_PATH_LEN(this) + 2); \
                strcpy (var, EN_BASE_PATH(this));			\
                strcpy (&var[EN_BASE_PATH_LEN(this)], "/pub_key");		\
        } while (0)

//base_path + "/priv_key"
#define MAKE_PRIV_PATH(var, this) do {                            \
		var = alloca (9 + EN_BASE_PATH_LEN(this) + 2); \
                strcpy (var, EN_BASE_PATH(this));			\
                strcpy (&var[EN_BASE_PATH_LEN(this)], "/priv_key");		\
        } while (0)

#define LONGEST_POLICY_LENGTH 256
#define FSIZE_XATTR_PREFIX "user.glusterfs.crypt.stat.size"
#define ENCRYPT_XATTR "user.encrypt"
#define CACHE_EFFECTIVE_TIME 10
//#define PTHREAD_COUNT 4

static inline int32_t parent_is_crypt_xlator(call_frame_t *frame,
					     xlator_t *this)
{
	return frame->parent->this == this;
}

void decrypt_aes_vec(call_frame_t* frame, xlator_t* this, struct iovec *vec, int32_t count);
void decrypt_abe_vec(call_frame_t* frame, xlator_t* this, struct iovec *vec, int32_t count);
void set_readv_config_offsets(call_frame_t *frame, xlator_t *this, uint64_t offset, uint64_t size);
void set_writev_config_offsets(call_frame_t *frame, xlator_t *this, uint64_t offset, uint64_t size);

void get_aes_key_from_priv(call_frame_t* frame, xlator_t* this);
void do_encrypt_buf(char* buf, size_t size, AES_KEY* KEY);

