
#include "crypt.h"
#include "dict.h"
#include <pthread.h>

extern int CRYPT_BLOCK_SIZE;
extern int PTHREAD_COUNT;

const char iv[] = "8765432112345678";
const char key[] = "1234567887654321";

//多线程结构
struct pthread_args{
	char* buf;
	size_t size;
	AES_KEY* KEY;
	int enc;
};

void
aes_key_init_by_element(element_t k, int enc, AES_KEY* KEY)
{
	int key_len;
	unsigned char* key_buf;

	key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
	key_buf = (unsigned char*) malloc(key_len);
	element_to_bytes(key_buf, k);

	if( enc )
		AES_set_encrypt_key(key_buf + 1, 128, KEY);
	else
		AES_set_decrypt_key(key_buf + 1, 128, KEY);
	free(key_buf);
}

void
aes_key_init_by_char(int enc, AES_KEY* KEY)
{
	if( enc )
		AES_set_encrypt_key(key, 128, KEY);
	else
		AES_set_decrypt_key(key, 128, KEY);
}

void read_cphbuf(const char* pathname, GByteArray** cph_buf)
{
	*cph_buf = g_byte_array_new();
	
	char len_buf[32];
	memset(len_buf, 0 ,32);
	if(lgetxattr(pathname, "user.cpabe_cph_length", len_buf, sizeof(len_buf)) == -1)
	{
		gf_log("common", GF_LOG_ERROR, "getattr error!");
		return;
	}
	int len = strtol(len_buf, NULL, 0);
	gf_log("common", GF_LOG_TRACE, "%d", len);

	g_byte_array_set_size(*cph_buf, len);

	int cph_blocks = len/MAX_XTTR_LENGTH + (len % MAX_XTTR_LENGTH == 0 ? 0 : 1);
	int i = 0;
	char str[MAX_CP_BUF_LEN_BITS];
	int size = 0;
	for(; i < cph_blocks - 1; ++i)
	{
		memset(str, 0, MAX_CP_BUF_LEN_BITS * sizeof(char));
		sprintf(str, "user.cpabe_cph%d", i);
		size = MAX_XTTR_LENGTH;
		if(lgetxattr(pathname, str, (*cph_buf)->data + MAX_XTTR_LENGTH * i, size) == -1)
 		{
			gf_log("common", GF_LOG_ERROR, "getattr error!");
			return;
		}
	}
	memset(str, 0, MAX_CP_BUF_LEN_BITS * sizeof(char));
	sprintf(str, "user.cpabe_cph%d", i);
	size = len - MAX_XTTR_LENGTH*i;
	if(lgetxattr(pathname, str, (*cph_buf)->data + MAX_XTTR_LENGTH * i, size) == -1)
	{
		gf_log("common", GF_LOG_ERROR, "getattr error!");
		return;
	}
}

void remove_cph_xattr(const char* pathname)
{
	int len = 0;

	char len_buf[32];	//要用char的格式来读
	memset(len_buf, 0, 32);
	if(lgetxattr(pathname, "user.cpabe_cph_length", len_buf, sizeof(len_buf)) == -1)
	{
		gf_log("common", GF_LOG_ERROR, "getattr error!");
		return;
	}
	
	if(lremovexattr(pathname, "user.cpabe_cph_length") == -1)
	{
		gf_log("common", GF_LOG_ERROR, "removeattr error!");
		return;
	}
	len = strtol(len_buf, NULL, 0);
	gf_log("common", GF_LOG_TRACE, "%d", len);
	int cph_blocks = len/MAX_XTTR_LENGTH + (len % MAX_XTTR_LENGTH == 0 ? 0 : 1);
	int i = 0;
	char str[MAX_CP_BUF_LEN_BITS];
	for(; i < cph_blocks; ++i)
	{
		memset(str, 0, MAX_CP_BUF_LEN_BITS * sizeof(char));
		sprintf(str, "user.cpabe_cph%d", i);
		if(lremovexattr(pathname, str) == -1)
		{
			gf_log("common", GF_LOG_ERROR, "removeattr %s error!", str);
			return;
		}
	}
}

void write_cphbuf(const char* pathname,  GByteArray* cph_buf)
{
	int cph_blocks = (cph_buf->len)/MAX_XTTR_LENGTH + ((cph_buf->len) % MAX_XTTR_LENGTH == 0 ? 0 : 1);
	int i = 0;
	char str[MAX_CP_BUF_LEN_BITS];
	int size = 0;
	for(; i < cph_blocks - 1; ++i)
	{
		memset(str, 0, MAX_CP_BUF_LEN_BITS * sizeof(char));
		sprintf(str, "user.cpabe_cph%d", i);
		size = MAX_XTTR_LENGTH;
		if(lsetxattr(pathname, str, cph_buf->data + MAX_XTTR_LENGTH * i, size, 0) == -1)
		{
			gf_log("common", GF_LOG_ERROR, "setattr error!");
			return;
		}
	}
	memset(str, 0, MAX_CP_BUF_LEN_BITS * sizeof(char));
	sprintf(str, "user.cpabe_cph%d", i);
	size = cph_buf->len - MAX_XTTR_LENGTH*i;
	if(lsetxattr(pathname, str, cph_buf->data + MAX_XTTR_LENGTH * i, size, 0) == -1)
	{
		gf_log("common", GF_LOG_ERROR, "setattr error!");
		return;
	}
	/*
	if(lsetxattr(pathname, "user.cpabe_cph_length", &(cph_buf->len), sizeof(cph_buf->len), 0) == -1)
	{
		gf_log("common", GF_LOG_ERROR, "setattr error!");
		return;
	}*/
	data_t *len_data = data_from_uint32(cph_buf->len);
	if(lsetxattr(pathname, "user.cpabe_cph_length", len_data->data, len_data->len, 0) == -1)
	{
		gf_log("common", GF_LOG_ERROR, "set xattr error!");
		return;
	}
}

FILE*
fopen_read_or_die(const char* file )
{
	FILE* f;

	if( !(f = fopen(file, "r")) )
	{
		die("can't read file: %s\n", file);
		gf_log("common", GF_LOG_ERROR, "can't read file: %s\n", file);
	}

	return f;
}

FILE*
fopen_write_or_die(const char* file )
{
	FILE* f;

	if( !(f = fopen(file, "w")) )
	{
		die("can't write file: %s\n", file);
		gf_log("common", GF_LOG_ERROR, "can't write file: %s\n", file);
	}

	return f;
}

GByteArray*
suck_file(const char* file )
{
	FILE* f;
	GByteArray* a;
	struct stat s;

	a = g_byte_array_new();
	stat(file, &s);
	g_byte_array_set_size(a, s.st_size);

	f = fopen_read_or_die(file);
	fread(a->data, 1, s.st_size, f);
	fclose(f);

	return a;
}

char*
suck_file_str( char* file )
{
	GByteArray* a;
	char* s;
	unsigned char zero;

	a = suck_file(file);
	zero = 0;
	g_byte_array_append(a, &zero, 1);
	s = (char*) a->data;
	g_byte_array_free(a, 0);

	return s;
}

char*
suck_stdin()
{
	GString* s;
	char* r;
	int c;

	s = g_string_new("");
	while( (c = fgetc(stdin)) != EOF )
		g_string_append_c(s, c);

	r = s->str;
	g_string_free(s, 0);

	return r;
}

void
spit_file( char* file, GByteArray* b, int free )
{
	FILE* f;

	f = fopen_write_or_die(file);
	fwrite(b->data, 1, b->len, f);
	fclose(f);

	if( free )
		g_byte_array_free(b, 1);
}

void
die(char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	gf_log("common", GF_LOG_ERROR, "die %s", fmt);
	va_end(args);
	//exit(1);  // 此处如果退出会引起文件系统退出
}


void* func(void* arg)
{
	struct timeval start, end;
	gettimeofday(&start, NULL);

	gf_log("crypt-common", GF_LOG_TRACE, "thread begin at %lld", start.tv_sec*1000000 + start.tv_usec );

	struct pthread_args* args = (struct pthread_args *)arg;
	
	if(args->enc == 1)
		do_encrypt_buf(args->buf, args->size, args->KEY);
	else
		do_decrypt_buf(args->buf, args->size, args->KEY);

	gettimeofday(&end, NULL);
	gf_log("crypt-common", GF_LOG_TRACE, "this thread use time:%d", (end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec) );
	
	gf_log("crypt-common", GF_LOG_TRACE, "thread end at %lld", end.tv_sec*1000000 + end.tv_usec );
	pthread_exit(NULL);
}

void do_crypt_buf_pthread(char* buf, size_t size, AES_KEY* KEY, int enc)
{
	struct timeval start, end;
	gettimeofday(&start, NULL);

	//计算应当设置的线程数，最多为PTHREAD_COUNT个
	int should_count, pthread_count;
	should_count = size/CRYPT_BLOCK_SIZE + (size % CRYPT_BLOCK_SIZE == 0 ? 0 : 1);
	if(should_count <= PTHREAD_COUNT)
		pthread_count = should_count;
	else 
		pthread_count = PTHREAD_COUNT;

	int len = 0;
 	
	int sizes[pthread_count];	//计算每个线程应该处理文件的长度
	if(pthread_count < PTHREAD_COUNT){ //每个线程处理CRYPT_BLOCK_SIZE大小
		int i ;		
		for(i = 0;i < pthread_count-1; i++ ){
			sizes[i] = CRYPT_BLOCK_SIZE;
			len += CRYPT_BLOCK_SIZE;
		}
		sizes[i] = size - len;	
	}
	else{	//每个线程处理长度不定，先按商平分，剩下的从左到右分，但是最后多出来的不足CRYPT_BLOCK_SIZE在最右边
		int multiple = should_count / PTHREAD_COUNT;
		int i ;		
		for(i = 0;i < pthread_count; i++ ){
			sizes[i] = CRYPT_BLOCK_SIZE * multiple;
			len += CRYPT_BLOCK_SIZE * multiple;
		}
		i = 0;
		while(len < size){
			if(size - len >= CRYPT_BLOCK_SIZE){
				sizes[i++] += CRYPT_BLOCK_SIZE;
				len += CRYPT_BLOCK_SIZE;		
			}
			else{
				sizes[pthread_count - 1] += size - len ;
				break;
			}
		}
		
	}
	//创建线程执行任务
	int has_alloc = 0;	
	int i = 0;
	int rc;
	pthread_t threads[pthread_count];
	struct pthread_args args[pthread_count];	//用于在创建线程的时候传递参数
	for(; i < pthread_count; i++){
		args[i].buf =  buf + has_alloc;
		args[i].size = sizes[i];
		args[i].KEY = KEY;
		args[i].enc = enc;
		gf_log("encryption", GF_LOG_TRACE, "user thread to calculate %d - %d", has_alloc,has_alloc + sizes[i]);
		has_alloc += sizes[i];
		rc = pthread_create(&threads[i], NULL, func, (void *)&args[i]);
		if(rc){
			gf_log("encryption", GF_LOG_WARNING, "thread create failed");
		}
	}
	
	for(i = 0; i < pthread_count; i++){
		pthread_join(threads[i], NULL);
	}

	gettimeofday(&end, NULL);
	gf_log("crypt-common", GF_LOG_TRACE, "this task use time:%d", (end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec) );
	//gf_log("crypt-common", GF_LOG_TRACE, "task end at %lld", end.tv_sec*1000000 + end.tv_usec );
}
