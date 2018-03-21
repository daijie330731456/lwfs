#include "crypt.h"

extern const char iv[];
extern int CRYPT_BLOCK_SIZE;
extern bswabe_pub_t* pub;

/*******************************************
功能：对字符串进行aes解密
输入：密文，密钥
输出：明文
*******************************************/
void aes_decrypt_buf(const unsigned char* ciphertext,unsigned char* plaintext,const int length,AES_KEY* KEY,const char* iv)
{
	int block_nums = length / 16;
	//用全局iv初始化计算的iv
	unsigned char use_iv[AES_BLOCK_SIZE];
	memcpy(use_iv,iv,sizeof(use_iv));

	AES_cbc_encrypt(ciphertext, plaintext, block_nums * AES_BLOCK_SIZE, KEY, use_iv, AES_DECRYPT);
}

/************************************************
功能：将buf拆分为一个个CRYPT_BLOCK_SIZE大小的块分别
	  调用aes_decrypt_buf
输入：char* 类型的明文数据，密钥key和向量iv
输出：加密之后的密文
************************************************/
void do_decrypt_buf(char* buf, size_t size, AES_KEY* KEY)
{
	int len = 0;
	int piece_size = 0;
	while(len < size){
		if(size - len >= CRYPT_BLOCK_SIZE){
			piece_size = CRYPT_BLOCK_SIZE;
		}
		else{
			piece_size = size - len ;
		}
		
		aes_decrypt_buf(buf + len, buf + len, piece_size, KEY, iv);

		len += piece_size;
	}
}

/*************************************
功能：对一个aes加密的文件进行解密
      每一个CRYPT_BLOCK_SIZE大小视为一个独立的解密单位
输入：文件名，密钥文件
输出：直接对该文进进行原地还原
*************************************/
void aes_decrypt_file(const char* pathname)
{
	/*
	char key[16];
	int fd;
	fd = open(aeskeyname, O_RDONLY);
	if(fd == -1)
	{
		gf_log("dec", GF_LOG_ERROR, "aeskey file can't open !" );
		return;
	}
	if(read(fd, key, 16) != 16)
	{
		gf_log("dec", GF_LOG_ERROR, "read aeskey file error!" );
		return;
	}
	close(fd);
	*/
	AES_KEY KEY;
	aes_key_init_by_char(0, &KEY);

	do_aes_decrypt_file(pathname, &KEY);
}

void do_aes_decrypt_file(const char* pathname, AES_KEY* KEY)
{
	struct stat file_stat;
	stat(pathname, &file_stat);

	gf_log("dec", GF_LOG_TRACE, "file size before decrypt: %lld", (long long)file_stat.st_size);

	//int file = open(pathname,O_RDWR|O_TRUNC);
	int file_read = open(pathname, O_RDONLY);
	if(file_read == -1)
	{
		gf_log("dec", GF_LOG_ERROR, "open error!");
		return;
	}

	int file_write = open(pathname, O_WRONLY);
	if(file_write == -1)
	{
		gf_log("dec", GF_LOG_ERROR, "open error!");
		return;
	}

	//创建固定大小的缓冲数组进行分块解密
	//缓冲区大小定义为  128k
	unsigned char buf[BUF_SIZE];
	memset(buf, 0, sizeof(buf));
	//unsigned char plaintext[CRYPT_BLOCK_SIZE];
	//memset(plaintext, 0, sizeof(plaintext));

	off_t off_read,off_write;
	off_read=lseek(file_read, 0, SEEK_CUR);
	off_write=lseek(file_write, 0, SEEK_CUR);

	int read_result=0;
	int write_result=0;
	int count=0;//用来记录结尾有几个'\0'
	long long has_read = 0;

	read_result = pread(file_read, buf, BUF_SIZE , off_read);
	while(read_result !=0) //未到达文件尾端
	{
		count=0;
		while(read_result == -1) //读出错重新读
		{
			read_result = pread(file_read, buf, BUF_SIZE , off_read);
			gf_log("dec", GF_LOG_ERROR, "read error, begin to read again!");
		}
		has_read += read_result;
		//aes_decrypt_buf(buf, plaintext, read_result, KEY, iv);
		do_crypt_buf_pthread(buf, read_result, KEY, 0);

		if(has_read == (long long)file_stat.st_size)//到达文件末尾
		{
			while(buf[read_result-1-count] == 0)
				++count;
		}

		write_result = pwrite(file_write, buf, read_result, off_write);
		while(write_result == -1)
		{
			write_result = pwrite(file_write, buf, read_result, off_write);
			gf_log("dec", GF_LOG_ERROR, "write error, begin to write again!");
		}

		memset(buf, 0, sizeof(buf));
		//memset(plaintext, 0, sizeof(plaintext));

		off_read = lseek(file_read, read_result, SEEK_CUR);
		off_write = lseek(file_write, write_result, SEEK_CUR);

		read_result = pread(file_read, buf, BUF_SIZE , off_read);

	}

	truncate(pathname, file_stat.st_size - count);//去掉文件最后的空字符


	close(file_read);
	close(file_write);

	gf_log("dec", GF_LOG_TRACE, "decrypt success!");

}

/*************************************
功能：对一个文件进行cpabe解密
      每一个CRYPT_BLOCK_SIZE大小视为一个独立的解密单位
      底层调用的是128位cbc模式AES对称加密算法
输入：文件名，密钥文件
输出：直接对该文进进行原地还原
      解密成功返回0，失败返回-1
*************************************/
int cpabe_decrypt_file(const char* pathname, const char* privkey)
{
	//bswabe_pub_t* pub;
	bswabe_prv_t* prv;
	GByteArray* cph_buf;
	bswabe_cph_t* cph;
	element_t m;
	
	//后面的1为free位，选择读后自动free
	//pub = bswabe_pub_unserialize(suck_file(pubkey), 1);
	prv = bswabe_prv_unserialize(pub, suck_file(privkey), 1);

	read_cphbuf(pathname ,&cph_buf);
	gf_log("dec", GF_LOG_TRACE, "read success!");
	cph = bswabe_cph_unserialize(pub, cph_buf, 1);

	if( !bswabe_dec(pub, prv, cph, m) )
	{
		gf_log("dec", GF_LOG_ERROR, "priv cannot gennerate aeskey!");
		die("%s", bswabe_error());
		bswabe_cph_free(cph);
		return -1;
	}
	bswabe_cph_free(cph);
	remove_cph_xattr(pathname);

	AES_KEY KEY;
	aes_key_init_by_element(m, 0 ,&KEY);
	element_clear(m);

	do_aes_decrypt_file(pathname, &KEY);
	return 0;
}
/*
int main(int argc, char** argv)
{
	if(!strcmp(argv[1], "aes"))
	{
		aes_decrypt_file(argv[2], argv[3]);
	}
	else if(!strcmp(argv[1], "cpabe"))
	{
		cpabe_decrypt_file(argv[2], argv[3], argv[4]);
	}
	return 0;
}
*/
