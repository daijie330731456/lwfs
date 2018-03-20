#include "crypt.h"
#include "policy_lang.h"

extern const char iv[];
extern int CRYPT_BLOCK_SIZE;

/******************************************
���ܣ����ַ�������128λCBCģʽAES����
      �����˻��������зֿ�ӽ��ܣ����Դ�����ļ�
���룺char* ���͵��������ݣ���Կkey������iv
���������֮�������
******************************************/
void aes_encrypt_buf(const unsigned char* buf,unsigned char* ciphertext,const int length,AES_KEY* KEY, const char* iv)
{
	int use_length = (length % AES_BLOCK_SIZE == 0) ? length : ((length/AES_BLOCK_SIZE+1)*AES_BLOCK_SIZE);
	//ÿ�μ��㶼��Ҫ��ʼ��iv��ֵ
	unsigned char use_iv[AES_BLOCK_SIZE];
	memcpy(use_iv,iv,sizeof(use_iv));

	AES_cbc_encrypt(buf,ciphertext,use_length,KEY, use_iv,AES_ENCRYPT);

	//return 0;
}

/************************************************
���ܣ���buf���Ϊһ����CRYPT_BLOCK_SIZE��С�Ŀ�ֱ�
	  ����aes_encrypt_buf
���룺char* ���͵��������ݣ���Կkey������iv
���������֮�������
************************************************/
void do_encrypt_buf(char* buf, size_t size, AES_KEY* KEY)
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
		
		aes_encrypt_buf(buf + len, buf + len, piece_size, KEY, iv);

		len += piece_size;
	}
}


/*************************************************
���ܣ���һ���ļ�����AES����
      ÿһ��CRYPT_BLOCK_SIZE��С��Ϊһ�������ļ��ܵ�λ
���룺�ļ�������Կ�ļ���iv����
��������ģ�ֱ�ӶԸ��ļ�����ԭ�ؼ���
*************************************************/
void aes_encrypt_file(const char* pathname)
{
	/*
	char key[16];
	int fd;
	fd = open(aeskeyname, O_RDONLY);
	if(fd == -1)
	{
		gf_log("enc", GF_LOG_ERROR, "aeskey file can't open !" );
		return;
	}
	if(read(fd, key, 16) != 16)
	{
		gf_log("enc", GF_LOG_ERROR, "read aeskey file error!" );
		return;
	}
	close(fd);

	//printf("the key is:%s\n", key);
	*/
	
	AES_KEY KEY;
	aes_key_init_by_char(1, &KEY);

	do_aes_encrypt_file(pathname, &KEY);
}

void do_aes_encrypt_file(const char* pathname, AES_KEY* KEY)
{
	struct stat file_stat;
	stat(pathname, &file_stat);

	gf_log("enc", GF_LOG_TRACE, "file size before encrypt: %lld", (long long)file_stat.st_size);

	//int file = open(pathname,O_RDWR|O_TRUNC);
	int file_read = open(pathname, O_RDONLY);
	if(file_read == -1)
	{
		gf_log("enc", GF_LOG_ERROR, "open error!");
		return;
	}

	int file_write = open(pathname, O_WRONLY);
	if(file_write == -1)
	{
		gf_log("enc", GF_LOG_ERROR, "open error!");
		return;
	}

	//�����̶���С�Ļ���������зֿ����
	//��������СΪ128k
	unsigned char buf[BUF_SIZE];
	memset(buf,0,sizeof(buf));
	//unsigned char ciphertext[CRYPT_BLOCK_SIZE * PTHREAD_COUNT];
	//memset(ciphertext, 0, sizeof(ciphertext));

	off_t off_read,off_write;
	off_read=lseek(file_read, 0, SEEK_CUR);
	off_write=lseek(file_write, 0, SEEK_CUR);

	int read_result=0;
	int write_result=0;
	int use_length = 0;

	read_result = pread(file_read, buf, BUF_SIZE, off_read);
	while(read_result !=0) //δ�����ļ�β��
	{
		while(read_result == -1) //���������¶�
		{
			read_result = pread(file_read, buf, BUF_SIZE, off_read);
			gf_log("enc", GF_LOG_ERROR, "read error, begin to read again!");
		}

		//aes_encrypt_buf(buf, ciphertext, read_result, KEY);
		do_crypt_buf_pthread(buf, read_result, KEY, 1);
		//�������ĳ��ȣ�����16nits�Ĳ��ֻᱻ���뵽16bits
		use_length = (read_result % AES_BLOCK_SIZE == 0) ? read_result : ((read_result/AES_BLOCK_SIZE+1)*AES_BLOCK_SIZE);

		write_result = pwrite(file_write, buf, use_length, off_write);
		while(write_result == -1)//д��������д
		{
			write_result = pwrite(file_write, buf, use_length, off_write);
			gf_log("enc", GF_LOG_ERROR, "write error, begin to write again!");
		}

		memset(buf,0,sizeof(buf));
		//memset(ciphertext, 0, sizeof(ciphertext));

		off_read=lseek(file_read, use_length, SEEK_CUR);
		off_write=lseek(file_write, write_result, SEEK_CUR);

		read_result = pread(file_read, buf, BUF_SIZE, off_read);

	}

	close(file_read);
	close(file_write);

	gf_log("enc", GF_LOG_TRACE, "encrypt success!");
}

/*************************************************
���ܣ���һ���ļ�����CPABE����
      ÿһ��CRYPT_BLOCK_SIZE��С��Ϊһ�������ļ��ܵ�λ
      �ײ���õ���128λcbcģʽAES�ԳƼ���
���룺�ļ�������Կ�ļ����������ַ���
��������ģ�ֱ�ӶԸ��ļ�����ԭ�ؼ���
       policy��������չ���Եĸ�ʽ���ļ��洢��һ��
*************************************************/
int cpabe_encrypt_file(const char* pathname, const char* pubkey, char* policy)
{
	bswabe_pub_t* pub;
	bswabe_cph_t* cph;
	GByteArray* cph_buf;
	element_t m;

	//����
	struct timeval start, end;

	//gettimeofday(&start, NULL);
	//���ع�Կ�ļ�pubkey
	pub = bswabe_pub_unserialize(suck_file(pubkey), 1);
	//gettimeofday(&end, NULL);
	//gf_log("enc", GF_LOG_TRACE, "pub unserialize use time:%d",
		//(end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec));


	//gettimeofday(&start, NULL);
	//��������ַ���
	char* policy_use  = parse_policy_lang(policy);
	//gettimeofday(&end, NULL);
	//gf_log("enc", GF_LOG_TRACE, "parse policy use time:%d",
		//(end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec));

	gettimeofday(&start, NULL);
	//�������ɶԳ���Կm�Ͳ�������cph
	if( !(cph = bswabe_enc(pub, m, policy_use)) )
	{

		gf_log("enc", GF_LOG_ERROR, "cannot gennerate m and cph!");
		die("%s", bswabe_error());
		
		free(policy_use);
		element_clear(m);
		bswabe_cph_free(cph);

		return -1;
	}	
	free(policy_use);

	gettimeofday(&end, NULL);
        gf_log("enc", GF_LOG_TRACE, "bswabe_enc use time:%d",
                (end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec));	

	cph_buf = bswabe_cph_serialize(cph);
	bswabe_cph_free(cph);

	//gettimeofday(&start, NULL);
	AES_KEY KEY;
	aes_key_init_by_element(m, 1 ,&KEY);
	do_aes_encrypt_file(pathname, &KEY);
	element_clear(m);
	//gettimeofday(&end, NULL);
	//gf_log("enc", GF_LOG_TRACE, "do aes use time:%d",
	//	(end.tv_sec - start.tv_sec)*1000000 + (end.tv_usec - start.tv_usec));

	write_cphbuf(pathname, cph_buf);

	g_byte_array_free(cph_buf, 1);
	
	return 0;
}
/*
int main(int argc, char** argv)
{
	if(!strcmp(argv[1], "aes"))
	{
		aes_encrypt_file(argv[2], argv[3]);
	}
	else if(!strcmp(argv[1], "cpabe"))
	{
		cpabe_encrypt_file(argv[2], argv[3], argv[4]);
	}
	return 0;
}
*/
