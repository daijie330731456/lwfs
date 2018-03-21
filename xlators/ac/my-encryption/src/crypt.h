/****************************************
和加密相关的函数申明
****************************************/

#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

#include "bswabe.h"
#include "policy_lang.h"
#include "logging.h"

//#define CRYPT_BLOCK_SIZE 1024
#define MAX_XTTR_LENGTH (64 * 1024)
#define MAX_CP_BUF_LEN_BITS 20


#define BUF_SIZE 128*1024


//加密相关函数
void aes_encrypt_buf(const unsigned char* buf,unsigned char* ciphertext,const int length,AES_KEY* KEY, const char* iv);
void aes_encrypt_file(const char* pathname);
void do_aes_encrypt_file(const char* pathname, AES_KEY* KEY);
int cpabe_encrypt_file(const char* pathname, char* policy);


//解密相关函数
void aes_decrypt_buf(const unsigned char* ciphertext,unsigned char* plaintext,const int length,AES_KEY* KEY,const char* iv);
void aes_decrypt_file(const char* pathname);
void do_aes_decrypt_file(const char* pathname, AES_KEY* KEY);
int cpabe_decrypt_file(const char* pathname, const char* privkey);


//common相关函数
void aes_key_init_by_element(element_t k, int enc, AES_KEY* KEY);
void aes_key_init_by_char(int enc, AES_KEY* KEY);
void read_cphbuf(const char* pathname, GByteArray** cph_buf);
void write_cphbuf(const char* pathname,  GByteArray* cph_buf);
void remove_cph_xattr(const char* pathname);

char*       suck_file_str( char* file );
char*       suck_stdin();
GByteArray* suck_file(const char* file );

void        spit_file( char* file, GByteArray* b, int free );


void die(char* fmt, ...);


void do_crypt_buf_pthread(char* buf, size_t size, AES_KEY* KEY, int enc);
void* func(void* arg);

void do_decrypt_buf(char* buf, size_t size, AES_KEY* KEY);
void do_encrypt_buf(char* buf, size_t size, AES_KEY* KEY);

