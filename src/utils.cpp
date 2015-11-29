#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include "utils.h"

#define IV 0 //Constant IV for now

// allocating descriptor get-string [with] delimiter, abandoned after deciding that fixed-length messages were a better idea
/*
//struct error_code { int err; };

#define ADGETS_MIN_SIZE 16

struct error_code adgets_d(char** pbuf, int fd, char delim) {
    assert(pbuf != 0);
    assert(*pbuf == 0);
    size_t capacity = ADGETS_MIN_SIZE;
    size_t count=0;
    char *buf, *p, c;

    if(!(p = buf = malloc(capacity * sizeof(char)))) {
        return error_code { .err = 1 };
    }

    for(;;) {
        if(read(fd, &c, 1) == -1) { goto fail; }
        if(c == delim) { break; }
        if(count >= capacity) {
            // TODO: resize buffer
        }
        // TODO: write to buffer
    }

    *pbuf = buf;
    return error_code { .err = 0 };

    fail:
    free(buf);
    return error_code { .err = 1 };
}*/

int dgetc(int fd) {
    char c;
    return (read(fd, &c, sizeof(char)) == sizeof(char)) ? c : EOF;
}

// "all or nothing" read/write, to handle interruptions/byte-by-byte input
#define DEF_AON(prefix, underlying) \
error_code underlying ## _aon(int fd, prefix char* buf, size_t count) { \
    ssize_t tmp, sofar=0; \
    while(sofar < count) { \
        tmp = underlying(fd, buf+sofar, count-sofar); \
        if(tmp <= 0) { return ECODE_FAILURE; } \
        sofar += tmp; \
    } \
    return ECODE_SUCCESS; \
}

DEF_AON(,read)
DEF_AON(const, write)

#undef DEF_AON

const char synchronization_magic[] = "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh";

// read bytes from fd until a specific magic sequence has been read
error_code recv_synchronize(int fd) {
    size_t i;
    int c;
    char buf[sizeof synchronization_magic];
    if(read_aon(fd, buf, sizeof synchronization_magic)) { return ECODE_FAILURE; }
    while(memcmp(buf, synchronization_magic, sizeof synchronization_magic)) {
        // shift the buffer left, and add the next byte to the end
        for(i=0; i < (sizeof synchronization_magic)-1; i++) {
            buf[i] = buf[i+1];
        }
        if((c = dgetc(fd)) == EOF) {
            return ECODE_FAILURE;
        } else {
            buf[i] = c;
        }
    }
    return ECODE_SUCCESS;
}

// send the magic synchronization sequence
error_code send_synchronize(int fd) {
    return write_aon(fd, synchronization_magic, sizeof synchronization_magic);
}

//Encrypts using 128 bit AES
//Based off the encryption sample code on the openssl wiki
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
        unsigned char* ciphertext){
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

    //Initialize context
    if(!(ctx = EVP_CIPHER_CTX_new() ) ){
        return -1;    
    }

    //Initialize AES
    if( EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, IV) != 1 ){
        return -1;
    }

    //Encrypt data
    if( EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1 ){
        return -1;
    }
    ciphertext_len = len;
    
    //Finish encryption
    if( EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1 ){
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

//Decrypts using 128 bit AES
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
        unsigned char* plaintext){
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;
    
    //Create context
    if(!(ctx = EVP_CIPHER_CTX_new()) ){
        return -1;
    }

    //Initialize AES
    if( EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, IV) != 1 ){
        return -1;
    }

    //Decrypt data
    if( EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1 ){
        return -1;
    }
    plaintext_len = len;

    //Finish decryption
    if( EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1 ){
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

/*
//Helper function to copy the data in a unint64_t into a char*. Returns the updated pointer that has been advanced past the copied data
char* serialize_uint64(uint64_t value, char* buf){
    memcpy(buf, &value, sizeof(value));
    buf += sizeof(value);
    return buf;
}

//Helper function to extract a unint64_t from a char*. Returns the updated pointer that has been advanced past the copied data.
char* deserialize_uint64(uint64_t &value, char* buf){
    memcpy(&value, buf, sizeof(value));
    buf += sizeof(value);
    return buf;
}

//Helper function to copy the data in a uint8_t array into a char*. Returns the updated pointer that has been advanced past the copied data
char* serialize_uint8a(uint8_t* value, unsigned int size, char* buf){
    memcpy(buf, value, size);
    buf += size;
    return buf;
}

//Helper function to extract a uint8_t array from a char*. Returns the updated pointer that has been advanced past the copied data
char* deserialize_uint8a(uint8_t* value, unsigned int size, char* buf){
    memcpy(value, buf, size);
    buf += size;
    return buf;
}*/

