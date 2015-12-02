#include <openssl/evp.h>
#include <alloca.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <iostream>

#include "constants.h"
#include "utils.h"

#define IV 0 //Constant IV for now

using namespace std;

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
    ssize_t tmp; \
    size_t sofar = 0; \
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

//High level function for calling read_aon and recv_synchronize
error_code read_synchronized(int fd, char* buf, size_t count){
    return recv_synchronize(fd) ? ECODE_FAILURE : read_aon(fd, buf, count);
}

//High level function for calling write_aon and send_synchronize
error_code write_synchronized(int fd, const char* buf, size_t count){
    return send_synchronize(fd) ? ECODE_FAILURE : write_aon(fd, buf, count);
}

//Encrypts using 128 bit AES
//Based off the encryption sample code on the openssl wiki
int encrypt(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, unsigned char* ciphertext){
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len = 0;
    int ret = -1;

    //Initialize context
    if(!(ctx = EVP_CIPHER_CTX_new() ) ){
        return ret; // avoid freeing uninitialized data
    }

    //Initialize AES
    if( EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, IV) != 1 ){
        goto cleanup;
    }

    //Encrypt data
    if( EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1 ){
        goto cleanup;
    }
    ciphertext_len = len;
    
    //Finish encryption
    if( EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1 ){
        goto cleanup;
    }
    ciphertext_len += len;
    ret = ciphertext_len;

    cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

//Decrypts using 128 bit AES
int decrypt(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, unsigned char* plaintext){
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;
    int ret = -1;
    
    //Create context
    if(!(ctx = EVP_CIPHER_CTX_new()) ){
        return ret; // avoid freeing uninitialized data
    }

    //Initialize AES
    if( EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, IV) != 1 ){
        goto cleanup;
    }

    //Decrypt data
    if( EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1 ){
        goto cleanup;
    }
    plaintext_len = len;

    //Finish decryption
    if( EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1 ){
        goto cleanup;
    }
    plaintext_len += len;
    ret = plaintext_len;

    cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

#define ENSERIALCRYPT_BODY \
if(encrypt((const unsigned char*)src, sizeof(*src), cryptkey, (unsigned char*)&dst->payload) < 0) { \
    return ECODE_FAILURE; \
} \
if(genHMAC((const unsigned char*)&dst->payload, sizeof(dst->payload), \
    signkey, (unsigned char*)&dst->hmac) < 0) { \
    return ECODE_FAILURE; \
} \
return ECODE_SUCCESS;

#define DESERIALCRYPT_BODY \
if(verifyHMAC((const unsigned char*)&src->payload, sizeof(src->payload), \
    signkey, (unsigned char*)&src->hmac) == ECODE_FAILURE) { \
    return ECODE_FAILURE; \
} \
if(decrypt((const unsigned char*)&src->payload, sizeof(src->payload), cryptkey, (unsigned char*)dst) < 0) { \
    return ECODE_FAILURE; \
} \
return ECODE_SUCCESS;


error_code enserialcrypt_cts(const unsigned char* cryptkey, const unsigned char* signkey,
    const struct cts_payload* src, struct client_to_server* dst) {
    ENSERIALCRYPT_BODY
}

error_code deserialcrypt_cts(const unsigned char* cryptkey, const unsigned char* signkey,
    const struct client_to_server* src, struct cts_payload* dst) {
    DESERIALCRYPT_BODY
}

error_code enserialcrypt_stc(const unsigned char* cryptkey, const unsigned char* signkey,
    const struct stc_payload* src, struct server_to_client* dst) {
    ENSERIALCRYPT_BODY
}
error_code deserialcrypt_stc(const unsigned char* cryptkey, const unsigned char* signkey,
    const struct server_to_client* src, struct stc_payload* dst) {
    DESERIALCRYPT_BODY
}

#undef ENSERIALCRYPT_BODY
#undef DESERIALCRYPT_BODY

//Generates an HMAC for the given key and data and puts it into destination. Returns the length of the hmac or -1 on error.
int genHMAC(const unsigned char* data, int data_len, const unsigned char* key, unsigned char* destination){
    unsigned int len;
    unsigned char* result = HMAC(EVP_sha256(), key, MAC_KEY_SIZE, data, data_len,
        destination, &len);
    if(result == NULL){
        return -1;
    }
    return len;
}

error_code verifyHMAC(const unsigned char* data, int data_len, const unsigned char* key, const unsigned char* hmac) {
    struct hmac_t tmp;
    if(genHMAC(data, data_len, key, (unsigned char*)&tmp) < 0) {
        return ECODE_FAILURE;
    }
    // CRYPTO_memcmp mitigates http://rdist.root.org/2010/08/05/optimized-memcmp-leaks-useful-timing-differences/
    return CRYPTO_memcmp(hmac, &tmp, sizeof tmp) == 0 ? ECODE_SUCCESS : ECODE_FAILURE;
}

std::vector<std::string> tokenize(std::string s, const char* delimiter) {
    size_t len = s.size();
    char *saveptr, *token, *base = (char*)alloca(len+1);
    memcpy(base, s.c_str(), len);
    base[len] = 0;
    std::vector<std::string> tokens;
    token = strtok_r(base, delimiter, &saveptr);
    while(token != NULL) {
        tokens.push_back(std::string(token));
        token = strtok_r(NULL, delimiter, &saveptr);
    }
    return tokens;
}

std::vector<std::string> get_tokenized_line() {
    std::string input;
    std::getline(std::cin, input);
    return tokenize(input, " ");
}

bool checkNonce(const uint8_t* n1, const uint8_t* n2){
    if(memcmp(n1, n2, NONCE_SIZE) != 0){
        cerr << "Nonce mismatch" << endl;
        return false;
    }
    return true;
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

char hexdigit(char nybble) {
    if((0x0 <= nybble) && (nybble <= 0x9)) { return '0'+nybble; }
    if((0xA <= nybble) && (nybble <= 0xF)) { return 'A'+nybble-0xA; }
    return '?';
}

void hexdump(int fd, const void* buffer, size_t count) {
    const unsigned char* p = (const unsigned char*)buffer;
    char outbuf[2];
    ssize_t unused;
    while(count--) {
        outbuf[0] = hexdigit(((*p) & 0xf0) >> 4);
        outbuf[1] = hexdigit((*p) & 0x0f);
        unused = write(fd, outbuf, 2);
        (void)unused;
        p++;
    }
}

void print_prompt() {
    cout << "> ";
    cout.flush();
}

