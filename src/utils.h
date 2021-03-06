#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <stdint.h>
#include <string>
#include <vector>
#include "datatypes.h"

#define ECODE_SUCCESS 0
#define ECODE_FAILURE 1
typedef uint8_t error_code;

int dgetc(int fd);

//Read/write all or error
error_code read_aon(int fd, char* buf, size_t count);
error_code write_aon(int fd, const char* buf, size_t count);

//Send/receive synchronization sequence
error_code recv_synchronize(int fd);
error_code send_synchronize(int fd);

//High level functions for synchronized reads and writes
error_code read_synchronized(int fd, char* buf, size_t count);
error_code write_synchronized(int fd, const char* buf, size_t count);

//AES encryption and decryption
int encrypt(const unsigned char* plaintext, int plaintext_len, const unsigned char* key, unsigned char* ciphertext);
int decrypt(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, unsigned char* plaintext);

//HMAC functions
int genHMAC(const unsigned char* data, int data_len, const unsigned char* key, unsigned char* destination);
error_code verifyHMAC(const unsigned char* data, int data_len, const unsigned char* key, const unsigned char* hmac);

// {,de}serialize and {en,de}crypt (and sign) as conceptually-atomic operations
// argument order: {en,de}cryption key, signing key, source, destination
// the enserialcrypt ones should never fail (always return ECODE_SUCCESS)
// the deserialcrypt ones should return ECODE_FAILURE iff the signature fails to validate
// the caller of enserialcrypt_cts is responsible for populating the username
error_code enserialcrypt_cts(const unsigned char* cryptkey, const unsigned char* signkey,
    const struct cts_payload* src, struct client_to_server* dst);
error_code deserialcrypt_cts(const unsigned char* cryptkey, const unsigned char* signkey,
    const struct client_to_server* src, struct cts_payload* dst);
error_code enserialcrypt_stc(const unsigned char* cryptkey, const unsigned char* signkey,
    const struct stc_payload* src, struct server_to_client* dst);
error_code deserialcrypt_stc(const unsigned char* cryptkey, const unsigned char* signkey,
    const struct server_to_client* src, struct stc_payload* dst);

std::vector<std::string> tokenize(std::string s, const char* delimiter);
std::vector<std::string> get_tokenized_line();

//Returns true if the two nonces match, returns false otherwise and prints error
bool checkNonce(const uint8_t* n1, const uint8_t* n2);

/*char* serialize_uint64(uint64_t value, char* buf);
char* deserialize_uint64(uint64_t &value, char* buf);

char* serialize_uint8a(uint8_t* value, int size, char* buf);
char* deserialize_uint8_a(uint8_t* value, int size, char* buf);*/

char hexdigit(char nybble);
void hexdump(int fd, const void* buffer, size_t count);
void print_prompt();

void output_dollars(std::ostream& o, currency_t amount);
bool convertTokenToCents(std::string token, uint64_t &value);

#endif
