#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <stdint.h>
#include <string>
#include <vector>

#define ECODE_SUCCESS 0
#define ECODE_FAILURE 1
typedef uint8_t error_code;

int dgetc(int fd);

error_code read_aon(int fd, char* buf, size_t count);
error_code write_aon(int fd, const char* buf, size_t count);

error_code recv_synchronize(int fd);
error_code send_synchronize(int fd);

int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key,
    unsigned char* ciphertext);
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key,
    unsigned char* plaintext);

int genHMAC(const unsigned char* data, int data_len, const unsigned char* key, unsigned char* destination);

std::vector<std::string> tokenize(std::string s);
std::vector<std::string> get_tokenized_line();

/*char* serialize_uint64(uint64_t value, char* buf);
char* deserialize_uint64(uint64_t &value, char* buf);

char* serialize_uint8a(uint8_t* value, int size, char* buf);
char* deserialize_uint8_a(uint8_t* value, int size, char* buf);*/

#endif
