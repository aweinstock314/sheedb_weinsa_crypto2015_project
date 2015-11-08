#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

#define ECODE_SUCCESS 0
#define ECODE_FAILURE 1
typedef uint8_t error_code;

int dgetc(int fd);

error_code read_aon(int fd, char* buf, size_t count);
error_code write_aon(int fd, const char* buf, size_t count);

error_code recv_synchronize(int fd);
error_code send_synchronize(int fd);

#endif
