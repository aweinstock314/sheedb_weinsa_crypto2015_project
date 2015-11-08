#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"


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
