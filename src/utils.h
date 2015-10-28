#include <stdio.h>

struct error_code { int err; };

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
}
