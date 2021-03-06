#ifndef CONSTANTS_H
#define CONSTANTS_H

#define MAX_CLIENTS 4096 // arbitrary power of 2
#define MAX_USERNAME_SIZE 23 // arbitrary odd prime > strlen("alice\0")
#define NONCE_SIZE 16 // 128-bits, arbitrary power of 2
#define ENCRYPT_KEY_SIZE 16 //128-bits, 128 bit AES is fine
#define MAC_KEY_SIZE 16 //128-bits, arbitrary power of 2
#define PIN_SIZE 4 //32 bits, 4 digit pin code
#define AES_BLOCKSIZE_BYTES (128/8) //16 byte block size
#define PADDING_FUDGE_FACTOR (2 * AES_BLOCKSIZE_BYTES) //Overallocate to be safe
#define CENTS_PER_DOLLAR 100
#define PADDING(s) (AES_BLOCKSIZE_BYTES - (sizeof(struct s) % AES_BLOCKSIZE_BYTES))
#define TIMEOUT_SECONDS 5
#define TIMEOUT_MICROSECONDS 0
#define SERVER_TIMEOUT_SECONDS 10

#endif
