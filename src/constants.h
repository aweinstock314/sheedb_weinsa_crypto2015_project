#ifndef CONSTANTS_H
#define CONSTANTS_H

#define MAX_CLIENTS 4096 // arbitrary power of 2
#define MAX_USERNAME_SIZE 23 // arbitrary odd prime > strlen("alice\0")
#define NONCE_SIZE 16 // 128-bits, arbitrary power of 2
#define ENCRYPT_KEY_SIZE 16 //128-bits, 128 bit AES is fine
#define MAC_KEY_SIZE 16 //128-bits, arbitrary power of 2
#define PIN_SIZE 4 //32 bits, 4 digit pin code

#endif
