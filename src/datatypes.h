#ifndef DATATYPES_H
#define DATATYPES_H
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdint.h>
#include "constants.h"

struct hmac_t { unsigned char hmac[EVP_MAX_MD_SIZE]; };

struct username_t { char username[MAX_USERNAME_SIZE]; };

struct nonce_t { uint8_t nonce[NONCE_SIZE]; };

struct currency_t { uint64_t cents; };

//Client to server message types
enum cts_payload_tag {
    requestNonce = 0,
    requestBalance,
    requestWithdrawl,
    requestTransfer,
    requestLogout
};

//Client to server message contents
struct cts_payload {
    cts_payload_tag tag;
    nonce_t nonce;
    currency_t currency;
    username_t destination;
};

//Encrypted client to server message contents
struct cts_payload_enc {
    //AES uses multiples of 16 bytes
    unsigned char payload[sizeof(struct cts_payload) + (sizeof(struct cts_payload) % 16) + 16];
};

//Client to server message
struct client_to_server {
    struct hmac_t hmac;
    struct username_t src;
    struct cts_payload_enc payload;
};

//Server to client message types
enum stc_payload_tag {
    supplyNonce = 0,
    invalidNonce,
    invalidUser, // only for the initiator of a request
    insufficentFunds, // for either withdrawl or transfer
    ackBalance,
    ackWithdrawlSuccess,
    ackWithdrawlFail, // "Insufficient funds"
    ackTransferSuccess,
    ackTransferInvalidDestination, // destination user doesn't exist
};

//Server to client message contents
struct stc_payload {
    stc_payload_tag tag;
    nonce_t nonce;
    currency_t currency;
};

//Encrypted server to client message contents
struct stc_payload_enc {
    //AES uses multiples of 16 bytes
    unsigned char* payload[sizeof(struct stc_payload) + (sizeof(struct stc_payload) % 16)];
};

//Server to client message
struct server_to_client {
    struct hmac_t hmac;
    struct stc_payload_enc payload;
};

#endif
