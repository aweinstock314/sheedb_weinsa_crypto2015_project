#ifndef DATATYPES_H
#define DATATYPES_H
#include <openssl/hmac.h>
#include <stdint.h>
#include "constants.h"

struct hmac_t { uint8_t hmac[EVP_MAX_MD_SIZE]; };

struct username_t { uint8_t username[MAX_USERNAME_LENGTH]; };

struct nonce_t { uint8_t nonce[NONCE_SIZE]; };

struct currency_t { uint64_t cents; };

enum cts_payload_tag {
    requestNonce = 0,
    requestBalance,
    requestWithdrawl,
    requestTransfer,
    requestLogout
};

struct cts_payload {
    cts_payload_tag tag;
    nonce_t nonce;
    currency_t currency;
    username_t destination;
};

struct client_to_server {
    struct hmac_t hmac;
    struct username_t src;
    struct cts_payload payload;
};

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

struct stc_payload {
    stc_payload_tag tag;
    nonce_t nonce;
    currency_t currency;
};

struct server_to_client {
    struct hmac_t hmac;
    struct stc_payload payload;
};

#endif
