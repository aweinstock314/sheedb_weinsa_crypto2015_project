#`sheedb_weinsa_crypto2015_project`
###ATM project for `Cryptography and Network Security` class


# Authors:
- Brian Sheedy
- Avi Weinstock

# Installation and Compilation
* Run `./bootstrap.sh && make`
* If at any point you need to recompile, run `make clean && make`

# Usage
* Binaries are placed in the bin directory
* The proxy and bank can be run from anywhere, but the ATM must be run from within the bin directory ("./atm") in order for it to find the cards
* Cleaning and recompiling will regenerate PINs and keys. If you forget your current PINs and don't want to recompile, the first four characters in *.card are the PINs


```
22:18:13 <+aweinstock> Unix-Dude: what are the requirements for the "protocol specification"?
22:18:27 <+aweinstock> (i.e. do we have the code the entire system again in English?)
22:18:38 <@Lense> no
22:19:03 <+aweinstock> how about Latin?
22:19:17 <+aweinstock> (but seriously, what is it supposed to consist of?)
22:20:25 <@Lense> Include the sentence: "To understand how my protocol works, read my code"
```

# Protocol Security
The protocol uses three forms of cryptography: an HMAC for data integrity, encryption for data confidentiality, and a nonce to prevent replay attacks.
## The HMAC uses:
* A 128 bit key
* SHA-256 as the hash function
* OpenSSL's EVP functions for the actual calculations
* Is calculated on the encrypted data

## The encryption uses:
* AES with a 128 bit key
* PKCS padding enabled

## The nonce uses:
* 128 bits from /dev/urandom
* Is calculated for every interaction between the ATM and bank
* Is cleared from the bank after every interaction

A mismatched nonce or HMAC on either side causes the current action to be aborted but keeps the connection intact

# Protocol Format
The protocol consists of two types of message structs, client-to-server and server-to-client. A more technical view (aka source code) of the message format can be found in the datatypes.h source file.

## Client-to-server messages consist of:
* The payload HMAC (byte array)
* The username of the sending client (byte array)
* The encrypted payload (byte array)

## The unencrypted client-to-server payload consists of:
* Tag describing what type of message it is (integer)
* Nonce (byte array)
* Currency in cents for withdrawal/transfer (uint64)
* Destination user for transfer (byte array)

## Server-to-client messages consist of:
* The payload HMAC (byte array)
* The encrypted payload (byte array)

## The unencrypted server-to-client message consists of:
* Tag describing what type of message it is (integer)
* Nonce (byte array)
* Currency in cents (uint64)

Messages are also preceded by a synchronization sequence

# Protocol Outline
1.  Client creates a nonce request payload
2.  Client encrypts payload and generates HMAC
3.  Client sends synchronization sequence then the message
4.  Server checks HMAC and decrypts
5.  Server generates new nonce, encrypts payload, and generates HMAC
6.  Server sends synchronization sequence then the message
7.  Client receives message and checks HMAC
8.  Client extracts nonce
9.  Client creates a request payload for whatever action they want and includes nonce
10.  Client encrypts payload and generates HMAC
11.  Client sends synchronization sequence then the message
12.  Server checks HMAC and decrypts
13.  Server checks nonce
14.  Server checks validity of requested action
15.  Server adds nonce to payload and any relevant currency information
16.  Server encrypts payload, generates HMAC, and sends synchronization sequence and message to client
17.  Server clears nonce
18.  Client receives message
19.  Client checks HMAC and decrypts payload
20.  Client checks nonce
21.  Client displays results of action to user
