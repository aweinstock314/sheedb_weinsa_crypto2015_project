/*
ATM program for the crypto project
*/

#include <sys/socket.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/epoll.h>
#include <string>
#include <vector>
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <cmath>
#include <iomanip>
#include <cerrno>
#include <time.h>

#include "constants.h"
#include "utils.h"
#include "datatypes.h"

#define CARD_PATH "../cards/"

using namespace std;

//Global variables
int sd; //Socket descriptor
bool connected = false;
string user;
uint8_t nonce[NONCE_SIZE];
unsigned char encrypt_key[ENCRYPT_KEY_SIZE];
unsigned char mac_key[MAC_KEY_SIZE];

/*##############################################################################
Macros
##############################################################################*/

//Initializes and zeroes the structs and arrays used for a client to server message
#define INIT_CTS \
    struct client_to_server message; \
    memset(&message, 0, sizeof(message)); \
    struct cts_payload payload; \
    memset(&payload, 0, sizeof(payload)); \
    char serialized_message[sizeof(message)];

//Initializes and zeroes the structs and arrays used for a server to client message
#define INIT_STC \
    struct server_to_client server_message; \
    memset(&server_message, 0, sizeof(server_message)); \
    struct stc_payload server_payload; \
    memset(&server_payload, 0, sizeof(server_payload)); \
    char serialized_server_message[sizeof(server_message)]; 

//Encrypts and packages a cts payload and returns if it fails
#define ENC_PACK_CTS \
    int rc = enserialcrypt_cts(encrypt_key, mac_key, &payload, &message); \
    if(rc != ECODE_SUCCESS){ \
        cerr << "Encryption failed" << endl; \
        return; \
    }

//Serialize and send a cts message
#define SER_SEND_CTS \
    serializeClientToServer(serialized_message, &message); \
    rc = write_synchronized(sd, serialized_message, sizeof(message)); \
    if(rc != ECODE_SUCCESS){ \
        cerr << "Failed to send request" << endl; \
        checkConnection(); \
        return; \
    }

//Receives and deserializes a cts message
#define RECV_DES_STC \
    rc = read_synchronized(sd, serialized_server_message, sizeof(server_message)); \
    if(rc != ECODE_SUCCESS){ \
        cerr << "Failed to receive valid response" << endl; \
        checkConnection(); \
        checkTimeout(); \
        return; \
    } \
    deserializeServerToClient(serialized_server_message, &server_message);

//Checks HMAC, decrypts and unpacks stc payload
#define HMAC_DEC_UNPACK_STC \
    rc = deserialcrypt_stc(encrypt_key, mac_key, &server_message, &server_payload); \
    if(rc != ECODE_SUCCESS){ \
        cerr << "Mismatched HMAC" << endl; \
        return; \
    }

//Handles all the encryption, sending, receiving, etc. that's the same in all actions
#define SEND_REQUEST_RECV_RESPONSE \
    /*Encrypt and package cts payload into cts message*/ \
    ENC_PACK_CTS \
    /*Serialize and send cts message*/ \
    SER_SEND_CTS \
    /*Initialize stc structs and arrays*/ \
    INIT_STC \
    /*Get response from bank and deserialize the message*/ \
    RECV_DES_STC \
    /*Check HMAC, decrypt, and unpack stc payload*/ \
    HMAC_DEC_UNPACK_STC

/*##############################################################################
Menu Functions
##############################################################################*/

void printMenu(){
    cout << endl;
    cout << "Please enter your desired command" << endl;
    cout << "Make sure amounts are entered in the form dollars.cents without a dollar sign" << endl;
    cout << "login [username]" << endl;
    cout << "balance" << endl;
    cout << "withdraw [amount]" << endl;
    cout << "transfer [amount] [username]" << endl;
    cout << "logout" << endl;
    cout << endl;
}

/*##############################################################################
Misc Functions
##############################################################################*/

void closeConnection(){
    connected = false;
    user = "";
    close(sd);
}

void connectionLost(){
    cout << "Connection lost. Logging out" << endl;
    closeConnection();
}

//Checks whether a function failed due to a closed connection
//If so, logs out
void checkConnection(){
    if(errno == EPIPE || errno == EINTR || errno == ECONNRESET || errno == ENOTCONN){
        connectionLost();
    }
}

//Checks whether a read call timed out
void checkTimeout(){
    if(errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT){
        cout << "Timed out waiting for response" << endl; 
    }
}

void serializeClientToServer(char* buf, const struct client_to_server* message){
    memcpy(buf, message, sizeof(*message));
}

void deserializeServerToClient(const char* buf, struct server_to_client* message){
    memcpy(message, buf, sizeof(*message));
}

//Gets a new nonce for communication
bool getNonce(){
    //Initialize cts structs and arrays
    INIT_CTS

    //Prepare the payload for encryption
    payload.tag = requestNonce;

    //Add the sending user
    strcpy(message.src.username, user.c_str());

    //Encrypt and package payload
    int rc = enserialcrypt_cts(encrypt_key, mac_key, &payload, &message);
    if(rc != ECODE_SUCCESS){
        return false;
    }
    
    //Send the nonce request
    serializeClientToServer(serialized_message, &message);
    rc = write_synchronized(sd, serialized_message, sizeof(message));
    if(rc != ECODE_SUCCESS){
        checkConnection();
        return false;
    }

    //Initialize stc structs and arrays
    INIT_STC

    //Wait for the response
    rc = read_synchronized(sd, serialized_server_message, sizeof(server_message));
    if(rc != ECODE_SUCCESS){
        checkConnection();
        checkTimeout();
        return false;
    }

    //Deserialize, decrypt and check HMAC
    deserializeServerToClient(serialized_server_message, &server_message);
    rc = deserialcrypt_stc(encrypt_key, mac_key, &server_message, &server_payload);
    if(rc != ECODE_SUCCESS){
        return false;
    }

    //Make sure it's a valid message type
    if(server_payload.tag != supplyNonce){
        return false;
    }

    //Copy nonce
    memcpy(nonce, server_payload.nonce.nonce, NONCE_SIZE);

    return true;
}

/*##############################################################################
Functions For Handling Input
##############################################################################*/

void handleLogin(vector<string> tokens, unsigned short port){
    if(connected){
        cout << "Already logged in as " << user << endl;
        return;
    }

    user = tokens[1];

    //Only allow alphabet characters for the user
    for(unsigned int i = 0; i < user.length(); i++){
        if( (user.c_str()[i] < 65) || (user.c_str()[i] > 122) ||
                (user.c_str()[i] > 90 && user.c_str()[i] < 97) ){
            cout << "User can only be alphabet characters" << endl;
            return;
        }
    }

    //Open the card for the user
    string path = CARD_PATH + user + ".card";
    int fd = open(path.c_str(), O_RDONLY);
    if(fd < 0){
        perror("Failed to open card for that user");
        return;
    }

    //Read the PIN and keys
    char pin[PIN_SIZE];    

    ssize_t bytes_read = read(fd, pin, (size_t) PIN_SIZE);
    if(bytes_read != PIN_SIZE){
        cout << "Could not read full pin from card" << endl;
        return;
    }

    bytes_read = read(fd, encrypt_key, ENCRYPT_KEY_SIZE);
    if(bytes_read != ENCRYPT_KEY_SIZE){
        cout << "Could not read full encryption key from card" << endl;
        return;
    }

    bytes_read = read(fd, mac_key, MAC_KEY_SIZE);
    if(bytes_read != MAC_KEY_SIZE){
        cout << "Could not read full MAC key from card" << endl;
        return;
    }
    close(fd);

    //Prompt for a pin and check
    cout << "Enter PIN: ";
    string userpin;
    getline(cin, userpin);
    if(userpin.length() < PIN_SIZE){
        cout << "Incorrect PIN" << endl;
        return;
    }
    for(int i = 0; i < PIN_SIZE; i++){
        if(pin[i] != userpin[i]){
            cout << "Incorrect PIN" << endl;
            return;
        }
    }
    cout << "PIN accepted. Connecting to bank." << endl;

    //Create socket
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if( sd < 0 ){
        perror("Failed to create socket descriptor");
        return;
    }

    //Connect to proxy
    struct sockaddr_in sock;
    memset(&sock, 0, sizeof sock);
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sock.sin_port = htons(port);

    if( connect(sd, (struct sockaddr*) &sock, sizeof(sock)) < 0 ){
        perror("Failed to connect to proxy");
        close(sd);
        return;
    }

    //Set the socket to have a timeout
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SECONDS;
    tv.tv_usec = TIMEOUT_MICROSECONDS;
    if( setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char*) &tv, sizeof(tv)) != 0 ){
        perror("Failed to set timeout on socket");
        close(sd);
        return;
    }

    cout << "Connected to proxy successfully" << endl;
    connected = true;

    //Zero nonce
    memset(nonce, 0, NONCE_SIZE);
}

void handleBalance(){
    if(!getNonce()){
        cerr << "Failed to get a new nonce" << endl;
        return;
    }

    //Initialize cts structs and arrays
    INIT_CTS

    //Prepare the payload for encryption
    payload.tag = requestBalance;
    memcpy(payload.nonce.nonce, nonce, NONCE_SIZE);

    //Add the sending user
    strcpy(message.src.username, user.c_str());

    //Send the request the request and get the response
    SEND_REQUEST_RECV_RESPONSE

    //Make sure it's a valid message type
    if(server_payload.tag != ackBalance){
        cerr << "Unexpected message response received" << endl;
        return;
    }

    //Check nonce
    if(!checkNonce(nonce, server_payload.nonce.nonce)){
        return;
    }

    //Print balance
    cout << "You have "; output_dollars(cout, server_payload.currency); cout << endl;
    if(server_payload.currency.cents == 0){
        cout << "You're poor." << endl;
    }
    else if(server_payload.currency.cents > (9000 * CENTS_PER_DOLLAR)) {
        cout << "It's over 9000." << endl;
    }
}

void handleWithdraw(vector<string> tokens){
    //Initialize cts structs and arrays
    INIT_CTS

    if(tokens.size() < 2){
        cout << "Too few arguments given" << endl;
        return;
    }
    if(!convertTokenToCents(tokens[1], payload.currency.cents)){
        return;
    }

    if(!getNonce()){
        cerr << "Failed to get a new nonce" << endl;
        return;
    }

    //Prepare the payload for encryption
    payload.tag = requestWithdrawal;
    memcpy(payload.nonce.nonce, nonce, NONCE_SIZE);

    //Add the sending user
    strcpy(message.src.username, user.c_str());

    //Send the request the request and get the response
    SEND_REQUEST_RECV_RESPONSE

    //Make sure it's a valid message type
    if(server_payload.tag != ackWithdrawalSuccess){
        switch(server_payload.tag){
            case insufficientFunds:
                cout << "Insufficient funds" << endl;
                break;
            default:
                cerr << "Unexpected message response received" << endl;
        }
        return;
    }

    //Check nonce
    if(!checkNonce(nonce, server_payload.nonce.nonce)){
        return;
    }

    //Print amount withdrawn
    cout << "You withdrew "; output_dollars(cout, server_payload.currency); cout << endl;
}

void handleTransfer(vector<string> tokens){
    //Initialize cts structs and arrays
    INIT_CTS

    if(tokens.size() < 3){
        cout << "Too few arguments given" << endl;
        return;
    }
    if(!convertTokenToCents(tokens[1], payload.currency.cents)){
        return;
    }
    if(tokens[2].size() >= MAX_USERNAME_SIZE){
        cout << "Destination user is too long" << endl;
        return;
    }

    if(!getNonce()){
        cerr << "Failed to get a new nonce" << endl;
        return;
    }

    //Prepare the payload for encryption
    payload.tag = requestTransfer;
    strcpy(payload.destination.username, tokens[2].c_str());
    memcpy(payload.nonce.nonce, nonce, NONCE_SIZE);

    //Add the sending user
    strcpy(message.src.username, user.c_str());

    //Send the request the request and get the response
    SEND_REQUEST_RECV_RESPONSE

    //Make sure it's a valid message type
    if(server_payload.tag != ackTransferSuccess){
        switch(server_payload.tag){
            case insufficientFunds:
                cout << "Insufficient funds" << endl;
                break;
            case ackTransferInvalidDestination:
                cout << "Destination user was invalid" << endl;
                break;
            case ackTransferWouldOverflow:
                cout << "That much money would cause problems for that person's account" << endl;
                break;
            default:
                cerr << "Unexpected message response received" << endl;
        }
        return;
    }

    //Check nonce
    if(!checkNonce(nonce, server_payload.nonce.nonce)){
        return;
    }

    //Print amount withdrawn
    cout << "You transfered "; output_dollars(cout, server_payload.currency); cout << endl;
}

void handleLogout(){
    if(!connected){
        cout << "Not logged in as anyone" << endl;
        return;
    }

    //Initialize cts structs
    INIT_CTS

    //Prepare the payload for encryption
    payload.tag = requestLogout;

    //Add the sending user
    strcpy(message.src.username, user.c_str());

    //Encrypt and package payload
    ENC_PACK_CTS
    
    //Serialize and send the logout request
    SER_SEND_CTS

    //Don't wait for a response
    closeConnection();
    cout << "Logged out" << endl;
}

int main(int argc, char* argv[]){
    if(argc != 2){
        cout << "Usage is <port to connect to>" << endl;
        return 1;
    }

    //Handle reads/writes to closed sockets killing program
    signal(SIGPIPE, SIG_IGN);

    //Get the port
    unsigned short port = (unsigned short) atoi(argv[1]);

    //Menu loop
    vector<string> tokens;
    while(true){
        printMenu();
        prompt:
        print_prompt();
        tokens = get_tokenized_line();
        if(tokens.size() == 0){
            goto prompt;
        }
        //Switch/Case doesn't work properly with strings
        if(tokens[0] == "login"){
            handleLogin(tokens, port);
        }
        else if(tokens[0] == "balance"){
            handleBalance();
        }
        else if(tokens[0] == "withdraw"){
            handleWithdraw(tokens);
        }
        else if(tokens[0] == "transfer"){
            handleTransfer(tokens);
        }
        else if(tokens[0] == "logout"){
            handleLogout();
        }
        else{
            cout << "Unknown command '" << tokens[0] << "'" << endl;
        }
    }
    
}
