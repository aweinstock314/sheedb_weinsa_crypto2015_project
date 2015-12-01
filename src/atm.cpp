/*
ATM program for the crypto project
*/

#include <sys/socket.h>
#include <iostream>
//#include <thread>
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

#include "constants.h"
#include "utils.h"
#include "datatypes.h"

#define CARD_PATH "../cards/"
#define TIMEOUT 5

using namespace std;

//Global variables
int sd; //Socket descriptor
bool connected = false;
string user;
uint8_t nonce[NONCE_SIZE];
unsigned char encrypt_key[ENCRYPT_KEY_SIZE];
unsigned char mac_key[MAC_KEY_SIZE];

/*##############################################################################
Menu Functions
##############################################################################*/

void printMenu(){
    cout << endl;
    cout << "Please enter your desired command" << endl;
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

bool convertTokenToCents(string token, uint64_t &value){
    vector<string> parts = tokenize(token, ".");
    if(parts.size() != 2){
        cout << "Invalid currency input" << endl;
        return false;
    }

    //If the user wants to withdraw > 2^32 dollars, they can deal with the
    //weird things that happen because no one will be withdrawing that
    //much money from the ATM. ATMS don't even carry that much money.
    unsigned long dollars = strtoul(parts[0].c_str(), NULL, 10);
    unsigned long cents = strtoul(parts[1].c_str(), NULL, 10);
    value = (uint64_t)(dollars * 100) + (uint64_t)cents;
    return true;
}

void serializeClientToServer(char* buf, const struct client_to_server* message){
    memcpy(buf, message, sizeof(*message));
}

void deserializeServerToClient(const char* buf, struct server_to_client* message){
    memcpy(message, buf, sizeof(*message));
}

//Gets a new nonce for communication
bool getNonce(){
    struct client_to_server message;
    memset(&message, 0, sizeof(message));
    struct cts_payload payload;

    //Prepare the payload for encryption
    memset(&payload, 0, sizeof(payload));
    payload.tag = requestNonce;

    //Add the sending user
    strcpy(message.src.username, user.c_str());

    //Encrypt and package payload
    int rc = enserialcrypt_cts(encrypt_key, mac_key, &payload, &message);
    if(rc != ECODE_SUCCESS){
        return false;
    }
    
    //Send the nonce request
    char serialized_message[sizeof(message)];
    serializeClientToServer(serialized_message, &message);
    rc = write_aon(sd, serialized_message, sizeof(message));
    if(rc != ECODE_SUCCESS){
        return false;
    }

    //Wait for the response
    struct server_to_client server_message;
    char serialized_server_message[sizeof(server_message)];
    rc = read_aon(sd, serialized_server_message, sizeof(server_message));
    if(rc != ECODE_SUCCESS){
        return false;
    }

    //Deserialize, decrypt and check HMAC
    struct stc_payload server_payload;
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

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if( sd < 0 ){
        perror("Failed to create socket descriptor");
        return;
    }

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

    cout << "Connected to proxy successfully" << endl;
    connected = true;

    //Zero nonce
    memset(nonce, 0, NONCE_SIZE);

    getNonce();
}

void handleBalance(){
    if(!getNonce()){
        cerr << "Failed to get a new nonce" << endl;
        return;
    }

    struct client_to_server message;
    memset(&message, 0, sizeof(message));
    struct cts_payload payload;

    //Prepare the payload for encryption
    memset(&payload, 0, sizeof(payload));
    payload.tag = requestBalance;
    memcpy(payload.nonce.nonce, nonce, NONCE_SIZE);

    //Add the sending user
    strcpy(message.src.username, user.c_str());

    //Encrypt and package payload
    int rc = enserialcrypt_cts(encrypt_key, mac_key, &payload, &message);
    if(rc != ECODE_SUCCESS){
        cerr << "Encryption failed" << endl;
        return;
    }
    
    //Send the nonce request
    char serialized_message[sizeof(message)];
    serializeClientToServer(serialized_message, &message);
    rc = write_aon(sd, serialized_message, sizeof(message));
    if(rc != ECODE_SUCCESS){
        cerr << "Failed to send balance request" << endl;
        return;
    }

    //Wait for the response
    struct server_to_client server_message;
    char serialized_server_message[sizeof(server_message)];
    rc = read_aon(sd, serialized_server_message, sizeof(server_message));
    if(rc != ECODE_SUCCESS){
        cerr << "Failed to receive valid response" << endl;
        return;
    }

    //Deserialize, decrypt and check HMAC
    struct stc_payload server_payload;
    deserializeServerToClient(serialized_server_message, &server_message);
    rc = deserialcrypt_stc(encrypt_key, mac_key, &server_message, &server_payload);
    if(rc != ECODE_SUCCESS){
        cerr << "Mismatched HMAC" << endl;
        return;
    }

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
    uint64_t dollars = (uint64_t)floor(server_payload.currency.cents / 100);
    unsigned int cents = (unsigned int)(server_payload.currency.cents % 100);
    cout << "You have $" << dollars << ".";
    cout << setfill('0') << setw(2) << cents << resetiosflags(ios::showbase) << endl;
    if(server_payload.currency.cents == 0){
        cout << "You're poor." << endl;
    }
    else if(server_payload.currency.cents > 900000){
        cout << "It's over 9000." << endl;
    }
}

void handleWithdraw(vector<string> tokens){
    struct cts_payload payload;
    memset(&payload, 0, sizeof(payload));

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

    struct client_to_server message;
    memset(&message, 0, sizeof(message));

    //Prepare the payload for encryption
    payload.tag = requestWithdrawl;
    memcpy(payload.nonce.nonce, nonce, NONCE_SIZE);

    //Add the sending user
    strcpy(message.src.username, user.c_str());

    //Encrypt and package payload
    int rc = enserialcrypt_cts(encrypt_key, mac_key, &payload, &message);
    if(rc != ECODE_SUCCESS){
        cerr << "Encryption failed" << endl;
        return;
    }
    
    //Send the nonce request
    char serialized_message[sizeof(message)];
    serializeClientToServer(serialized_message, &message);
    rc = write_aon(sd, serialized_message, sizeof(message));
    if(rc != ECODE_SUCCESS){
        cerr << "Failed to send withdrawl request" << endl;
        return;
    }

    //Wait for the response
    struct server_to_client server_message;
    char serialized_server_message[sizeof(server_message)];
    rc = read_aon(sd, serialized_server_message, sizeof(server_message));
    if(rc != ECODE_SUCCESS){
        cerr << "Failed to receive valid response" << endl;
        return;
    }

    //Deserialize, decrypt and check HMAC
    struct stc_payload server_payload;
    deserializeServerToClient(serialized_server_message, &server_message);
    rc = deserialcrypt_stc(encrypt_key, mac_key, &server_message, &server_payload);
    if(rc != ECODE_SUCCESS){
        cerr << "Mismatched HMAC" << endl;
        return;
    }

    //Make sure it's a valid message type
    if(server_payload.tag != ackWithdrawlSuccess){
        if(server_payload.tag == insufficentFunds){
            cout << "Insufficient funds" << endl;
        }
        else{
            cerr << "Unexpected message response received" << endl;
        }
        return;
    }

    //Check nonce
    if(!checkNonce(nonce, server_payload.nonce.nonce)){
        return;
    }

    //Print amount withdrawn
    uint64_t dollars = (uint64_t)floor(server_payload.currency.cents / 100);
    unsigned int cents = (unsigned int)(server_payload.currency.cents % 100);
    cout << "You withdrew $" << dollars << ".";
    cout << setfill('0') << setw(2) << cents << resetiosflags(ios::showbase) << endl;
}

void handleTransfer(vector<string> tokens){
    struct cts_payload payload;
    memset(&payload, 0, sizeof(payload));

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

    struct client_to_server message;
    memset(&message, 0, sizeof(message));

    //Prepare the payload for encryption
    payload.tag = requestTransfer;
    strcpy(payload.destination.username, tokens[2].c_str());
    memcpy(payload.nonce.nonce, nonce, NONCE_SIZE);

    //Add the sending user
    strcpy(message.src.username, user.c_str());

    //Encrypt and package payload
    int rc = enserialcrypt_cts(encrypt_key, mac_key, &payload, &message);
    if(rc != ECODE_SUCCESS){
        cerr << "Encryption failed" << endl;
        return;
    }
    
    //Send the nonce request
    char serialized_message[sizeof(message)];
    serializeClientToServer(serialized_message, &message);
    rc = write_aon(sd, serialized_message, sizeof(message));
    if(rc != ECODE_SUCCESS){
        cerr << "Failed to send transfer request" << endl;
        return;
    }

    //Wait for the response
    struct server_to_client server_message;
    char serialized_server_message[sizeof(server_message)];
    rc = read_aon(sd, serialized_server_message, sizeof(server_message));
    if(rc != ECODE_SUCCESS){
        cerr << "Failed to receive valid response" << endl;
        return;
    }

    //Deserialize, decrypt and check HMAC
    struct stc_payload server_payload;
    deserializeServerToClient(serialized_server_message, &server_message);
    rc = deserialcrypt_stc(encrypt_key, mac_key, &server_message, &server_payload);
    if(rc != ECODE_SUCCESS){
        cerr << "Mismatched HMAC" << endl;
        return;
    }

    //Make sure it's a valid message type
    if(server_payload.tag != ackTransferSuccess){
        if(server_payload.tag == insufficentFunds){
            cout << "Insufficient funds" << endl;
        }
        else if(server_payload.tag == ackTransferInvalidDestination){
            cout << "Destination user was invalid" << endl;
        }
        else{
            cerr << "Unexpected message response received" << endl;
        }
        return;
    }

    //Check nonce
    if(!checkNonce(nonce, server_payload.nonce.nonce)){
        return;
    }

    //Print amount withdrawn
    uint64_t dollars = (uint64_t)floor(server_payload.currency.cents / 100);
    unsigned int cents = (unsigned int)(server_payload.currency.cents % 100);
    cout << "You transfered $" << dollars << ".";
    cout << setfill('0') << setw(2) << cents << resetiosflags(ios::showbase) << " to " << tokens[2] << endl;
}

void handleLogout(){
    if(!connected){
        cout << "Not logged in as anyone" << endl;
        return;
    }

    struct client_to_server message;
    memset(&message, 0, sizeof(message));
    struct cts_payload payload;

    //Prepare the payload for encryption
    memset(&payload, 0, sizeof(payload));
    payload.tag = requestLogout;

    //Add the sending user
    strcpy(message.src.username, user.c_str());

    //Encrypt and package payload
    int rc = enserialcrypt_cts(encrypt_key, mac_key, &payload, &message);
    if(rc != ECODE_SUCCESS){
        cerr << "Encryption failed" << endl;
        return;
    }
    
    //Send the nonce request
    char serialized_message[sizeof(message)];
    serializeClientToServer(serialized_message, &message);
    rc = write_aon(sd, serialized_message, sizeof(message));
    if(rc != ECODE_SUCCESS){
        cerr << "Failed to send logout request" << endl;
        return;
    }

    //Don't wait for a response
    connected = false;
    user = "";
    close(sd);
}

int main(int argc, char* argv[]){
    if(argc != 2){
        cout << "Usage is <port to connect to>" << endl;
        return 1;
    }

    //Get the port
    unsigned short port = (unsigned short) atoi(argv[1]);

    //Menu loop
    vector<string> tokens;
    while(true){
        printMenu();
        tokens = get_tokenized_line();
        if(tokens.size() == 0){
            continue;
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
