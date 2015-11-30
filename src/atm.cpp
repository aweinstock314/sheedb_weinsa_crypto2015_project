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

void serializeClientToServer(char* buf, struct client_to_server message){
    memcpy(buf, &message, sizeof(message));
}

void serializeCtsPayload(unsigned char* buf, struct cts_payload payload){
    memcpy(buf, &payload, sizeof(payload));
}

//Gets a new nonce for communication
bool getNonce(){
    struct client_to_server message;
    memset(&message, 0, sizeof(message));
    struct cts_payload payload;

    //Prepare the payload for encryption
    memset(&payload, 0, sizeof(payload));
    payload.tag = requestNonce;
    unsigned char plaintext[sizeof(struct cts_payload) + (sizeof(struct cts_payload) % 16)];
    memset(plaintext, 0, sizeof(plaintext));
    serializeCtsPayload(plaintext, payload);    
    
    //Encrypt the payload
    int rc = encrypt( plaintext, sizeof(plaintext),
        encrypt_key, message.payload.payload );
    if(rc == -1){
        return false;    
    }
    
    //Add the sending user
    strcpy(message.src.username, user.c_str());
    
    //Generate the HMAC
    rc = genHMAC(message.payload.payload, sizeof(message.payload.payload),
        mac_key, message.hmac.hmac);
    if(rc == -1){
        return false;
    }

    //TODO: Send message and wait for reply

    //Test code
    /*unsigned char hmac[EVP_MAX_MD_SIZE];
    rc = genHMAC(message.payload.payload, sizeof(message.payload.payload), mac_key, hmac);
    cout << rc << endl;
    for(int i = 0; i < rc; i++){
        cout << hex << (int)hmac[i];
    }
    cout << endl;*/
    /*memset(&plaintext, 0, sizeof(plaintext));
    
    rc = decrypt(message.payload.payload, sizeof(message.payload.payload), encrypt_key, plaintext);
    cout << rc << endl;
    struct cts_payload test;
    memcpy(&test, plaintext, sizeof(test));
    cout << test.tag << " " << test.destination.username << endl;*/

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
    cout << "BALANCE" << endl;
}

void handleWithdraw(vector<string> tokens){
    cout << "Withdraw" << endl;
}

void handleTransfer(vector<string> tokens){
    cout << "Transfer" << endl;
}

void handleLogout(){
    if(!connected){
        cout << "Not logged in as anyone" << endl;
        return;
    }
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
