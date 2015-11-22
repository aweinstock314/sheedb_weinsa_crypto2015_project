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

#include "constants.h"

#define CARD_PATH "../cards/"

using namespace std;

int sd;
bool connected = false;
string user;

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

vector<string> getTokens(string s){
    char base[s.size() + 1];
    strcpy(base, s.c_str());
    vector<string> tokens;
    char* token = strtok(base, " ");
    while(token != NULL){
        tokens.push_back(string(token));
        token = strtok(NULL, " ");
    }
    return tokens;
}

vector<string> getInput(){
    string input;
    printMenu();
    getline(cin, input);
    return getTokens(input);
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
    char encrypt_key[ENCRYPT_KEY_SIZE];
    char mac_key[MAC_KEY_SIZE];

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
        tokens = getInput();
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