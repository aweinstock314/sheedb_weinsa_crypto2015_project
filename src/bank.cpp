#include <iostream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <thread>
#include <unistd.h>
#include <string.h>

#include "metacard.h"
#include "utils.h"

using namespace std;

// GLOBAL VARIABLES
int listener_socket;
map<string, uint64_t> balances;
mutex balance_guard;

//Close socket on ^C
void handle_control_c(int s) {
    (void)s; // silence -Wunused-parameter
    close(listener_socket);
    exit(EXIT_SUCCESS);
}

const unsigned char* get_cryptkey(const char* name) {
    if(!strcmp(name, "Alice")) { return Alice_cryptkey; }
    if(!strcmp(name, "Bob")) { return Bob_cryptkey; }
    if(!strcmp(name, "Eve")) { return Eve_cryptkey; }
    return 0;
}

const unsigned char* get_signkey(const char* name) {
    if(!strcmp(name, "Alice")) { return Alice_signkey; }
    if(!strcmp(name, "Bob")) { return Bob_signkey; }
    if(!strcmp(name, "Eve")) { return Eve_signkey; }
    return 0;
}

void handle_nonce(nonce_t* nonce, stc_payload* dst) {
}
void handle_balance(const char* username, const cts_payload* src, stc_payload* dst) {
}
void handle_withdrawl(const char* username, const cts_payload* src, stc_payload* dst) {
}
void handle_transfer(const char* username, const cts_payload* src, stc_payload* dst) {
    const char* other = src->destination.username;
    uint64_t amount = src->currency.cents;
    if(!get_cryptkey(other)) {
        dst->tag = ackTransferInvalidDestination;
        return;
    }
    lock_guard<mutex> lock(balance_guard);
    if(balances[username] < amount) {
        dst->tag = insufficientFunds;
        return;
    }
    if(balances[other] + amount < balances[other]) {
        // Avoid the case where:
        // 1) A bank admin uses the shell to (legitimately) deposit 2**64-1 cents to Eve
        // 2) Alice transfers 2 cents to Eve
        // 3) Eve now has only 1 cent
        dst->tag = ackTransferWouldOverflow;
        return;
    }
    balances[other] += amount;
    balances[username] -= amount;
}

void handle_connection(int fd) {
    //cout << "handle_connection(" << fd << ")" << endl;
    cts_payload in_payload;
    client_to_server incoming;
    stc_payload out_payload;
    server_to_client outgoing;
    nonce_t nonce;
    const unsigned char *cryptkey, *signkey;
    do {
        if(read_synchronized(fd, (char*)&incoming, sizeof incoming)) { break; }
        memset(&out_payload, 0, sizeof out_payload);
        if(!(cryptkey = get_cryptkey(incoming.src.username)) ||
            !(signkey = get_signkey(incoming.src.username))) {
            //out_payload.tag = invalidUser;
            goto skip_reply; // if we don't have keys for the user, we can't sign a response at them.
        }
        if(deserialcrypt_cts(cryptkey, signkey, &incoming, &in_payload)) {
            out_payload.tag = invalidNonce; // technically invalid HMAC, but why leak info?
            goto reply;
        }
        //cout << endl; hexdump(1, &in_payload, sizeof in_payload); cout << endl;
        if((in_payload.tag != requestNonce) && (in_payload.tag != requestLogout) &&
            CRYPTO_memcmp(nonce.nonce, in_payload.nonce.nonce, sizeof nonce)) {
            out_payload.tag = invalidNonce;
            goto reply;
        } else {
            memcpy(out_payload.nonce.nonce, nonce.nonce, sizeof nonce);
        }
        switch(in_payload.tag) {
            case requestNonce: handle_nonce(&nonce, &out_payload); break;
            case requestBalance: handle_balance(incoming.src.username, &in_payload, &out_payload); break;
            case requestWithdrawl: handle_withdrawl(incoming.src.username, &in_payload, &out_payload); break;
            case requestTransfer: handle_transfer(incoming.src.username, &in_payload, &out_payload); break;
            case requestLogout: goto skip_reply; break;
        }
        if(in_payload.tag != requestNonce) {
            memset(&nonce, 0, sizeof nonce);
        }
        reply:
        if(enserialcrypt_stc(cryptkey, signkey, &out_payload, &outgoing)) { break; }
        if(write_synchronized(fd, (char*)&outgoing, sizeof outgoing)) { break; }
        skip_reply:
        (void)0;
    } while(in_payload.tag != requestLogout);
    close(fd);
}

int bindloop(unsigned short listen_port) {
    //Create listener socket
    listener_socket = socket( AF_INET, SOCK_STREAM, 0 );
    if ( listener_socket < 0 ) {
        cerr << "Socket creation failed" << endl;
        return EXIT_FAILURE;
    }
    signal(SIGINT, &handle_control_c);

    //Bind socket
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(listen_port);
    int len = sizeof(server);
    if ( bind( listener_socket, (struct sockaddr *) &server, len ) < 0 ) {
        cerr << "Bind failed" << endl;
        return EXIT_FAILURE;
    }
    //Start listening
    listen(listener_socket, MAX_CLIENTS);

    struct sockaddr_in client;
    int fromlen = sizeof(client);

    while(true) {
        int atm_sd = accept(listener_socket, (struct sockaddr *) &client, (socklen_t*) &fromlen);
        if(atm_sd < 0) {
            cerr << "Failed to accept connection" << endl;
            continue;
        }

        thread client_thread(handle_connection, atm_sd);
        client_thread.detach();
    }
}

void print_bankshell_menu() {
    cout << endl;
    cout << "Please enter your desired command" << endl;
    cout << "deposit [username] [amount]" << endl;
    cout << "balance [username]" << endl;
    cout << endl;
}

void handle_deposit(vector<string> tokens) {
    if(tokens.size() != 3) {
        cout << "Expected 2 parameters to 'deposit'." << endl;
        return;
    }
    string username = tokens[1];
    uint64_t amount = strtol(tokens[2].c_str(), NULL, 10);
    lock_guard<mutex> lock(balance_guard);
    balances[username] += amount; // No overflow checking since shell is trusted
}

void handle_balance(vector<string> tokens) {
    if(tokens.size() != 2) {
        cout << "Expected 1 parameter to 'balance'." << endl;
        return;
    }
    string username = tokens[1];
    lock_guard<mutex> lock(balance_guard);
    cout << "Balance for user '" << username << "': " << balances[username] << " cents" << endl;
}

void bankshell() {
    vector<string> tokens;
    while(true){
        print_bankshell_menu();
        prompt:
        print_prompt();
        tokens = get_tokenized_line();
        if(tokens.size() == 0){
            goto prompt;
        }
        if(tokens[0] == "deposit") {
            handle_deposit(tokens);
        }
        else if(tokens[0] == "balance") {
            handle_balance(tokens);
        }
        else if(tokens[0] == "easteregg") {
            cout << "Merry nondenominational seasonal holiday!" << endl;
        }
        else{
            cout << "Unknown command '" << tokens[0] << "'" << endl;
        }
    }
}

int main(int argc, char** argv) {
    // Display a usage message
    if(argc != 2) {
        cout << "Usage: " << argv[0] << " LISTEN_PORT" << endl;
        return EXIT_FAILURE;
    }

    // Get ports
    unsigned short listen_port = (unsigned short) atoi(argv[1]);

    // Assign default balances
    // (doesn't need a mutex since this is before threads are started)
    balances["Alice"] = 100 * CENTS_PER_DOLLAR;
    balances["Bob"] = 50 * CENTS_PER_DOLLAR;
    balances["Eve"] = 0 * CENTS_PER_DOLLAR;

    thread shell = thread(bankshell);
    shell.detach();

    return bindloop(listen_port);
}
