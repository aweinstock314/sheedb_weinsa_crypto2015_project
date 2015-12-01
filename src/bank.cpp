#include <iostream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <thread>
#include <unistd.h>

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

void handle_connection(int fd) {
    cout << "handle_connection(" << fd << ")" << endl;
    write_aon(fd, "some data", 10);
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

void print_prompt() {
    cout << "> ";
    cout.flush();
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
