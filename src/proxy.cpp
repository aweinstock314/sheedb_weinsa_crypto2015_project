/*
Proxy for the crypto project. Simply creates a new thread for each incoming connection and forwards its data
Derived from code at http://www.cs.rpi.edu/~goldsd/docs/spring2015-csci4210/server.c.txt
*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "constants.h"
#include "ctrlc_handler.h"

#define MAX_EVENTS 2
#define NUM_BYTES_FORWARD 1024

using namespace std;

//Evil global variables because it's simplest to do it this way
unsigned short send_port;

//Forwards data from one socket to the other
int forwardData(int in_sd, int out_sd){
    ssize_t num_bytes_read, num_bytes_sent;
    char buffer[NUM_BYTES_FORWARD];

    num_bytes_read = recv(in_sd, buffer, (size_t)NUM_BYTES_FORWARD, 0);
    if(num_bytes_read == 0){
        return 0;
    }
    else if(num_bytes_read < 0){
        return -1;
    }

    num_bytes_sent = send(out_sd, buffer, (size_t) num_bytes_read, 0);
    if(num_bytes_sent != num_bytes_read){
        return -1;
    }

    return num_bytes_sent;
}

//Handle an incoming connection from an ATM
//Load tested via "for i in $(seq 1 10000); do (nc localhost 8080 &) ; done"
void handleConnection(int atm_sd){
    cout  << "Start" << endl;
    //Create a socket for the connection to the bank
    int bank_sd = socket(AF_INET, SOCK_STREAM, 0);
    if(bank_sd < 0){
        cerr << "Failed to create socket for connection to bank" << endl;
        close(atm_sd);
        return;
    }

    cout << "Server socket created" << endl;

    struct sockaddr_in server;
    memset(&server, 0, sizeof server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port = htons(send_port);

    //Connect to the bank
    if( connect(bank_sd, (struct sockaddr*) &server, sizeof(server)) < 0 ){
        perror("Failed to connect to bank");
        close(atm_sd);
        close(bank_sd);
        return;
    }

    cout << "Connected to bank" << endl;

    //Create epoll
    int epoll_fd = epoll_create1(0);
    if(epoll_fd < 0){
        cerr << "epoll creation failed" << endl;
        close(atm_sd);
        close(bank_sd);
        return;
    }

    cout << "Epoll created" << endl;

    //Setup epoll
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = atm_sd;
    if( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, atm_sd, &ev) < 0 ){
        cerr << "Failed to setup epoll for atm" << endl;
        close(atm_sd);
        close(bank_sd);
        close(epoll_fd);
        return;
    }
    ev.data.fd = bank_sd;
    if( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bank_sd, &ev) < 0 ){
        cerr << "Failed to setup epoll for bank" << endl;
        close(atm_sd);
        close(bank_sd);
        close(epoll_fd);
        return;
    }

    //Listen for any data and forward it
    int num_fds, rc;
    while(true){
        num_fds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for(int i = 0; i < num_fds; i++){
            if(events[i].data.fd == atm_sd){
                cout << "Received data from client" << endl;
                rc = forwardData(atm_sd, bank_sd);
            }
            else{
                cout << "Received data from server" << endl;
                rc = forwardData(bank_sd, atm_sd);
            }
            if(rc == -1){
                cerr << "Error forwarding data" << endl;
                close(atm_sd);
                close(bank_sd);
                close(epoll_fd);
                return;
            }
            else if(rc == 0){
                cerr << "Connection closed" << endl;
                close(atm_sd);
                close(bank_sd);
                close(epoll_fd);
                return;
            }
        }
    }

    close(atm_sd);
    close(bank_sd);
    close(epoll_fd);
}

//Listens for connections on the specified port and creates a thread to handle each one
int main(int argc, char* argv[]){
    if(argc != 3){
        cout << "Proxy takes arguments <port to listen for atms> <port to connect to bank>" << endl;
        return EXIT_FAILURE;
    }
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, &handle_control_c);

    //Get ports
    unsigned short listen_port = (unsigned short) atoi(argv[1]);
    send_port = (unsigned short) atoi(argv[2]);

    //Create listener socket
    int listener_socket = socket( AF_INET, SOCK_STREAM, 0 );
    if ( listener_socket < 0 ){
        cerr << "Socket creation failed" << endl;
        return EXIT_FAILURE;
    }
    //Close socket on ^C
    CtrlCHandler::add_handler(std::function<void()>([=]() {
        cout << "Closing fd " << listener_socket << endl;
        close(listener_socket);
    }));

    //Bind socket
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(listen_port);
    int len = sizeof(server);
    if ( bind( listener_socket, (struct sockaddr *) &server, len ) < 0 ){
        cerr << "Bind failed" << endl;
        return EXIT_FAILURE;
    }

    //Start listening
    listen(listener_socket, MAX_CLIENTS);

    struct sockaddr_in client;
    int fromlen = sizeof(client);

    while(true){
        int atm_sd = accept(listener_socket, (struct sockaddr *) &client, (socklen_t*) &fromlen);
        if(atm_sd < 0){
            cerr << "Failed to accept connection" << endl;
            continue;
        }
        
        thread client_thread(handleConnection, atm_sd);
        client_thread.detach();
    }
}
