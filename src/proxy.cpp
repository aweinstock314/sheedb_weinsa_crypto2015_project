/*
Proxy for the crypto project. Simply creates a new thread for each incoming connection and forwards its data
Derived from code at http://www.cs.rpi.edu/~goldsd/docs/spring2015-csci4210/server.c.txt
*/

#include <sys/socket.h>
#include <iostream>
#include <thread>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/epoll.h>

#include "constants.h"

#define MAX_EVENTS 2
#define NUM_BYTES_FORWARD 1024

using namespace std;

//Evil global variables because it's simplest to do it this way
unsigned short send_port;
int listener_socket;

//Close socket on ^C
void handle_control_c(int s){
    close(listener_socket);
    exit(EXIT_SUCCESS);
}

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
void handleConnection(int client_sd){
    cout  << "Start" << endl;
    //Create a socket for the connection to the bank
    int server_sd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_sd < 0){
        cerr << "Failed to create socket for connection to bank" << endl;
        close(client_sd);
        return;
    }

    cout << "Server socket created" << endl;

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port = htons(send_port);

    //Connect to the bank
    if( connect(server_sd, (struct sockaddr*) &server, sizeof(server)) < 0 ){
        cerr << "Failed to connect to bank" << endl;
        perror("Reason:");
        close(client_sd);
        close(server_sd);
        return;
    }

    cout << "Connected to bank" << endl;

    //Create epoll
    int epoll_fd = epoll_create1(0);
    if(epoll_fd < 0){
        cerr << "epoll creation failed" << endl;
        close(client_sd);
        close(server_sd);
        return;
    }

    cout << "Epoll created" << endl;

    //Setup epoll
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = client_sd;
    if( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_sd, &ev) < 0 ){
        cerr << "Failed to setup epoll for atm" << endl;
        close(client_sd);
        close(server_sd);
        close(epoll_fd);
        return;
    }
    ev.data.fd = server_sd;
    if( epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_sd, &ev) < 0 ){
        cerr << "Failed to setup epoll for bank" << endl;
        close(client_sd);
        close(server_sd);
        close(epoll_fd);
        return;
    }

    //Listen for any data and forward it
    int num_fds, rc;
    while(true){
        num_fds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for(int i = 0; i < num_fds; i++){
            if(events[i].data.fd == client_sd){
                cout << "Received data from client" << endl;
                rc = forwardData(client_sd, server_sd);
            }
            else{
                cout << "Received data from server" << endl;
                rc = forwardData(server_sd, client_sd);
            }
            if(rc == -1){
                cerr << "Error forwarding data" << endl;
                close(client_sd);
                close(server_sd);
                close(epoll_fd);
                return;
            }
            else if(rc == 0){
                cerr << "Connection closed" << endl;
                close(client_sd);
                close(server_sd);
                close(epoll_fd);
                return;
            }
        }
    }

    close(client_sd);
    close(server_sd);
    close(epoll_fd);
}

//Listens for connections on the specified port and creates a thread to handle each one
int main(int argc, char* argv[]){
    if(argc != 3){
        cout << "Proxy takes arguments <listen port> <send port>" << endl;
        return EXIT_FAILURE;
    }

    //Get ports
    unsigned short listen_port = (unsigned short) atoi(argv[1]);
    send_port = (unsigned short) atoi(argv[2]);
    if( listen_port > 65535 || send_port > 65535 ){
        cout << "Port larger than supported value" << endl;
        return EXIT_FAILURE;
    }

    //Create listener socket
    listener_socket = socket( AF_INET, SOCK_STREAM, 0 );
    if ( listener_socket < 0 ){
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
    if ( bind( listener_socket, (struct sockaddr *) &server, len ) < 0 ){
        cerr << "Bind failed" << endl;
        return EXIT_FAILURE;
    }

    //Start listening
    listen(listener_socket, MAX_CLIENTS);

    struct sockaddr_in client;
    int fromlen = sizeof(client);

    while(true){
        int client_sd = accept(listener_socket, (struct sockaddr *) &client, (socklen_t*) &fromlen);
        if(client_sd < 0){
            cerr << "Failed to accept connection" << endl;
            continue;
        }
        
        thread client_thread(handleConnection, client_sd);
        client_thread.detach();
    }
}