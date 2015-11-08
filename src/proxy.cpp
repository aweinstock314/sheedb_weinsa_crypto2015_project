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

#include "constants.h"

using namespace std;

//Evil global variables because it's simplest to do it this way
int send_port;
int listener_socket;

//Load tested via for i in $(seq 1 10000); do (nc localhost 8080 &) ; done
void handle_control_c(int s){
    close(listener_socket);
    exit(0);
}

void handleConnection(int sd){
    cout << "Connection handled on sd " << sd << endl;
    close(sd);
}

int main(int argc, char* argv[]){
    if(argc != 3){
        cout << "Proxy takes arguments <listen port> <send port>" << endl;
        return EXIT_FAILURE;
    }

    //Get ports
    int listen_port = (unsigned short) atoi(argv[1]);
    send_port = (unsigned short) atoi(argv[2]);
    if( listen_port > 65535 || send_port > 65535 ){
        cout << "Port larger than supported value" << endl;
        return EXIT_FAILURE;
    }

    //Create listener socket
    listener_socket = socket( PF_INET, SOCK_STREAM, 0 );
    if ( listener_socket < 0 ){
        cerr << "Socket creation failed" << endl;
        return EXIT_FAILURE;
    }
    signal(SIGINT, &handle_control_c);

    //Bind socket
    struct sockaddr_in server;
    server.sin_family = PF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(listen_port);
    int len = sizeof(server);
    if ( bind( listener_socket, (struct sockaddr *)&server, len ) < 0 ){
        cerr << "Bind failed" << endl;
        return EXIT_FAILURE;
    }

    //Start listening
    listen(listener_socket, MAX_CLIENTS);

    struct sockaddr_in client;
    int fromlen = sizeof(client);

    while(true){
        int client_sock = accept(listener_socket, (struct sockaddr *) &client, (socklen_t*) &fromlen);
        if(client_sock < 0){
            cerr << "Failed to accept connection" << endl;
            continue;
        }
        
        thread client_thread(handleConnection, client_sock);
        client_thread.detach();
    }
}