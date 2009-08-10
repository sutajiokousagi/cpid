/*
  Cryptoprocessor code. Compliant to spec version 1.3.

  This code is released under a BSD license.

  bunnie@chumby.com 04/07, updated 5/07. All mistakes are mine.
  with contributions from and corrections by Nate Lawson
  with corrections by Eugene Tsyrklevich
*/

#include "commonCrypto.h"
#include <time.h>
#include <termio.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <signal.h>


// these variables comes from crypto.c
extern unsigned int powerTimer;
extern unsigned char powerState;
static int io_initialized = 0;
static int socket_file    = 0;
static int current_socket = 0;

static int CP_initialize_io(const char *socket_name) {
    int temp_socket;
    static struct sockaddr_un sa;
    int size = 1;

    // Create the fifo node, making sure it doesn't exist.
    unlink(socket_name);

    // Specify AF_UNIX, rather than AF_INET, because we'll be listening
    // locally.
    sa.sun_family = AF_UNIX;
        
        
    // Copy the socket's name to the address object.
    strncpy(sa.sun_path, socket_name, sizeof(sa)-sizeof(short));
        
            
    // Create the socket that we'll use to send data through.
    if((temp_socket = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        return -1;
    }       
                
                
    // Adjust the size of the socket to be just big enough to hold one
    // struct.      
    size = 1;
    if((setsockopt(temp_socket, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)))<0)
        return -1;  

    // Adjust the size of the socket to be just big enough to hold one
    // struct.      
    size = 1;
    if((setsockopt(temp_socket, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)))<0)
        return -1;  
                    

    // Bind the server socket to its name, so we can listen for connections.
    if((bind(temp_socket, (struct sockaddr *)&sa, sizeof(struct sockaddr_un))) < 0)
        return -1;


    // Begin listening for incoming connections.  This doesn't accept
    // connections, and returns immediately.
    if((listen(temp_socket, 0)) < 0)
        return -1;


    io_initialized = 1;

    // We might want to do more manipulation of temp_file here, for example
    // to manipulate the buffer.  Or not.
    socket_file = temp_socket;

    return socket_file;
}

static void CP_accept_new_connection() {
    int new_socket;
    int size;
    static struct sockaddr_un sa;
    unsigned int socket_size = sizeof(sa);

    if(!socket_file)
        CP_initialize_io(DEFAULT_IO_PIPE);

    if((new_socket = accept(socket_file, (struct sockaddr *) &sa, &socket_size)) < 0) {
        if(errno == EINTR)
            CP_accept_new_connection();
        perror("Unable to accept connection");
        exit(1);
    }

    // Adjust the size of the socket to be just big enough to hold one
    // struct.      
    size = 1;
    if((setsockopt(new_socket, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)))<0) {
        perror("Unable to set up socket send size");
        return;
    }

    // Adjust the size of the socket to be just big enough to hold one
    // struct.      
    size = 1;
    if((setsockopt(new_socket, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)))<0) {
        perror("Unable to set up socket receive size");
        return;
    }


    if(current_socket)
        close(current_socket);
    current_socket = new_socket;

    return;
}


unsigned char CPgetc() {
    char c;
    if(!current_socket)
        CP_accept_new_connection();

    //read 1 char @ a time from stdin
    if(1!=read(current_socket,&c,1)) {
        // Not being able to read probably indicates the other side of the
        // connection has closed.  Attempt to make a new connection.
//        perror("Unable to read"); 
        CP_accept_new_connection();
        if(1!=read(current_socket,&c,1)) {
            perror("Unable to read character, so dropped");
            return c;
        }
    }

    // Write the character back.  This has the side-effect of flushing the
    // buffer.
//    write(current_socket, &c, 1);


    return c;
}

int CPputs( char *str ) {
  int i = 0;
  while( str[i] != '\0' ) {
    CPputc(str[i++]);
  }
  return (i);
}

int CPputc( char c ) {
  //  printf( "%c", c ); fflush(stdout);
    if(!io_initialized)
        CP_accept_new_connection();
    if(1!=write(current_socket, &c, 1)) {
        // The inability to write probably signals the end of a connection.
        // Try to accept a new connection.
//        perror("Unable to write character");
        CP_accept_new_connection();
        if(1!=write(current_socket, &c, 1)) {
            perror("Tried again and failed, so dropped character");
            return 1;
        }
    }

    // Read the character back.  It ought to be the same.  This flushes the
    // buffer.
//    read(current_socket, &c, 1);

    return (1);
}

#if 0
/*************************************************************************/
// this function attempts to wait the number of ms specified by the passed arg

void wait_ms(unsigned int var)
{
  msleep(var);
}
#endif

unsigned short ADC_RandValue() {
#warning "USING LINUX random() function -- port this to a proper RNG on falconwing"
  /* ADC1 regular channel1 configuration -- for PRNG sampling */ 
  return (unsigned short) random();
}

