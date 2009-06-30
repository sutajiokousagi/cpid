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
#define DEFAULT_IO_PIPE "/tmp/.cpid"


// these variables comes from crypto.c
extern unsigned int powerTimer;
extern unsigned char powerState;
static int io_initialized = 0;
static int pipe_file = 0;

static void CP_initialize_io(const char *pipe_name) {
    int temp_file;
    int err;

    // Create the fifo node, making sure it doesn't exist.
    unlink(pipe_name);
    if((err=mknod(pipe_name, S_IFIFO | 0666, 0)))
        return err;

    // Open the pipe, and return its handle.
    if((temp_file = open(pipe_name, O_WRONLY)) < 0)
        return temp_file;

    // Now that the pipe is open, set it to nonblocking.
    //fcntl(temp_file, F_SETFD, O_NONBLOCK);

    io_initialized = 1;

    // We might want to do more manipulation of temp_file here, for example
    // to manipulate the buffer.  Or not.
    pipe_file = temp_file;

    return;
}

unsigned char CPgetc() {
    char c;
    /*
    // begin icky linux termio stuff
    struct termios oldT, newT;
    char c;

    ioctl(0,TCGETS,&oldT); //get current mode

    newT=oldT;
    newT.c_lflag &= ~ECHO; // echo off
    newT.c_lflag &= ~ICANON; //one char @ a time
    
    ioctl(0,TCSETS,&newT); // set new terminal mode
    
    read(0,&c,1); //read 1 char @ a time from stdin
    
    ioctl(0,TCSETS,&oldT); // restore previous terminal mode
    */
    if(!io_initialized)
        CP_initialize_io(DEFAULT_IO_PIPE);

    //read 1 char @ a time from stdin
    if(1!=read(pipe_file,&c,1)) {
        perror("Unable to read"); 
        CP_initialize_io(DEFAULT_IO_PIPE);
    }
    if(1!=read(pipe_file,&c,1)) {
        perror("Unable to read character, so dropped");
    }

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
    if(!io_initialized)
        CP_initialize_io(DEFAULT_IO_PIPE);
    if(1!=write(pipe_file, &c, 1)) {
        perror("Unable to write character");
        CP_initialize_io(DEFAULT_IO_PIPE);
    }
    if(1!=write(pipe_file, &c, 1)) {
        perror("Tried again and failed, so dropped character");
    }
    //fflush(stdout);
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

