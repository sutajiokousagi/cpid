#include "commonCrypto.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

void print_help(char *name) {
    printf("Usage:\n"
            "    %s [-hd] -k [keyfile]\n"
            "   -k [keyfile]        Use [keyfile] instead of eeprom\n"
            "   -d                  Run as daemon\n"
            "   -h                  Print this help text\n"
            , name);
}

static void cleanup(int arg) {
    unlink(DEFAULT_IO_PIPE);
    exit(0);
    return;
}


int main(int argc, char **argv) {
    int ch;
    char keyfile[128];
    int as_daemon = 0;

    bzero(keyfile, sizeof(keyfile));

    while(-1 != (ch=getopt(argc, argv, "dhk:"))) {
        switch(ch) {

            case 'k':
                strncpy(keyfile, optarg, sizeof(keyfile)-1);
                break;

            case 'd':
                as_daemon = 1;
                break;

            case 'h':
            default:
                print_help(argv[0]);
                exit(0);
                break;

        }
    }

    /*
    // If the user didn't specify a keyfile, print out help and exit.
    if(!keyfile[0]) {
        print_help(argv[0]);
        exit(0);
    }
    */

    argc -= optind;
    argv += optind;

    if(as_daemon)
        if(daemon(1, 0))
            perror("Unable to run as daemon");


    // Have signals call our cleanup function.
    // We do this first since creating pidfiles and pipes can block.
    signal(SIGTERM, cleanup);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP,  cleanup);
    signal(SIGINT,  cleanup);


    while (1)
        crypto(keyfile); 

    cleanup(0);
}

