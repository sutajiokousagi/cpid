#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void print_help(char *name) {
    printf("Usage:\n"
            "    %s -k [keyfile]\n", name);
}

int main(int argc, char **argv) {
    int ch;
    char keyfile[128];

    bzero(keyfile, sizeof(keyfile));

    while(-1 != (ch=getopt(argc, argv, "hk:"))) {
        switch(ch) {

            case 'k':
                strncpy(keyfile, optarg, sizeof(keyfile)-1);
                break;

            case 'h':
            default:
                print_help(argv[0]);
                exit(0);
                break;

        }
    }

    // If the user didn't specify a keyfile, print out help and exit.
    if(!keyfile[0]) {
        print_help(argv[0]);
        exit(0);
    }

    argc -= optind;
    argv += optind;

    while (1) {
        crypto(keyfile); 
    }
}

