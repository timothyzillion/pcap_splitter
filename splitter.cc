/*
 * Program to
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <pcap.h>

#include "SessionHash.h"

#include "fnv.h"

static void usage(const char *p)
{
    fprintf(stderr, "usage: %s -f <input.pcap>\n", p);
    exit(1);
}

int main(int argc, char **argv)
{
    char pcapError[PCAP_ERRBUF_SIZE];
    pcap_t *input;
//    CSessionHash sessions;
    char *inputFile=NULL;

    int opt;

    while ((opt = getopt(argc, argv, "f:")) != -1) {
        switch(opt) {
        case 'f':
            inputFile = optarg;
            break;
        default:
            usage(argv[0]);
        }
    }
    if (inputFile == NULL) {
        usage(argv[0]);
    }

    input = pcap_open_offline(inputFile, pcapError);
    if (input == NULL) {
        fprintf(stderr, "Couldn't open %s: %s\n", inputFile, pcapError);
        exit(1);
    }


    pcap_close(input);
}
