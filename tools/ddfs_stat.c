// clang-format off
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "../src/ddfs.h"
// clang-format on

int get_stats(char* file, struct stats*);

int
main(int argc, char* argv[]) {
    int fd;
    struct stats stats = { 0 };
    uint32_t total_blocks;
    uint32_t used_blocks;
    uint64_t total_refs;

    if (argc != 2) {
        printf("Incorrect usage: ./ddfsstat /path/to/fs\n");
        exit(EXIT_FAILURE);
    }

    // open the file or directory
    if ((fd = open(argv[1], O_RDONLY)) == -1) {
        fprintf(stderr, "Error: Could not open: %s: %s\n", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, STAT, &stats)) {
        fprintf(stderr, "Error reading file\n");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);

    // perform calculations and print
    total_blocks = stats.total_data_blocks;
    total_refs   = stats.total_block_refs;
    used_blocks  = stats.used_data_blocks;
    printf("Filesystem stats:\n");
    printf("Total data blocks: %u\n", total_blocks);
    printf("Used data blocks: %u\n", used_blocks);
    printf("Total block references: %lu\n", total_refs);
    printf("Space saved from deduplication: %4.2f%%\n",
           ((float)(total_refs - used_blocks) / total_refs) * 100);

    exit(EXIT_SUCCESS);
}
