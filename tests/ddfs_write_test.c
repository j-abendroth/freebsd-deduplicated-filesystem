#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char** argv) {
    if (argc != 2) {
        printf("Incorrect usage. Need path to ddfs mount\n");
        return (EXIT_FAILURE);
    }

    // try writing to kvs.h
    printf("Writing to existing file kvs.c\n");
    char* ddfs_mount = argv[1];
    char* test_path  = malloc(strlen(ddfs_mount) + 6);
    memcpy(test_path, ddfs_mount, strlen(ddfs_mount));
    strcat(test_path, "kvs.c");
    printf("file name: %s\n", test_path);

    int fd;
    if ((fd = open(test_path, O_WRONLY)) < 0) {
        perror("Error opening kvs.c in ddfs");
        return (EXIT_FAILURE);
    }

    char* test_str = "Hello world! From ddfs!!\n";
    if (write(fd, test_str, strlen(test_str)) < 0) {
        perror("Error writing test file value");
        return (EXIT_FAILURE);
    }
    close(fd);

    if ((fd = open(test_path, O_RDONLY)) < 0) {
        perror("Error opening kvs.c in ddfs");
        return (EXIT_FAILURE);
    }

    char buffer[4096];
    if (read(fd, buffer, 4096) < 0) {
        perror("Error reading from kvs.c\n");
        return (EXIT_FAILURE);
    }

    if (strncmp(buffer, test_str, strlen(test_str)) != 0) {
        perror("Write failed :( First part of kvs.c not equal to test string");
        return (EXIT_FAILURE);
    } else {
        printf("Write succeeded! First part of kvs.c equal to test string\n");
    }
    close(fd);

    // now try creating new file
    printf("\nTest creating new file and writing to it\n");
    char* test_file = malloc(strlen(ddfs_mount) + 5);
    memcpy(test_file, ddfs_mount, strlen(ddfs_mount));
    strcat(test_file, "test");
    printf("file name: %s\n", test_file);
    if ((fd = open(test_file, O_WRONLY | O_CREAT, 0644)) < 0) {
        perror("Error opening new test file in ddfs\n");
        return (EXIT_FAILURE);
    }

    char* test_str2 = "Hello world! Testing new file from ddfs!!\n";
    if (write(fd, test_str2, strlen(test_str2)) < 0) {
        perror("Error writing test file value\n");
        return (EXIT_FAILURE);
    }
    close(fd);

    if ((fd = open(test_file, O_RDWR | O_CREAT, 0644)) < 0) {
        perror("Error opening new test file in ddfs\n");
        return (EXIT_FAILURE);
    }

    memset(buffer, 0, 4096);
    if (read(fd, buffer, 4096) < 0) {
        perror("error reading new test file");
        return (EXIT_FAILURE);
    }

    if (strncmp(buffer, test_str2, strlen(test_str2)) != 0) {
        perror("Write failed :( First part of test file not equal to test string");
        return (EXIT_FAILURE);
    } else {
        printf("Write succeeded! First part of test file equal to test string\n");
    }
    close(fd);

    printf("Write tests successful! Run cat on %skvs.c or %stest to see results!\n", ddfs_mount, ddfs_mount);

    return (0);
}
