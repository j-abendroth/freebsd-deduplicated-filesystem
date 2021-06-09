#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUEST_SIZE 8000
#define SRC_PATH     "../src/"
#define PATH_LEN     1024

int
main(int argc, char* argv[]) {
    printf("going to read the first %u bytes of each file...\n", REQUEST_SIZE);
    char ddfs_buf[REQUEST_SIZE + 1];
    memset(ddfs_buf, '\0', REQUEST_SIZE + 1);
    char orig_buf[REQUEST_SIZE + 1];
    memset(orig_buf, '\0', REQUEST_SIZE + 1);
    int path_prefix_len;
    char ddfs_path[PATH_LEN];
    char cmp_path[PATH_LEN];
    int ddfs_fd;
    int orig_fd;
    DIR* dir_fd;
    int bytes;
    int res;

    struct dirent* in_file;

    if (argc != 2) {
        printf("Incorrect usage: ./rdtest </absolute/path/to/testfs>\n");
        return 1;
    } else {
        path_prefix_len = strlen(argv[1]);
        strncpy(ddfs_path, argv[1], path_prefix_len);
        if (ddfs_path[path_prefix_len - 1] != '/') {
            ddfs_path[path_prefix_len++] = '/';
            ddfs_path[path_prefix_len]   = '\0';
        }
    }

    // open src directory (we'll compare these files to ddfs's version)
    if ((dir_fd = opendir(SRC_PATH)) == NULL) {
        fprintf(stderr, "Error : Failed to open input directory - %s\n", strerror(errno));
        return 1;
    }

    // loop through files
    while ((in_file = readdir(dir_fd))) {
        if (!strcmp(in_file->d_name, "."))
            continue;
        if (!strcmp(in_file->d_name, ".."))
            continue;

        // open the comparison file
        memset(cmp_path, 0, PATH_LEN);
        strncpy(cmp_path, SRC_PATH, PATH_LEN);
        strncat(cmp_path, in_file->d_name, PATH_LEN);
        orig_fd = open(cmp_path, O_RDONLY);
        if (orig_fd == -1) {
            printf("Error : Failed to open entry file [%s] : %s\n", cmp_path, strerror(errno));
            continue;
        }

        // read in the comparison file
        if (read(ddfs_fd, orig_buf, REQUEST_SIZE) == -1) {
            printf("error: orig read(%s): %s\n", cmp_path, strerror(errno));
            close(orig_fd);
            continue;
        }
        close(orig_fd);

        // open the ddfs's version of the file

        memset(&ddfs_path[path_prefix_len], '\0', PATH_LEN - path_prefix_len);
        strncat(ddfs_path, in_file->d_name, PATH_LEN);
        if ((ddfs_fd = open(ddfs_path, O_RDONLY)) == -1) {
            printf("error: open(%s): %s\n", ddfs_path, strerror(errno));
            ddfs_path[path_prefix_len] = '\0';
            continue;
        }

        // read in the ddfs's version of the file
        if ((bytes = read(ddfs_fd, ddfs_buf, REQUEST_SIZE)) == -1) {
            printf("error: ddfs read(%s): %s\n", ddfs_path, strerror(errno));
            close(ddfs_fd);
            ddfs_path[path_prefix_len] = '\0';
            continue;
        }
        close(ddfs_fd);

        // print whether they match
        res = strncmp(ddfs_buf, orig_buf, bytes);
        if (res == 0) {
            printf("SUCCESS: Files match: %s\n", ddfs_path);
        } else {
            printf("FAILURE: Files DO NOT match: %s\n", ddfs_path);
            printf("%s is greater", res > 0 ? "ddfs version" : "original");
            printf("Your source files may have changed. Did you forget to run testfs first?\n");

            printf("Here's the file: \n\n");
            printf("%s\n\n", ddfs_buf);
        }

        memset(orig_buf, '\0', REQUEST_SIZE);
        memset(ddfs_buf, '\0', REQUEST_SIZE);
    }

    closedir(dir_fd);

    return 0;
}
