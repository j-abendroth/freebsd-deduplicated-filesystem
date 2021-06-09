#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUEST_SIZE 8000
#define PATH_LEN     1024

int
main(int argc, char* argv[]) {
    printf("going to read the first %u bytes of each file...\n", REQUEST_SIZE);
    char ddfs_buf[REQUEST_SIZE + 1];
    memset(ddfs_buf, '\0', REQUEST_SIZE + 1);
    int path_prefix_len;
    char ddfs_path[PATH_LEN];
    int ddfs_fd;
    DIR* dir_fd;
    int bytes;

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
    if ((dir_fd = opendir(ddfs_path)) == NULL) {
        fprintf(stderr, "Error : Failed to open directory - %s\n", strerror(errno));
        return 1;
    }

    // loop through files
    while ((in_file = readdir(dir_fd))) {
        if (!strcmp(in_file->d_name, "."))
            continue;
        if (!strcmp(in_file->d_name, ".."))
            continue;

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

        printf("%s\n\n", ddfs_buf);
        memset(ddfs_buf, '\0', REQUEST_SIZE);
    }

    closedir(dir_fd);

    return 0;
}
