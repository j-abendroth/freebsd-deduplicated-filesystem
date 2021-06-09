// clang-format off
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/disk.h>
#include <sys/types.h>
#include <unistd.h>

#include "../src/kvs.h"
#include "../src/ddfs.h"
#include "../src/dir.h"

// clang-format on

#define BITS_PER_BLOCK (BLOCKSIZE * 8)

// copied from: sys/ufs/ufs/ufs_vnops.c
static struct dirtemplate mastertemplate = {
    0, 12, DT_DIR, 1, ".", 0, DIRBLKSIZ - 12, DT_DIR, 2, "..",
};

void write_blocks(FILE* fd, char* buf, int offset, int num_blocks);
void init_superblock(struct ddfs_sblock* sblock);
bool read_superblock(FILE* disk);
void write_root_dir(FILE* fd, struct ddfs_sblock* sblock);

/*
 * Disk Structure:
 * (4KB)   superblock 	                ** 1   block  **
 * (8KB)   hash bitmap                  ** 2   blocks **
 * (256MB) inode table                  ** ~64k blocks **
 * (var)   free data block bitmap       ** var blocks **
 * (var)   file dinode free bitmap      ** var blocks **
 * (var)   file dinodes                 ** var blocks **
 * (var)   data blocks                  ** var blocks **
 */
int
main(int argc, char* argv[]) {
    FILE* fd;
    off_t partition_size;
    uint32_t total_blocks;
    uint32_t total_finode_blocks;
    uint32_t total_finodes;
    uint32_t finode_bitmap_blocks;
    uint32_t bitmap_blocks;
    struct ddfs_sblock superblock;
    int kvs_inode_blocks = KVS_INODE_TABLE_SIZE / BLOCKSIZE;
    char* buf;
    char input;

    if (argc != 2) {
        printf("Incorrect usage: ./mkddfs <disk-name>\n");
        exit(EXIT_FAILURE);
    }
    if ((buf = malloc(BLOCKSIZE)) == NULL) {
        fprintf(stderr, "Error malloc: %s\n", strerror(errno));
    }
    memset(buf, 0, BLOCKSIZE);
    init_superblock(&superblock);

    // Get partition size and total number of blocks
    int ioctl_fd = open(argv[1], O_RDWR);
    if (ioctl_fd == -1) {
        err(EXIT_FAILURE, "%s: can't open %s for writing", __func__, argv[1]);
    }
    ioctl(ioctl_fd, DIOCGMEDIASIZE, &partition_size);
    total_blocks = partition_size / BLOCKSIZE;
    close(ioctl_fd);

    // calculate total number of finodes
    total_finode_blocks  = total_blocks * RESERVED_INODE_SPACE_PERCENT;
    total_finodes        = total_finode_blocks * FILE_DINODES_PER_BLOCK;
    finode_bitmap_blocks = ceil(total_finodes / BITS_PER_BLOCK);

    total_blocks = total_blocks              //
                   - kvs_inode_blocks        //
                   - total_finode_blocks     //
                   - finode_bitmap_blocks    //
                   - 3;

    // How many blocks do we need to represent the remaining data blocks
    bitmap_blocks = ceil(total_blocks / BITS_PER_BLOCK);

    superblock.total_data_blocks     = total_blocks - bitmap_blocks;
    superblock.finode_bitmap_offset  = FREE_BITMAP_OFF + bitmap_blocks;
    superblock.file_inode_offset     = FREE_BITMAP_OFF + bitmap_blocks + finode_bitmap_blocks;
    superblock.max_file_inodes       = (uint32_t)total_finodes;
    superblock.data_block_offset     = superblock.file_inode_offset + total_finode_blocks;
    superblock.last_used_finode_blk  = 0;
    superblock.last_alloc_finode_blk = STATIC_INODE_COUNT / FILE_DINODES_PER_BLOCK - 1;

    if ((fd = fopen(argv[1], "w+")) == NULL) {
        err(EXIT_FAILURE, "%s: can't open %s for writing", __func__, argv[1]);
    }

    // Check for existing KVFS, get confirmation for overwrite
    if (read_superblock(fd)) {
        printf("Would you like to overwrite the existing KVFS image? [y/n]\n");
        while ((input = fgetc(stdin)) != 'y' && input != 'n') {
            printf("Invalid input. [y/n]\n");
        }
        if (input == 'n') {
            printf("Leaving existing KVFS as is. Exiting...\n");
            exit(EXIT_SUCCESS);
        }
    }

    // Probably don't need to seek because we're probably already at 0
    if (fseek(fd, SUPERBLOCK_OFF, SEEK_SET) == -1) {
        fprintf(stderr, "Error seeking superblock: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Writing superblock
    printf("writing superblock...\n");
    if (fwrite(&superblock, sizeof(struct ddfs_sblock), 1, fd) != 1) {
        fprintf(stderr, "Error writing superblock: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Writing hash bitmap
    printf("writing hash bitmap...\n");
    write_blocks(fd, buf, superblock.hash_bitmap_offset, 2);

    // Writing inode table
    printf("writing kvs_inode table...\n");
    write_blocks(fd, buf, superblock.kvs_inode_table_offset, kvs_inode_blocks);

    // Writing data block bitmap
    printf("writing data block bitmap...\n");
    write_blocks(fd, buf, superblock.free_bitmap_offset, bitmap_blocks);

    // writing finode bitmap
    printf("writing finode bitmap...\n");
    write_blocks(fd, buf, superblock.finode_bitmap_offset, finode_bitmap_blocks);

    // zero out default inodes
    printf("writing static file inodes...\n");
    write_blocks(fd, buf, superblock.file_inode_offset, STATIC_INODE_COUNT / FILE_DINODES_PER_BLOCK);

    free(buf);

    // Need to write the root node:
    printf("initializing root node...\n");
    write_root_dir(fd, &superblock);

    printf("DONE!\n");
    fclose(fd);
    return 0;
}

void
init_superblock(struct ddfs_sblock* sblock) {
    sblock->superblock_size        = 1;
    sblock->total_data_blocks      = 0;
    sblock->data_block_offset      = 0;
    sblock->kvs_inode_table_offset = KVS_INODE_TABLE_OFF;
    sblock->kvs_inode_table_size   = 65536;
    sblock->hash_bitmap_offset     = HASH_BITMAP_OFF;
    sblock->free_bitmap_offset     = FREE_BITMAP_OFF;
    sblock->fs_magic               = DDFSMAGIC;
    sblock->fs_uid                 = 0;
    sblock->block_size             = BLOCKSIZE;
    memset(sblock->fs_name, 0, MAXMNTLEN);
    memset(sblock->fs_volname, 0, MAXVOLLEN);
    memset(sblock->padding, 0, SUPERBLOCK_PADDING);

    char name[100] = "jra_ddfs";
    strcpy((char*)sblock->fs_name, name);
    strcpy((char*)sblock->fs_volname, name);

    sblock->used_data_blocks = 1;    // 1 block will be used by root
    sblock->used_file_inodes = 2;    // first 2 inodes reserved (2nd is root dir)
    sblock->used_kvs_inodes  = 1;    // used by root dir
    sblock->total_block_refs = 1;    // used by root dir
}

bool
read_superblock(FILE* disk) {
    struct ddfs_sblock superblock;
    if (fread(&superblock, sizeof(struct ddfs_sblock), 1, disk) != 1) {
        printf("fread failed\n");
        return false;
    }
    if (superblock.fs_magic != DDFSMAGIC) {
        printf("magic number isn't the same\n");
        return false;
    }
    return true;
}

void
write_blocks(FILE* fd, char* buf, int offset, int num_blocks) {
    if (fseek(fd, offset * BLOCKSIZE, SEEK_SET) == -1) {
        perror("write_blocks():fseek()");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < num_blocks; i++) {
        if (fwrite(buf, sizeof(char), BLOCKSIZE, fd) == 0) {
            fprintf(stderr, "Error writing blocks: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
}

/*
 *  - Create a direct struct
 *  - put the struct in a zeroed block
 *  - write the block to disk at data block 1 (for simplicity)
 *  - hash the block
 *  - update kvs inode and data block bitmap, write it to disk at hash loc
 *  - create a file_dinode struct and initialize it at the ROOT location
 *  - update the finode bitmap and write to disk
 *
 * source:
 * (used to figure out what macros and default values were needed, also dir structure)
 * https://github.com/bluerise/openbsd-src/blob/master/sbin/newfs/mkfs.c
 */
void
write_root_dir(FILE* fd, struct ddfs_sblock* sblock) {
    char buf[BLOCKSIZE];
    char hash[INODE_KEY_LENGTH];
    struct dirtemplate dir;
    struct kvs_dinode kvs_inode;
    struct file_dinode dinode;
    uint32_t inode_location;
    uint32_t lblock;

    // init directory
    memset(buf, 0, BLOCKSIZE);
    memcpy(&dir, &mastertemplate, sizeof(struct dirtemplate));
    dir.dot_ino = DDFS_ROOT_INO;

    // write the directory to disk at data block 1
    memcpy(buf, &dir, sizeof(struct dirtemplate));
    write_blocks(fd, buf, sblock->data_block_offset + 1, 1);

    // hash the directory
    SHA1((unsigned char*)buf, BLOCKSIZE, (unsigned char*)hash);

    // print the key for the kvs_inode
    printf("kvs_dinode dir key: ");
    for (int i = 0; i < INODE_KEY_LENGTH; i++) {
        printf("%02hX", hash[i]);
    }
    printf("\n");

    // update the data bitmap
    memset(buf, 0, BLOCKSIZE);
    buf[0] |= 3;
    write_blocks(fd, buf, sblock->free_bitmap_offset, 1);

    // update the kvs inode
    memcpy(&kvs_inode.key.key, hash, INODE_KEY_LENGTH);
    kvs_inode.data_block = 1;
    kvs_inode.ref_count  = 1;

    // write the inode to disk
    memset(buf, 0, BLOCKSIZE);
    ((struct inode_list_block*)buf)->entries[0]  = kvs_inode;
    ((struct inode_list_block*)buf)->entry_count = 1;
    inode_location                               = 0x0000FFFF & ((hash[18] << 8) | hash[19]);
    lblock                                       = sblock->kvs_inode_table_offset + inode_location;
    write_blocks(fd, buf, lblock, 1);

    // update the dinode for the directory
    memset(&dinode, 0, sizeof(struct file_dinode));
    memcpy(&dinode.di_db[0].key, hash, INODE_KEY_LENGTH);
    dinode.di_blksize = BLOCKSIZE;
    dinode.di_size    = DIRBLKSIZ;
    dinode.di_blocks  = 1;
    dinode.di_mode    = 0755 | IFDIR;
    dinode.di_nlink   = 2;
    dinode.di_uid     = geteuid();
    dinode.di_gid     = geteuid();

    // write the dinode to disk
    memset(buf, 0, BLOCKSIZE);
    memcpy(&buf[0] + sizeof(struct file_dinode), &dinode, sizeof(struct file_dinode));
    write_blocks(fd, buf, sblock->file_inode_offset, 1);

    // update the inode bitmap and write it
    memset(buf, 0, BLOCKSIZE);
    buf[0] |= 3;
    write_blocks(fd, buf, sblock->finode_bitmap_offset, 1);
}
