/*
    This program initializes our on-disk structures
    with default data for testing purposes.
*/

#include <dirent.h>
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

#include "../src/ddfs.h"
#include "../src/dir.h"
#include "../src/kvs.h"

#define DIR_PREFIX "../src/"

int read_superblock(FILE* disk, struct ddfs_sblock*);
int write_data(FILE*, struct ddfs_sblock*);
int write_data_block(FILE* disk, char* buf, uint32_t block);
int write_inode_block(FILE* disk, uint32_t inode_table_offset, char* key, uint32_t data_blocks_written);
int write_hash_bitmap(FILE* disk, uint32_t hash_bitmap_offset, char* hash);
int write_data_bitmap(FILE* disk, uint32_t bitmap_offset, uint32_t data_blocks_written);
int get_key(char* buf, char* key, char* hash);
int init_dinode(struct file_dinode* dinode);
int write_finode(FILE* disk, struct file_dinode* dinode, struct ddfs_sblock* superblock, int dinodes_written);
int write_finode_bitmap(FILE* disk, struct ddfs_sblock* superblock, int dinodes_written);
int write_dir(FILE* disk, struct ddfs_sblock* superblock, int dinodes_written, char* filename);

/* struct ddfs_sblock {
    uint32_t superblock_size;           // size in blocks (always 1 block)
    uint32_t total_data_blocks;         // number of usable data blocks
    uint32_t data_block_offset;         // block number of beginning of data blocks
    uint32_t kvs_inode_table_offset;    // block number of beginning of inode table
    uint32_t kvs_inode_table_size;      // hash table size expressed as a count of entries
    uint32_t hash_bitmap_offset;        // offset of hash bitmap (track used entries)
    uint32_t free_bitmap_offset;        // block number of beginning of free data bitmap
    uint32_t finode_bitmap_offset;      // offset of file inode bitmap
    uint64_t fs_uid;                    // system wide uid for our fs
    uint16_t block_size;                // block size in bytes
    uint32_t file_inode_offset;         // disk offset where inodes are
    uint32_t max_file_inodes;           // maximum number of file inodes
    uint32_t last_used_finode_blk;      // max inode block number of where inodes were actually used from
    uint32_t last_alloc_finode_blk;     // location of last allocated file inode block

    u_char fs_name[MAXMNTLEN];       // path name of our fs
    u_char fs_volname[MAXVOLLEN];    // volume name of our fs

    int32_t fs_magic;    // magic number identifies our fs

    // Summary info for os
    uint32_t used_data_blocks;
    uint32_t used_file_inodes;

    uint32_t used_kvs_inodes;
    uint8_t padding[3520];
}; */

/*
 * Disk Structure:
 * (4KB)   superblock 	  ** 1   block  **
 * (8KB)   hash bitmap    ** 2   blocks **
 * (256MB) inode table    ** ~64k blocks **
 * (var)   free bitmap    ** var blocks **
 * (var)   data blocks    ** var blocks **
 */
int
main(int argc, char* argv[]) {
    FILE* fd;
    struct ddfs_sblock superblock;
    if (argc != 2) {
        printf("Incorrect usage: ./mktestfs <disk-name>\n");
        exit(EXIT_FAILURE);
    }

    if ((fd = fopen(argv[1], "w+")) == NULL) {
        err(EXIT_FAILURE, "%s: can't open %s for writing", __func__, argv[1]);
    }

    if (read_superblock(fd, &superblock) != 0) {
        exit(EXIT_FAILURE);
    }

    if (write_data(fd, &superblock)) {
        printf("Error writing data\n");
        exit(EXIT_FAILURE);
    }

    printf("SUCCESS!\n");

    exit(EXIT_SUCCESS);
}

int
read_superblock(FILE* disk, struct ddfs_sblock* sbp) {
    if (fread(sbp, sizeof(struct ddfs_sblock), 1, disk) != 1) {
        printf("fread failed\n");
        return 1;
    }
    if (sbp->fs_magic != DDFSMAGIC) {
        printf("magic number isn't the same\n");
        return 1;
    }

    printf("\nSUPERBLOCK INFO-----------------------------\n");
    printf("magic number:\t\t\t\t%i\n", sbp->fs_magic);
    printf("block size:\t\t\t\t%u\n", sbp->block_size);
    printf("total data blocks:\t\t\t%u\n", sbp->total_data_blocks);
    printf("used data blocks:\t\t\t%u\n", sbp->used_data_blocks);
    printf("data block offset:\t\t\t%u\n", sbp->data_block_offset);
    printf("kvs_inode table offset:\t\t\t%u\n", sbp->kvs_inode_table_offset);
    printf("kvs_inode table size:\t\t\t%u\n", sbp->kvs_inode_table_size);
    printf("used kvs inodes:\t\t\t%u\n", sbp->used_kvs_inodes);
    printf("file inode table offset:\t\t%u\n", sbp->file_inode_offset);
    printf("max file inodes:\t\t\t%u\n", sbp->max_file_inodes);
    printf("used file inodes:\t\t\t%u\n", sbp->used_file_inodes);
    printf("last used inode block:\t\t\t%u\n", sbp->last_used_finode_blk);
    printf("allocated inodes:\t\t\t%u\n", (sbp->last_alloc_finode_blk + 1) * FILE_DINODES_PER_BLOCK);
    printf("hash bitmap offset:\t\t\t%u\n", sbp->hash_bitmap_offset);
    printf("free bitmap offset:\t\t\t%u\n", sbp->free_bitmap_offset);
    printf("file inode bitmap offset:\t\t%u\n", sbp->finode_bitmap_offset);
    printf("--------------------------------------------\n\n");

    return 0;
}

int
write_data(FILE* disk, struct ddfs_sblock* superblock) {
    uint32_t data_block_offset  = superblock->data_block_offset;
    uint32_t inode_table_offset = superblock->kvs_inode_table_offset;
    uint32_t hash_bitmap_offset = superblock->hash_bitmap_offset;
    uint32_t bitmap_offset      = superblock->free_bitmap_offset;
    DIR* dir_fd;
    struct dirent* in_file;
    int entry_file;
    int keys_fd;
    uint32_t data_blocks_written = 2;
    int dinodes_written          = 2;
    struct file_dinode dinode;

    // open src directory (we'll write these files to disk)
    if ((dir_fd = opendir("../src")) == NULL) {
        fprintf(stderr, "Error : Failed to open input directory - %s\n", strerror(errno));
        return 1;
    }

    // open keys file
    if ((keys_fd = open("./test_keys", O_WRONLY | O_TRUNC | O_CREAT, 666)) == -1) {
        perror("failed to open keys file");
        return 1;
    }

    // loop through files
    while ((in_file = readdir(dir_fd))) {
        if (!strcmp(in_file->d_name, "."))
            continue;
        if (!strcmp(in_file->d_name, ".."))
            continue;
        /* Open directory entry file */
        char filepath[1024] = { '\0' };
        strcat(filepath, DIR_PREFIX);
        char filename[255] = { '\0' };
        strcat(filepath, in_file->d_name);
        strcat(filename, in_file->d_name);
        entry_file = open(filepath, O_RDONLY);
        if (entry_file == -1) {
            printf("Error : Failed to open entry file [%s] : %s\n", filepath, strerror(errno));
            continue;
        }

        init_dinode(&dinode);

        char buf[BLOCKSIZE];
        memset(buf, 0, BLOCKSIZE);
        char hash_key[20];
        char hash_str[41];
        hash_str[40]           = '\0';
        int blocks_read_so_far = 0;
        int bytes_read         = 0;
        // read in a source code file from /src and write contents to our file system
        // we write <= 3 blocks per file b/c I don't want to deal with
        // indirect blocks rn
        while (blocks_read_so_far < 3 && (bytes_read = read(entry_file, buf, BLOCKSIZE)) > 0) {
            get_key(buf, hash_str, hash_key);
            printf("key: %.40s\n", hash_str);
            if (write_data_block(disk, buf, data_block_offset + data_blocks_written + 1))
                exit(EXIT_FAILURE);
            if (write_inode_block(disk, inode_table_offset, hash_key, data_blocks_written + 1))
                exit(EXIT_FAILURE);
            if (write_hash_bitmap(disk, hash_bitmap_offset, hash_key))
                exit(EXIT_FAILURE);
            if (write_data_bitmap(disk, bitmap_offset, data_blocks_written + 1))
                exit(EXIT_FAILURE);

            // update dinode
            memcpy(&dinode.di_db[blocks_read_so_far].key, hash_key, INODE_KEY_LENGTH);
            dinode.di_size += bytes_read;
            dinode.di_blocks++;

            hash_str[40] = '\n';
            write(keys_fd, hash_str, 41);
            data_blocks_written++;
            blocks_read_so_far++;
            memset(buf, 0, BLOCKSIZE);
        }

        if (blocks_read_so_far > 0) {
            printf("writing finode...\n");
            if (write_finode(disk, &dinode, superblock, dinodes_written))
                exit(EXIT_FAILURE);
            printf("writing finode bitmap...\n");
            if (write_finode_bitmap(disk, superblock, dinodes_written))
                exit(EXIT_FAILURE);
            printf("writing directory...\n");
            if (write_dir(disk, superblock, dinodes_written, filename))
                exit(EXIT_FAILURE);
            dinodes_written++;
        }

        close(entry_file);
    }

    // update superblock block count
    if (data_blocks_written > 0) {
        superblock->used_data_blocks = data_blocks_written;
        superblock->used_kvs_inodes  = data_blocks_written;
        superblock->used_file_inodes = dinodes_written;
        fseek(disk, 0, SEEK_SET);
        if (fwrite(superblock, sizeof(struct ddfs_sblock), 1, disk) != 1) {
            printf("error writing superblock: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    closedir(dir_fd);
    close(keys_fd);
    return 0;
}

int
get_key(char* buf, char* key, char* hash) {
    SHA1((unsigned char*)buf, BLOCKSIZE, (unsigned char*)hash);

    // convert to characters
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&key[i * 2], "%02hX", hash[i]);
    }
    return 0;
}

int
write_data_block(FILE* disk, char* buf, uint32_t block) {
    printf("write_data_block(): writing data to logical block %u\n", block);
    if (fseek(disk, block * BLOCKSIZE, SEEK_SET) != 0
        || fwrite(buf, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        perror("write_data_block");
        return 1;
    }
    return 0;
}

int
write_inode_block(FILE* disk, uint32_t inode_table_offset, char* key, uint32_t data_blocks_written) {
    struct inode_list_block inode_block;
    memcpy(&inode_block.entries[0].key, key, INODE_KEY_LENGTH);
    inode_block.entries[0].data_block = data_blocks_written;
    inode_block.entries[0].mod_time   = 0;
    inode_block.entries[0].ref_count  = 1;
    inode_block.entry_count           = 1;
    inode_block.next_block            = 0;
    uint32_t hash_index               = 0x0000FFFF & ((key[18] << 8) | key[19]);

    uint32_t location = BLOCKSIZE * (inode_table_offset + hash_index);
    if (fseek(disk, location, SEEK_SET) != 0
        || fwrite(&inode_block, sizeof(struct inode_list_block), 1, disk) != 1) {
        perror("write_inode_block");
        return 1;
    }
    return 0;
}

int
write_hash_bitmap(FILE* disk, uint32_t hash_bitmap_offset, char* hash) {
    uint32_t bits_per_block = 4096 * 8;
    uint32_t hash_index     = hash[18] & 0xFFFF;
    uint32_t blockno        = hash_bitmap_offset + (hash_index / bits_per_block);
    uint64_t bitmap[512];

    // first read the bitmap block
    fseek(disk, BLOCKSIZE * blockno, SEEK_SET);
    if (fread(bitmap, sizeof(uint64_t), 512, disk) != 512) {
        printf("write_hash_bitmap(): error reading bitmap: %s\n", strerror(errno));
        return 1;
    }

    // now write back with altered bit
    bitmap[(hash_index / 64) % 512] |= (1 << hash_index % 64);
    fseek(disk, BLOCKSIZE * blockno, SEEK_SET);
    if (fwrite(bitmap, sizeof(uint64_t), 512, disk) != 512) {
        perror("write_hash_bitmap");
        return 1;
    }
    return 0;
}

int
write_data_bitmap(FILE* disk, uint32_t bitmap_offset, uint32_t data_blocks_written) {
    uint32_t bits_per_block = BLOCKSIZE * 8;
    uint32_t blockno        = bitmap_offset + (data_blocks_written / bits_per_block);
    char bitmap[BLOCKSIZE];

    // first read the bitmap block
    fseek(disk, BLOCKSIZE * blockno, SEEK_SET);
    if (fread(bitmap, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        printf("write_data_bitmap(): error reading bitmap: %s\n", strerror(errno));
        return 1;
    }

    // now write back with altered bit
    bitmap[(data_blocks_written / 8) % BLOCKSIZE] |= (1 << data_blocks_written % 8);
    fseek(disk, BLOCKSIZE * blockno, SEEK_SET);
    if (fwrite(bitmap, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        perror("write_data_bitmap");
        return 1;
    }

    return 0;
}

int
init_dinode(struct file_dinode* dinode) {
    memset(dinode, 0, sizeof(struct file_dinode));
    dinode->di_mode    = IFREG | 0755;
    dinode->di_nlink   = 1;
    dinode->di_uid     = geteuid();
    dinode->di_gid     = geteuid();
    dinode->di_blksize = BLOCKSIZE;

    return 0;
}

int
write_finode(FILE* disk, struct file_dinode* dinode, struct ddfs_sblock* superblock, int dinodes_written) {
    uint32_t lblock     = superblock->file_inode_offset + (dinodes_written / FILE_DINODES_PER_BLOCK);
    uint32_t dinode_off = dinodes_written % FILE_DINODES_PER_BLOCK;
    char buf[BLOCKSIZE];

    printf("write_finode: file size: %lu\n", dinode->di_size);

    // write finode
    fseek(disk, (lblock * BLOCKSIZE), SEEK_SET);
    if (fread(buf, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        printf("write_data_bitmap(): error reading bitmap: %s\n", strerror(errno));
        return 1;
    }

    memcpy(&buf[0] + (dinode_off * sizeof(struct file_dinode)), dinode, sizeof(struct file_dinode));

    if (fseek(disk, (lblock * BLOCKSIZE), SEEK_SET) != 0
        || fwrite(buf, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        perror("write_finode()");
        return 1;
    }
    return 0;
}

int
write_finode_bitmap(FILE* disk, struct ddfs_sblock* superblock, int dinodes_written) {
    uint32_t blockno = superblock->finode_bitmap_offset;
    char bitmap[BLOCKSIZE];

    // first read the bitmap block
    if (fseek(disk, BLOCKSIZE * blockno, SEEK_SET) != 0) {
        printf("write_finode_bitmap(): error seeking to %u: %s\n", BLOCKSIZE * blockno, strerror(errno));
        return 1;
    }
    if (fread(bitmap, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        printf("write_finode_bitmap(): error reading bitmap: %s\n", strerror(errno));
        return 1;
    }

    // now write back with altered bit
    bitmap[(dinodes_written / 8) % BLOCKSIZE] |= (1 << dinodes_written % 8);
    fseek(disk, BLOCKSIZE * blockno, SEEK_SET);
    if (fwrite(bitmap, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        perror("write_finode_bitmap");
        return 1;
    }

    return 0;
}

/*
    Just write entries to the root, ignore other data blocks except first direct for now

    Jesus fuck this is hideous -- if there are bugs in mktestfs, this should be the first
    place you look
*/
int
write_dir(FILE* disk, struct ddfs_sblock* superblock, int dinodes_written, char* filename) {
    struct direct direct;
    struct file_dinode dir_dinode;
    uint32_t dir_dinode_loc = (superblock->file_inode_offset * BLOCKSIZE);
    uint32_t dir_dinode_off = sizeof(struct file_dinode);
    uint32_t dir_block_cnt  = 1;
    char hash_key[INODE_KEY_LENGTH];
    uint32_t dir_block_loc;
    struct kvs_dinode kvs_dinode;
    char buf[BLOCKSIZE];
    struct direct* this_direct;
    uint32_t buf_off = 0;
    uint32_t old_reclen;

    // create the new directory entry
    direct.d_ino    = dinodes_written;
    direct.d_namlen = strlen(filename);
    memcpy(&direct.d_name, filename, direct.d_namlen + 1);
    direct.d_type   = DT_REG;
    direct.d_reclen = 8 + direct.d_namlen + 1;
    direct.d_reclen += ((direct.d_reclen % 4) == 0) ? 0 : 4 - (direct.d_reclen % 4);

    // read the root directory dinode
    fseek(disk, dir_dinode_loc, SEEK_SET);
    if (fread(buf, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        printf("write_dir(): error reading dir_dinode: %s\n", strerror(errno));
        return 1;
    }

    memcpy(&dir_dinode, &buf[0] + dir_dinode_off, sizeof(struct file_dinode));

    // find the block in the directory we need
    dir_block_cnt = dir_dinode.di_blocks - 1;
    if (dir_block_cnt < 0) {
        printf("write_dir(): root dir has no backing file");
        return -1;
    }
    // printf("write_dir(): reading dir_dinode db[%u]\n", dir_block_cnt);
    memcpy(hash_key, &dir_dinode.di_db[dir_block_cnt].key, INODE_KEY_LENGTH);
    dir_block_loc = 0x0000FFFF & ((hash_key[18] << 8) | hash_key[19]);
    // printf("write_dir(): kvs_inode location: %u\n", dir_block_loc);

    // read the block's kvs_inode
    fseek(disk, BLOCKSIZE * (dir_block_loc + superblock->kvs_inode_table_offset), SEEK_SET);
    if (fread(buf, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        printf("write_dir(): error reading kvs_dinode: %s\n", strerror(errno));
        return 1;
    }

    // assume its the first inode in the block
    memcpy(&kvs_dinode, buf, sizeof(struct kvs_dinode));

    // printf("write_dir():found the kvs_inode for dir:\n");
    // printf("write_dir():data block number: %u\n", kvs_dinode.data_block);

    // read the root directory file block
    fseek(disk, BLOCKSIZE * (kvs_dinode.data_block + superblock->data_block_offset), SEEK_SET);
    if (fread(buf, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        printf("write_dir(): error reading dir file: %s\n", strerror(errno));
        return 1;
    }

    // search the directory for the last entry
    // printf("write_dir():searching directory...\n");
    while (true) {
        this_direct = (struct direct*)&buf[buf_off];
        if (this_direct->d_reclen == 0) {
            printf("write_dir(): corrupt directory\n");
            return -1;
        }
        if (buf_off + this_direct->d_reclen >= BLOCKSIZE - 1) {
            // found it
            printf("write_dir(): last entry in this dir: %s\n", this_direct->d_name);
            printf("write_dir(): last entry's length: %hu\n", this_direct->d_reclen);
            this_direct->d_reclen = 8 + this_direct->d_namlen + 1;
            this_direct->d_reclen += ((this_direct->d_reclen % 4) == 0) ? 0 : 4 - (this_direct->d_reclen % 4);
            buf_off += this_direct->d_reclen;
            printf("write_dir(): last entry's new length: %hu\n", this_direct->d_reclen);
            break;
        }
        buf_off += this_direct->d_reclen;
        if (buf_off >= BLOCKSIZE - 20) {    // let's be safe and not do anything near end of buffer
            printf("write_dir(): dir search failed\n");
            return -1;
        }
    }

    // insert the new entry
    if (buf_off + direct.d_reclen < BLOCKSIZE) {
        old_reclen      = direct.d_reclen;
        direct.d_reclen = BLOCKSIZE - buf_off;    // + 1 ??
        memcpy(&buf[buf_off], &direct, old_reclen);
        printf("write_dir(): new entry's length: %hu\n", direct.d_reclen);
        printf("write_dir(): new entry's name: %s\n", direct.d_name);

    } else {
        return -1;
    }

    // write it back to disk (don't bother rehashing)
    fseek(disk, BLOCKSIZE * (kvs_dinode.data_block + superblock->data_block_offset), SEEK_SET);
    if (fwrite(buf, sizeof(char), BLOCKSIZE, disk) != BLOCKSIZE) {
        perror("write_dir(): write dir file");
        return 1;
    }

    printf("write_dir(): SANITY CHECK: first entry: %s\n", ((struct direct*)buf)->d_name);

    // we didn't rehash, so dir dinode and kvs_inode stay the same
    return 0;
}
