// clang-format off
#ifndef _DDFS_KVS_H_
#define _DDFS_KVS_H_
#ifdef _SYS_KERNEL_H_   /* Only include these headers if its kernel code */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/mount.h>

#include <geom/geom.h>
#include <geom/geom_vfs.h>

#else
#include <stdint.h>
#endif

// clang-format on

/*
    Copied from asgn3 -- may need modifications -- some modifications already done
*/

#define INODE_PER_BLOCK_COUNT 102
#define INODE_KEY_LENGTH      20

#ifndef _SYS_KERNEL_H_
typedef unsigned char u_char;
#else
MALLOC_DECLARE(M_KVS_LAYER);
#endif

typedef struct kvs_key {
    u_char key[INODE_KEY_LENGTH];
} kvs_key;

// clang-format off
#define copy_hash_key(dest, src) (memcpy(dest, src, INODE_KEY_LENGTH))

// clang-format on

struct kvs_dinode {         // 40 bytes
    struct kvs_key key;     // the 160 bit (40 hex char) key for a block
    uint32_t data_block;    // block number of the data relative to the
                            // start of the data section
    uint64_t mod_time;      // last written time
    uint16_t ref_count;     // how many keys point to this block?
};

struct inode_list_block {
    struct kvs_dinode entries[INODE_PER_BLOCK_COUNT];    // list of inodes
    uint32_t next_block;                                 // data block number of the next block
    uint16_t entry_count;                                // how many entries are currently in the block
    char padding[10];
};

#ifdef _SYS_KERNEL_H_
struct kvs_node {                   // this node resides exclusively in memory
    struct kvs_dinode* inode;       // in-memory inode
    uint32_t inode_table_lblock;    // which logical block is the inode table located at
    uint32_t entry_index;           // which entry in the inode table is it
};

struct ddfs_mount;

/**
 * Have lower layer KVS write a 4KiB block to disk
 *
 * Needs block buffer to write, kvs_key hash to lookup, and ddfs mount pointer
 */
int kvs_write_block(char* block_buf, kvs_key* hash_key, struct ddfs_mount* mnt);

/**
 * Have lower layer KVS full a buffer with a 4KiB block referenced by hash_key
 */
int kvs_read_block(kvs_key* hash_key, struct buf** bpp, struct ddfs_mount* mnt);

/**
 * Have lower layer KVS return a kvs_node pointing to a block on disk if hash_key currently refers to a block
 *
 * Reuturns -1 if hash_key not found on disk
 */
int kvs_lookup_block(kvs_key* hash_key, struct kvs_node** node, struct ddfs_mount* mnt);

/**
 * Allocate a new block inode and write dinode to disk for a given hash_key
 *
 * NOTE: Does not zero out block on disk
 */
int kvs_create_block(kvs_key* hash_key, struct kvs_node** node, struct ddfs_mount* mnt);

/**
 * Remove reference to a data block with given hash key
 * If ref count drops to 0 for the data block, mark data block as free in free data block bitmap
 *
 * Return: 0 if successful, error number on error
 */
int kvs_remove_block(struct kvs_key* hash_key, struct ddfs_mount* mnt);

#endif
#endif
