// clang-format off
#ifndef _DDFS_H_
#define _DDFS_H_

#include "kvs.h"
#include "dir.h"

// clang-format on

// disk block size is 512B --- our block size is 4096 bytes
// 4096 / 512 = 8, so our logical block addr = disk_block_addr * 8
// AKA (logical_block << 3)
#define FSBTODB_SHIFT 3

// Convert our logical block numbers to device
#define fsbtodb(b) ((daddr_t)(b) << FSBTODB_SHIFT)

// the root of the filesystem (1 for now, because that's what ffs does)
#define DDFS_ROOT_INO 1

#ifdef _SYS_KERNEL_H_
MALLOC_DECLARE(M_DDFSNOPS);
MALLOC_DECLARE(M_DDFSNODE);
#endif

// IOCTL STUFF
typedef struct stats {
    uint32_t total_data_blocks;
    uint32_t used_data_blocks;
    uint64_t total_block_refs;
} stats;

#define STAT _IOR('d', 1, stats) /* get space saving stats */

// MACROS for superblock -------------------------------------
// 8% of disk reserved for file dinodes
#define RESERVED_INODE_SPACE_PERCENT .08f
#define STATIC_INODE_COUNT           2048
#define FILE_DINODES_PER_BLOCK       16
#define INODE_ALLOCATION_THRESHOLD   80

#define BLOCKSIZE 4096

// max length of the pathname for our fs
#define MAXMNTLEN 468    // size taken from ffs

// max length of the volume name (name of our fs)
#define MAXVOLLEN 32    // size taken from ffs

#define DDFSMAGIC 0x1337

#define HASH_TABLE_ENTRIES 65536

#define ENTRIES_PER_BITMAP_BLOCK    512
#define BITS_PER_BITMAP_ENTRY       64
#define DATABLOCKS_PER_BITMAP_BLOCK (ENTRIES_PER_BITMAP_BLOCK * BITS_PER_BITMAP_ENTRY)

#define HASH_BITMAP_ARRAY_SIZE 1024

#define SUPERBLOCK_PADDING 3544    // update this

// -------------------------------------------------------------

#define IFMT  0170000 /* Mask of file type. */
#define IFDIR 0040000 /* Directory file. */
#define IFREG 0100000 /* Regular file. */

#define HASH_KEYS_PER_INDIRECT_BLOCK 204
#define BLOCKS_FROM_DIRECT           3
#define BLOCKS_FROM_SINGLE_INDIRECT  207
#define BLOCKS_FROM_DOUBLE_INDIRECT  41823
#define BLOCKS_FROM_TRIPLE_INDIRECT  8531487

#define KVS_INODE_TABLE_SIZE   268435456    // 256 MiB
#define KVS_INODE_TABLE_BLOCKS 65536

// Offsets in terms of 4KiB blocks
#define SUPERBLOCK_OFF      0
#define HASH_BITMAP_OFF     1                        // 4KiB
#define KVS_INODE_TABLE_OFF (HASH_BITMAP_OFF + 2)    // 4KiB + 8KiB
#define FREE_BITMAP_OFF     (KVS_INODE_TABLE_OFF + KVS_INODE_TABLE_BLOCKS)

typedef int64_t ufs_time_t;

struct ddfs_sblock {
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
    uint32_t used_data_blocks;    // total number of used data blocks
    uint32_t used_file_inodes;    // total number of files inodes
    uint32_t used_kvs_inodes;     // total number of kvs inodes
    uint64_t total_block_refs;    // total number of references across all blocks
    uint8_t padding[3512];
};

#ifdef _SYS_KERNEL_H_
struct ddfs_mount {
    struct mount* mountp;                            // ptr to the mount struct
    struct ddfs_sblock superblock;                   // our in-memory superblock
    uint64_t hash_bitmap[HASH_BITMAP_ARRAY_SIZE];    // tracks which hash entries have >= 1 key
    struct g_consumer* consumer_geom;                // our fs geom
    struct bufobj* mnt_bufobj;                       //
    struct vnode* devvp;                             // vnode for char device mounted
    struct cdev* dev;                                // character device
};
#endif

// on-disk file inode structure
struct file_dinode {
    u_int16_t di_mode;       /*   0: IFMT, permissions; see below. */
    int16_t di_nlink;        /*   2: File link count. */
    u_int32_t di_uid;        /*   4: File owner. */
    u_int32_t di_gid;        /*   8: File group. */
    u_int32_t di_blksize;    /*  12: Inode blocksize. */
    u_int64_t di_size;       /*  16: File byte count. */
    u_int64_t di_blocks;     /*  24: Blocks actually held. */
    ufs_time_t di_atime;     /*  32: Last access time. */
    ufs_time_t di_mtime;     /*  40: Last modified time. */
    ufs_time_t di_ctime;     /*  48: Last inode change time. */
    ufs_time_t di_birthtime; /*  56: Inode creation time. */
    int32_t di_mtimensec;    /*  64: Last modified time. */
    int32_t di_atimensec;    /*  68: Last access time. */
    int32_t di_ctimensec;    /*  72: Last inode change time. */
    int32_t di_birthnsec;    /*  76: Inode creation time. */
    u_int32_t di_gen;        /*  80: Generation number. */
    u_int32_t di_kernflags;  /*  84: Kernel flags. */
    u_int32_t di_flags;      /*  88: Status flags (chflags). */
    u_int32_t di_extsize;    /*  92: External attributes size. */
    kvs_key di_db[3];        /* 112: Direct disk blocks. */
    kvs_key di_idb1;         // single indirect block pointer
    kvs_key di_idb2;         // double indirect block pointer
    kvs_key di_idb3;         // triple indirect block pointer
    u_int64_t di_modrev;     /* 232: i_modrev for NFSv4 */
    uint32_t di_freelink;    /* 240: SUJ: Next unlinked inode. */
    uint32_t di_ckhash;      /* 244: if CK_INODE, its check-hash */
    uint32_t di_spare[2];    /* 248: Reserved; currently unused */
};

/*
 * These flags are kept in i_flag.
 * copied from ffs inode
 */
#define IN_ACCESS      0x0001    /* Access time update request. */
#define IN_CHANGE      0x0002    /* Inode change time update request. */
#define IN_UPDATE      0x0004    /* Modification time update request. */
#define IN_MODIFIED    0x0008    /* Inode has been modified. */
#define IN_NEEDSYNC    0x0010    /* Inode requires fsync. */
#define IN_LAZYMOD     0x0020    /* Modified, but don't write yet. */
#define IN_LAZYACCESS  0x0040    // Process IN_ACCESS after the suspension finished
#define IN_EA_LOCKED   0x0080    /* Extended attributes locked */
#define IN_EA_LOCKWAIT 0x0100    /* Want extended attributes lock */
#define IN_TRUNCATED   0x0200    /* Journaled truncation pending. */
#define IN_UFS2        0x0400    /* UFS2 vs UFS1 */
#define IN_IBLKDATA    0x0800    // datasync requires inode block update
#define IN_SIZEMOD     0x1000    /* Inode size has been modified */
#define IN_ENDOFF      0x2000    // Free space at the end of directory, try to truncate when possible

// In-memory file inode
#ifdef _SYS_KERNEL_H_
struct file_inode {
    struct vnode* i_vnode;         // pointer to the parent vnode
    struct ddfs_mount* mnt;        // pointer to the mount for our fs
    struct file_dinode* dinode;    // actual on-disk inode

    uint32_t i_number;    // the inode's number
    u_int32_t i_flag;     /* flags, see below */

    /*
     * Side effects; used during directory lookup.
     */
    int32_t i_count; /* Size of free slot in directory. */
    doff_t i_endoff; /* End of useful stuff in directory. */
    doff_t i_diroff; /* Offset in dir, where we found last entry. */
    doff_t i_offset; /* Offset of free space in directory. */

    /*
     * Copies from the on-disk dinode itself.
     */
    u_int64_t i_size;  /* File byte count. */
    u_int64_t i_gen;   /* Generation number. */
    u_int32_t i_flags; /* Status flags (chflags). */
    u_int32_t i_uid;   /* File owner. */
    u_int32_t i_gid;   /* File group. */
    u_int16_t i_mode;  /* IFMT, permissions; see below. */
    int16_t i_nlink;   /* File link count. */
};
#endif

// Extract our internal mount struct from the kernel mount struct and return a ptr to it
#define VFSTODDFS(mp) ((struct ddfs_mount*)mp->mnt_data)

// Get file_inode from vnode
#define VTOI(vp) ((struct file_inode*)(vp)->v_data)

#define SET_I_OFFSET(dp, i_offset) (dp->i_offset = i_offset)
#define SET_I_COUNT(dp, cnt)       (dp->i_count = cnt)
#define I_OFFSET(dp)               (dp->i_offset)

// clang-format off
#define lblockno_from_ino(mnt, ino)     ((ino / FILE_DINODES_PER_BLOCK) \
                                          + mnt->superblock.file_inode_offset)

#define file_inode_block_offset(ino)    (ino % FILE_DINODES_PER_BLOCK)

#define byte_off_to_block_off(off)      (off / BLOCKSIZE)

#define offset_within_block(off)        (off % BLOCKSIZE)
// clang-format on

#endif
