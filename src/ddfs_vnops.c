// clang-format off
// not sure if we need all these - literally copied from FAT
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/ctype.h>
#include <sys/buf.h>
#include <sys/clock.h>
#include <sys/dirent.h>
#include <sys/lock.h>
#include <sys/lockf.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/unistd.h>
#include <sys/vmmeter.h>
#include <sys/vnode.h>
#include <sys/dirent.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vnode_pager.h>

#include <crypto/sha1.h>

#include "kvs.h"
#include "ddfs.h"
#include "dir.h"

/* 
 * Notes:
 *		Where do create vm backing object for vnodes? -- vfs_vget -- lookup..?
 * 
 * TODOS:
 *      - test reading and writing files from an offset
 *      - finish insert_key_into_inode() == only works for <= 828KB files
 *      - there are a lot of places where we're writing data to disk and 
 *        an error afterwards could cause us to lose track of the allocated
 *        blocks permanently
 */

// clang-format on

MALLOC_DEFINE(M_DDFSNOPS, "ddfs_nodeops", "DDFS node ops");

// default directory values -- taken from ufs_vnops
static struct dirtemplate mastertemplate = {
    0, 12, DT_DIR, 1, ".", 0, DIRBLKSIZ - 12, DT_DIR, 2, "..",
};

// extern int get_node(struct ddfs_mount* mnt, struct file_inode** node, uint32_t ino;
extern int ddfs_reclaim(struct vop_reclaim_args*);
extern int ddfs_lookup(struct vop_cachedlookup_args* ap);
extern int kvs_read_block(kvs_key* hash_key, struct buf** bpp, struct ddfs_mount* mnt);
extern int kvs_write_block(char* block_buf, kvs_key* hash_key, struct ddfs_mount* mnt);
extern int kvs_remove_block(kvs_key* hash_key, struct ddfs_mount* mnt);
extern int get_node(struct ddfs_mount* mnt, struct vnode** vpp, uint32_t ino);

static int
ddfs_direnter(struct vnode* dvp, struct vnode* tvp, struct direct* newdir, struct componentname* cnp);
static int ddfs_makedirentry(struct file_inode* ip, struct componentname* cnp, struct direct* newdir);
static int ddfs_readdir(struct vop_readdir_args* ap);
int initialize_new_inode(struct file_inode* ip);
int allocate_new_inode_block(struct ddfs_mount* mnt);
int get_hash_at_block_off(struct vnode* vp, uint32_t off, kvs_key* key);
int insert_key_into_inode(struct ddfs_mount* mnt, struct file_inode* dp, kvs_key* key, uint32_t* blkoff);
int get_hash_from_block(char* block_buf, kvs_key* key);

int
get_hash_from_block(char* block_buf, kvs_key* key) {
    struct sha1_ctxt sha1_st;
    SHA1Init(&sha1_st);
    SHA1Update(&sha1_st, block_buf, BLOCKSIZE);
    SHA1Final(key->key, &sha1_st);
    return 0;
}

/*
 * Initializes the directory with the name provided and sets the fields appropriately.
 */
static int
ddfs_makedirentry(struct file_inode* ip, struct componentname* cnp, struct direct* newdir) {
    if (ip->i_number <= 1) {
        return -1;
    }

    newdir->d_ino    = ip->i_number;
    newdir->d_namlen = cnp->cn_namelen;
    newdir->d_type   = IFTODT(ip->i_mode);
    newdir->d_reclen = STATIC_DIR_SIZE + newdir->d_namlen + 1;
    newdir->d_reclen += ((newdir->d_reclen % 4) == 0) ? 0 : 4 - (newdir->d_reclen % 4);
    memcpy(newdir->d_name, cnp->cn_nameptr, newdir->d_namlen + 1);

    return 0;
}

/*
 *  Insert an entry into the parent directory dvp
 *
 *  TODOS:
 *      need to convert the directory offset to a block offset
 *      so you can find out where the new key goes =>
 *      direct or indirect block, if indirect => allocate new one?
 *
 * Write a directory entry after a call to namei, using the parameters
 * that it left in nameidata. The argument dirp is the new directory
 * entry contents. Dvp is a pointer to the directory to be written,
 * which was left locked by namei. Remaining parameters (dp->i_offset,
 * dp->i_count) indicate how the space for the new entry is to be obtained.
 *
 * source: sys/ufs/ufs/ufs_lookup.c
 */
static int
ddfs_direnter(struct vnode* dvp, struct vnode* tvp, struct direct* dirp, struct componentname* cnp) {
    struct ddfs_mount* mnt = VFSTODDFS(dvp->v_mount);
    struct ucred* cr;
    struct thread* td;
    int newentrysize;
    struct file_inode* dp;
    struct buf* bp;
    u_int dsize;
    struct direct *ep, *nep;
    int error, loc, spacefree, namlen;
    char* dirbuf;
    char block_buf[BLOCKSIZE];
    uint32_t old_reclen;
    struct kvs_key hash_key;
    uint32_t dblock;
    uint32_t block_off;
    kvs_key dir_block_key;

    td = curthread; /* XXX */
    cr = td->td_ucred;

    dp           = VTOI(dvp);
    newentrysize = DIRSIZ(dirp);

    if (dp->i_count == 0) {
        /*
         * If dp->i_count is 0, then namei could find no
         * space in the directory. Here, dp->i_offset will
         * be on a directory block boundary and we will write the
         * new entry into a fresh block.
         */

        if (I_OFFSET(dp) & (DIRBLKSIZ - 1)) {
            // panic("ddffs_direnter: newblk");
            return -1;
        }

        // put the direntry in a fresh block
        old_reclen     = dirp->d_reclen;
        dirp->d_reclen = BLOCKSIZE;
        memset(block_buf, 0, BLOCKSIZE);
        memcpy(block_buf, dirp, old_reclen);

        // get the hash key
        get_hash_from_block(block_buf, &hash_key);

        // write the new block to disk
        error = kvs_write_block(block_buf, &hash_key, mnt);
        if (error)
            return error;

        // need to insert the key into the inode
        error = insert_key_into_inode(mnt, dp, &hash_key, NULL);
        if (error) {
            return error;
        }

        // update the directory's inode
        dp->i_size          = I_OFFSET(dp) + DIRBLKSIZ;
        dp->dinode->di_size = dp->i_size;
        dp->i_endoff        = dp->i_size;
        dp->i_flag |= IN_SIZEMOD | IN_CHANGE | IN_UPDATE;

        // read in the dinode block from disk and copy updated inode into it
        dblock = fsbtodb(lblockno_from_ino(mnt, dp->i_number));
        error  = bread(mnt->devvp, dblock, BLOCKSIZE, NOCRED, &bp);
        if (error) {
            return error;
        }
        memcpy(bp->b_data + (file_inode_block_offset(dp->i_number) * sizeof(struct file_dinode)),
               dp->dinode,
               sizeof(struct file_dinode));

        // write the dinode to disk
        error = bwrite(bp);
        if (error)
            brelse(bp);
        return (error);
    }

    /*
     * If dp->i_count is non-zero, then namei found space for the new
     * entry in the range dp->i_offset to dp->i_offset + dp->i_count
     * in the directory. To use this space, we may have to compact
     * the entries located there, by copying them together towards the
     * beginning of the block, leaving the free space in one usable
     * chunk at the end.
     */

    /*
     * Get the block containing the space for the new directory entry.
     */
    block_off = dp->i_offset / BLOCKSIZE;
    error     = get_hash_at_block_off(dvp, block_off, &dir_block_key);
    if (error)
        return error;
    error = kvs_read_block(&dir_block_key, &bp, mnt);
    if (error) {
        return (error);
    }
    dirbuf = (char*)bp->b_data;
    /*
     * Find space for the new entry. In the simple case, the entry at
     * offset base will have the space. If it does not, then namei
     * arranged that compacting the region dp->i_offset to
     * dp->i_offset + dp->i_count would yield the space.
     */
    ep        = (struct direct*)dirbuf;
    dsize     = ep->d_ino ? DIRSIZ(ep) : 0;
    spacefree = ep->d_reclen - dsize;
    for (loc = ep->d_reclen; loc < dp->i_count;) {
        nep = (struct direct*)(dirbuf + loc);

        /* Trim the existing slot (NB: dsize may be zero). */
        ep->d_reclen = dsize;
        ep           = (struct direct*)((char*)ep + dsize);

        /* Read nep->d_reclen now as the bcopy() may clobber it. */
        loc += nep->d_reclen;
        if (nep->d_ino == 0) {
            /*
             * A mid-block unused entry. Such entries are
             * never created by the kernel, but fsck_ffs
             * can create them (and it doesn't fix them).
             *
             * Add up the free space, and initialise the
             * relocated entry since we don't bcopy it.
             */
            spacefree += nep->d_reclen;
            ep->d_ino = 0;
            dsize     = 0;
            continue;
        }
        dsize = DIRSIZ(nep);
        spacefree += nep->d_reclen - dsize;

        bcopy((caddr_t)nep, (caddr_t)ep, dsize);    // idk if this works
    }
    /*
     * Here, `ep' points to a directory entry containing `dsize' in-use
     * bytes followed by `spacefree' unused bytes. If ep->d_ino == 0,
     * then the entry is completely unused (dsize == 0). The value
     * of ep->d_reclen is always indeterminate.
     *
     * Update the pointer fields in the previous entry (if any),
     * copy in the new entry, and write out the block.
     */

    namlen = ep->d_namlen;

    if (ep->d_ino == 0
        || (ep->d_ino == DDFS_ROOT_INO && namlen == dirp->d_namlen
            && bcmp(ep->d_name, dirp->d_name, dirp->d_namlen) == 0)) {
        if (spacefree + dsize < newentrysize)
            panic("ddfs_direnter: compact1");
        dirp->d_reclen = spacefree + dsize;
    } else {
        if (spacefree < newentrysize)
            panic("ddfs_direnter: compact2");
        dirp->d_reclen = spacefree;
        ep->d_reclen   = dsize;
        ep             = (struct direct*)((char*)ep + dsize);
    }

    bcopy((caddr_t)dirp, (caddr_t)ep, (u_int)newentrysize);

    error = bwrite(bp);

    /*
     * If all went well, and the directory can be shortened,
     * mark directory inode with the truncation request.
     */
    dp->i_flag |= IN_CHANGE | IN_UPDATE
                  | (error == 0 && dp->i_endoff != 0 && dp->i_endoff < dp->i_size ? IN_ENDOFF : 0);

    return (error);
}

/*
    Returns the hash key that points to the data block at the provided offset in
    the inode associated with vp. Currently, this function performs no validation checking
    on the keys. It is assumed that they exist as long as off < di_blocks.

    The math here is extremely disgusting. Try not to look.

    This function works for the direct blocks.
    Indirect block access is currently untested.
 */
int
get_hash_at_block_off(struct vnode* vp, uint32_t off, kvs_key* key) {
    struct file_inode* dp  = VTOI(vp);
    struct ddfs_mount* mnt = dp->mnt;
    kvs_key indirect_key;
    int error;
    struct buf* bp;
    uint32_t indir_off;

    if (off >= dp->dinode->di_blocks || dp->dinode->di_blocks == 0) {
        // return -1;
        // set key to 0 so that key is equal to null key
        memset(&(key->key), 0, INODE_KEY_LENGTH);
        return (0);
    }

    if (off < BLOCKS_FROM_DIRECT && off < dp->dinode->di_blocks) {
        copy_hash_key(key, &dp->dinode->di_db[off]);
    } else if (off < BLOCKS_FROM_SINGLE_INDIRECT && off < dp->dinode->di_blocks) {
        copy_hash_key(&indirect_key, &dp->dinode->di_idb1);
        error = kvs_read_block(&indirect_key, &bp, mnt);
        if (error) {
            return error;
        }
        indir_off = (off - BLOCKS_FROM_DIRECT) * sizeof(kvs_key);
        copy_hash_key(key, (kvs_key*)(bp->b_data + indir_off));
        brelse(bp);
    } else if (off < BLOCKS_FROM_DOUBLE_INDIRECT && off < dp->dinode->di_blocks) {
        copy_hash_key(&indirect_key, &dp->dinode->di_idb2);
        error = kvs_read_block(&indirect_key, &bp, mnt);
        if (error) {
            return error;
        }

        // fetch the double indirect block
        indir_off = ((off - BLOCKS_FROM_SINGLE_INDIRECT) / HASH_KEYS_PER_INDIRECT_BLOCK) * sizeof(kvs_key);
        copy_hash_key(&indirect_key, (kvs_key*)(bp->b_data + indir_off));
        brelse(bp);
        error = kvs_read_block(&indirect_key, &bp, mnt);
        if (error) {
            return error;
        }

        // get the key
        indir_off = ((off - BLOCKS_FROM_SINGLE_INDIRECT) % HASH_KEYS_PER_INDIRECT_BLOCK) * sizeof(kvs_key);
        copy_hash_key(key, (kvs_key*)(bp->b_data + indir_off));
        brelse(bp);
    } else if (off < BLOCKS_FROM_TRIPLE_INDIRECT && off < dp->dinode->di_blocks) {
        copy_hash_key(&indirect_key, &dp->dinode->di_idb3);
        error = kvs_read_block(&indirect_key, &bp, mnt);
        if (error) {
            return error;
        }

        // fetch the double indirect block
        indir_off = ((off - BLOCKS_FROM_DOUBLE_INDIRECT) /    //
                     (HASH_KEYS_PER_INDIRECT_BLOCK * HASH_KEYS_PER_INDIRECT_BLOCK))
                    * sizeof(kvs_key);
        copy_hash_key(&indirect_key, (kvs_key*)(bp->b_data + indir_off));
        brelse(bp);
        error = kvs_read_block(&indirect_key, &bp, mnt);
        if (error) {
            return error;
        }

        // fetch the triple indirect block
        indir_off = (((off - BLOCKS_FROM_DOUBLE_INDIRECT) %    //
                      (HASH_KEYS_PER_INDIRECT_BLOCK * HASH_KEYS_PER_INDIRECT_BLOCK))
                     / 204)
                    * sizeof(kvs_key);
        copy_hash_key(&indirect_key, (kvs_key*)(bp->b_data + indir_off));
        brelse(bp);
        error = kvs_read_block(&indirect_key, &bp, mnt);
        if (error) {
            return error;
        }

        // get the key
        indir_off = ((off - BLOCKS_FROM_DOUBLE_INDIRECT) %    //
                     (HASH_KEYS_PER_INDIRECT_BLOCK))
                    * sizeof(kvs_key);
        copy_hash_key(&indirect_key, (kvs_key*)(bp->b_data + indir_off));

        brelse(bp);
    } else {
        return -1;
    }

    for (int i = 0; i < INODE_KEY_LENGTH; i++) {
    }

    return 0;
}

/*
 * Insert a key into the dinode at the next available slot. It is the caller's
 * reponsibility to write the dinode back to disk for persistence.
 *
 * The argument blkoff indicates where to insert the key
 *      - pass NULL to insert at the end of the file
 *
 * IMPORTANTLY, this function does NOT alter the file size -- it will however
 * alter di_blocks (block count of inode)
 *
 * TODOS:
 *      I was too lazy to implement inserting keys into more than a single
 *      indirect block -- for the time being, this should be fine. We can
 *      at least start testing files <= 828 KB.
 *
 *
 * Algorithm:
 *      - calculate the block offset from di_blocks
 *      - calculate which of di_db, di_idb1, di_idb2, di_idb3 should be used
 *      - see if the needed block (if indirect) already exists
 *      - if not => allocate it
 *      - otherwise, insert the key into the slot
 */
int
insert_key_into_inode(struct ddfs_mount* mnt, struct file_inode* dp, kvs_key* key, uint32_t* blkoff) {
    kvs_key indirect_key;
    int error;
    struct buf* bp;
    struct file_dinode* dinode = dp->dinode;
    kvs_key null_key           = {};
    kvs_key new_key            = {};
    kvs_key* key_from_buf      = NULL;
    char block_buf[BLOCKSIZE];
    int indir_off;
    uint32_t block_off     = blkoff == NULL ? dinode->di_blocks : *blkoff;
    uint32_t new_block_cnt = dinode->di_blocks;

    if (block_off < 3) {
        // offset is small enough to put the new block in direct block
        if (memcmp(&dinode->di_db[block_off].key, &null_key.key, INODE_KEY_LENGTH) == 0) {
            new_block_cnt++;
        }
        copy_hash_key(&dinode->di_db[block_off], key);
        dinode->di_blocks = new_block_cnt;
    } else if (block_off < BLOCKS_FROM_SINGLE_INDIRECT) {
        // the new key goes in the indirect block

        // if the indirect block is NULL, we need to allocate it
        if (memcmp(&dinode->di_idb1.key, &null_key.key, INODE_KEY_LENGTH) == 0) {
            memset(block_buf, 0, BLOCKSIZE);
            memcpy(block_buf, key, INODE_KEY_LENGTH);
            get_hash_from_block(block_buf, &new_key);
            error = kvs_write_block(block_buf, &new_key, mnt);
            if (error) {
                return error;
            }
            copy_hash_key(&dp->dinode->di_idb1, &new_key);
            new_block_cnt++;
            dinode->di_blocks = new_block_cnt;
        } else {
            // else we can just insert the key into the existing indirect block

            // read in the indirect block
            copy_hash_key(&indirect_key, &dinode->di_idb1);
            error = kvs_read_block(&indirect_key, &bp, mnt);
            if (error) {
                return error;
            }
            memcpy(block_buf, bp->b_data, BLOCKSIZE);
            brelse(bp);

            // update it
            indir_off    = (block_off - BLOCKS_FROM_DIRECT) * sizeof(kvs_key);
            key_from_buf = (kvs_key*)(block_buf + indir_off);
            if (memcmp(&key_from_buf->key, &null_key.key, INODE_KEY_LENGTH) == 0) {
                new_block_cnt++;
            }
            copy_hash_key(key_from_buf, key);

            // remove the old indirect block
            error = kvs_remove_block(&indirect_key, mnt);
            if (error)
                return error;

            // write the new updated indirect block
            get_hash_from_block(block_buf, &indirect_key);
            error = kvs_write_block(block_buf, &indirect_key, mnt);
            if (error)
                return error;

            copy_hash_key(&dp->dinode->di_idb1, &indirect_key);
            dinode->di_blocks = new_block_cnt;
        }

    }    // else if (dp->dinode->di_blocks < BLOCKS_FROM_DOUBLE_INDIRECT) {
    //     // this is a big file, we need to insert into an indirect block now
    //     copy_hash_key(&indirect_key, &dp->dinode->di_idb2);
    //     error = kvs_read_block(&indirect_key, &bp, mnt);
    //     if (error) {
    //         return error;
    //     }

    //     // fetch the double indirect block
    //     indir_off = (off - BLOCKS_FROM_SINGLE_INDIRECT) / HASH_KEYS_PER_INDIRECT_BLOCK;
    //     copy_hash_key(&indirect_key, (kvs_key*)(bp->b_data + indir_off));
    //     brelse(bp);
    //     error = kvs_read_block(&indirect_key, &bp, mnt);
    //     if (error) {
    //         return error;
    //     }

    //     // get the key
    //     indir_off = (off - BLOCKS_FROM_SINGLE_INDIRECT) % HASH_KEYS_PER_INDIRECT_BLOCK;
    //     copy_hash_key(key, (kvs_key*)(bp->b_data + indir_off));
    //     brelse(bp);
    // } else if (off < BLOCKS_FROM_TRIPLE_INDIRECT && off < dp->dinode->di_blocks) {
    //     copy_hash_key(&indirect_key, &dp->dinode->di_idb3);
    //     error = kvs_read_block(&indirect_key, &bp, mnt);
    //     if (error) {
    //         return error;
    //     }

    //     // fetch the double indirect block
    //     indir_off = (off - BLOCKS_FROM_DOUBLE_INDIRECT) /    //
    //                 (HASH_KEYS_PER_INDIRECT_BLOCK * HASH_KEYS_PER_INDIRECT_BLOCK);
    //     copy_hash_key(&indirect_key, (kvs_key*)(bp->b_data + indir_off));
    //     brelse(bp);
    //     error = kvs_read_block(&indirect_key, &bp, mnt);
    //     if (error) {
    //         return error;
    //     }

    //     // fetch the triple indirect block
    //     indir_off = ((off - BLOCKS_FROM_DOUBLE_INDIRECT) %    //
    //                  (HASH_KEYS_PER_INDIRECT_BLOCK * HASH_KEYS_PER_INDIRECT_BLOCK))
    //                 / 204;
    //     copy_hash_key(&indirect_key, (kvs_key*)(bp->b_data + indir_off));
    //     brelse(bp);
    //     error = kvs_read_block(&indirect_key, &bp, mnt);
    //     if (error) {
    //         return error;
    //     }

    //     // get the key
    //     indir_off = (off - BLOCKS_FROM_DOUBLE_INDIRECT) %    //
    //                 (HASH_KEYS_PER_INDIRECT_BLOCK);
    //     copy_hash_key(&indirect_key, (kvs_key*)(bp->b_data + indir_off));

    //     brelse(bp);
    // } else {
    //     return -1;
    // }
    else {
        return -1;
    }
    for (int i = 0; i < INODE_KEY_LENGTH; i++) {
    }
    return 0;
}

/*
 * Checks if our current number of used inodes exceeds the threshold as
 * defined in ddfs.h under INODE_ALLOCATION_THRESHOLD. If it does, then
 * it allocates a new inode block and updates the superblock's last_alloc_finod_blk
 * field. It then linearly searches through the bitmap blocks until it finds a free
 * bit, which it then updates and writes back to disk. The superblock's last_used_finode_blk
 * field will be updated if we can't find a free space in the current block.
 */
static int
find_free_inode(struct ddfs_mount* mnt, uint32_t* inode_number) {
    struct vnode* devvp = mnt->devvp;
    struct buf* bp;
    struct ddfs_sblock* sblock = &mnt->superblock;
    uint32_t bitmap_off        = sblock->finode_bitmap_offset;
    uint32_t bitmap_blocks     = sblock->file_inode_offset - sblock->finode_bitmap_offset;
    uint32_t allocated_inodes  = FILE_DINODES_PER_BLOCK * (sblock->last_alloc_finode_blk + 1);
    // Get block number of bitmap relative to offset
    uint32_t bitmap_block =
        ((sblock->last_used_finode_blk + 1) * FILE_DINODES_PER_BLOCK) / DATABLOCKS_PER_BITMAP_BLOCK;
    uint32_t threshold;

    // Check if we need to allocate a new inode block
    // This is some hacky shit because we don't get floats in the kernel
    threshold = (INODE_ALLOCATION_THRESHOLD * allocated_inodes) / 100;
    if (sblock->used_file_inodes >= threshold) {
        allocate_new_inode_block(mnt);
    }

    uint32_t bitmap_lblock_no, bitmap_dblock_no;
    uint32_t current_datablock_number;
    int error;
    int found_block = 0;

    while (!found_block) {
        if (bitmap_block > bitmap_blocks) {
            bitmap_block             = 0;
            current_datablock_number = 0;
        }

        bitmap_lblock_no = bitmap_block + bitmap_off;
        bitmap_dblock_no = fsbtodb(bitmap_lblock_no);

        error = bread(devvp, bitmap_dblock_no, BLOCKSIZE, NOCRED, &bp);
        if (error) {
            return error;
        }
        uint64_t* bitmap = (uint64_t*)bp->b_data;

        current_datablock_number = bitmap_block * DATABLOCKS_PER_BITMAP_BLOCK;

        int bitmap_entry;
        int bit_index;

        for (bitmap_entry = 0;
             bitmap_entry < ENTRIES_PER_BITMAP_BLOCK && current_datablock_number < allocated_inodes;
             bitmap_entry++) {
            for (bit_index = 0;
                 bit_index < BITS_PER_BITMAP_ENTRY && current_datablock_number < allocated_inodes;
                 bit_index++) {
                if (current_datablock_number != DDFS_ROOT_INO) {
                    if ((bitmap[bitmap_entry] & (1 << bit_index)) == 0) {
                        found_block = 1;
                        bitmap[bitmap_entry] |= (1 << bit_index);
                        error = bwrite(bp);
                        if (error) {
                            brelse(bp);
                            return error;
                        }
                        break;
                    }
                }
                current_datablock_number++;
            }
            if (found_block) {
                break;
            }
            brelse(bp);
        }
        // Couldn't find a free inode in current bitmap block. Go to next and possibly
        // wrap around
        bitmap_block++;
    }

    // TODO: Writeback superblock, maybe update last_used_finode_blk as well
    sblock->last_used_finode_blk = (current_datablock_number / FILE_DINODES_PER_BLOCK);

    if (found_block == 0) {
        return -1;
    }

    *inode_number = current_datablock_number;
    return 0;
}

/*
 * Initialzes a new regular file inode.
 * Should be called after get_node()
 */
int
initialize_new_inode(struct file_inode* ip) {
    struct timespec ts;
    vfs_timestamp(&ts);

    ip->i_size  = 0;
    ip->i_mode  = IFREG | 0766;
    ip->i_nlink = 1;

    ip->dinode->di_mode      = IFREG | 0766;
    ip->dinode->di_nlink     = 1;
    ip->dinode->di_size      = 0;
    ip->dinode->di_birthtime = ts.tv_sec;
    ip->dinode->di_birthnsec = ts.tv_nsec;
    ip->dinode->di_mtime     = ts.tv_sec;
    ip->dinode->di_mtimensec = ts.tv_nsec;

    return 0;
}

/*
 * Initializes new block of inodes, updates inode information
 * in superblock.
 * This should be called after checking the current capacity.
 * TODO: Writeback superblock
 */
int
allocate_new_inode_block(struct ddfs_mount* mnt) {
    struct vnode* devvp = mnt->devvp;
    struct buf* bp;
    struct ddfs_sblock sblock = mnt->superblock;
    uint32_t current_block    = sblock.last_alloc_finode_blk;
    uint32_t lblock_no, dblock_no;
    int error = 0;

    // TODO: Make sure we don't overwrite stuff, e.g. current_block + 1 doesn't overstep bounds
    uint32_t new_block = current_block + 1;
    lblock_no          = new_block + sblock.file_inode_offset;
    dblock_no          = fsbtodb(lblock_no);
    error              = bread(devvp, dblock_no, BLOCKSIZE, NOCRED, &bp);
    if (error) {
        return -1;
    }

    memset(bp->b_data, 0, BLOCKSIZE);
    bwrite(bp);
    // TODO: Writeback superblock
    sblock.last_alloc_finode_blk += 1;

    return 0;
}

static int
ddfs_create(struct vop_create_args* ap) {
    struct vnode* devvp = NULL;
    struct vnode* dvp   = ap->a_dvp;
    struct vnode* new_vp;
    struct componentname* cnp = ap->a_cnp;
    struct file_inode *ip, *dp;
    struct ddfs_mount* mnt;
    struct direct newdir;
    uint32_t new_inode_number;
    uint32_t data_lblock_no;
    uint32_t data_dblock_no;
    int error;
    struct buf* bp;

    mnt   = VFSTODDFS(dvp->v_mount);
    devvp = mnt->devvp;
    dp    = VTOI(dvp);

    // TODO: Check if we need to allocate a new inode block
    /*
     * if we need to allocate new inode block:
     * 	 allocate_new_inode_block(mnt);
     */
    find_free_inode(mnt, &new_inode_number);

    if (get_node(mnt, &new_vp, new_inode_number) != 0) {
    }

    // Read in the block containing our inode
    data_lblock_no = lblockno_from_ino(mnt, new_inode_number);
    data_dblock_no = fsbtodb(data_lblock_no);
    error          = bread(devvp, data_dblock_no, BLOCKSIZE, NOCRED, &bp);
    if (error) {
    }
    // We have our 4K block, now we not to offset into it to found our inode
    int offset = file_inode_block_offset(new_inode_number) * sizeof(struct file_dinode);

    // Set up new regular file inode
    ip = VTOI(new_vp);
    initialize_new_inode(ip);

    // set the owner
    ip->i_uid          = cnp->cn_cred->cr_uid;
    ip->dinode->di_uid = ip->i_uid;

    memcpy(bp->b_data + offset, ip->dinode, sizeof(struct file_dinode));
    bwrite(bp);
    bp = NULL;

    ddfs_makedirentry(ip, cnp, &newdir);

    ddfs_direnter(dvp, new_vp, &newdir, cnp);

    *(ap->a_vpp) = new_vp;
    return 0;
}

/*
    Algorithm:
        while more data requested and not at EOF:
            hash_key = get next kvs_key from inode
            kvs_read_block (hash_key, bp)
            uiomove(uio, buf)
            brelse(bp)
 */
static int
ddfs_read(struct vop_read_args* ap)
/*
    struct vop_read_args {
        struct vop_generic_args a_gen;
        struct vnode* a_vp;
        struct uio* a_uio;
        int a_ioflag;
        struct ucred* a_cred;
    }
*/
{
    struct vnode* vp         = ap->a_vp;
    struct file_inode* inode = (struct file_inode*)vp->v_data;
    struct mount* mp         = vp->v_mount;
    struct ddfs_mount* mnt   = (struct ddfs_mount*)mp->mnt_data;
    struct uio* uio          = ap->a_uio;
    struct buf* bp           = NULL;
    // int ioflag = ap->a_ioflag;
    int error = 0;
    struct kvs_key key;
    uint64_t offset = uio->uio_offset;
    int amount;
    int remaining;

    // return failure if the vnode is a directory?
    if (vp->v_type == VDIR) {
        return EISDIR;
    }

    // return if they requested no data
    if (uio->uio_resid == 0) {
        return 0;
    }

    // transfer data as long as it is available
    while (uio->uio_resid > 0 && offset < inode->i_size) {
        get_hash_at_block_off(vp, (uint32_t)byte_off_to_block_off(offset), &key);

        error = kvs_read_block(&key, &bp, mnt);
        if (error) {
            return EJUSTRETURN;
        }

        remaining = (inode->i_size - offset) >= BLOCKSIZE
                        ? BLOCKSIZE - offset_within_block(offset)
                        : offset_within_block(inode->i_size) - offset_within_block(offset);
        amount    = MIN(uio->uio_resid, remaining);
        error     = uiomove(bp->b_data + offset_within_block(offset), amount, uio);
        if (error) {
            return EJUSTRETURN;
        }
        brelse(bp);

        offset += amount;
    }

    return 0;
}

/**
 * .vop_write() handler
 * Handles write to ddfs
 *
 * Algorithm:
 *  While more data to copy from user
 *      copy old data block if not writing full datablock at file offset
 *      Then copy data and hash it
 *      if hash is same as old block, continue to next amount to copy
 *      else, write to disk with kvs_write_block
 *      Remove the old hash from disk and update dinode
 *
 * Sources:
 * /sys/ufs/ffs/ffs_vnops.c & /sys/fs/msdosfs/msdosfs_vnops.c
 */
static int
ddfs_write(struct vop_write_args* ap) {
    /*
        struct vop_write_args {
            struct vnode* a_vp
            struct uio* a_uio
            int a_ioflag
            struct ucred* a_cred
        }
    */

    struct vnode* vp;
    struct uio* uio;
    struct buf* bp;
    struct ddfs_mount* mnt;
    struct file_inode* ip;
    char block_buf[BLOCKSIZE];
    struct kvs_key old_hash;
    struct kvs_key new_hash;
    struct kvs_key null_key = {};
    struct timespec ts;
    uint32_t blkoffset, xfersize, inode_dblock;
    bool same_hash;
    int error;

    vp    = ap->a_vp;
    ip    = VTOI(vp);
    uio   = ap->a_uio;
    mnt   = (struct ddfs_mount*)vp->v_mount->mnt_data;
    bp    = NULL;
    error = 0;

    /* Perform error checks before beginning write */
    if (vp == NULL || vp->v_data == NULL) {
        return (EBADF);
    }
    if (vp->v_type == VDIR) {
        return (EISDIR);
    }
    if (uio->uio_resid <= 0) {
        return (0);
    }
    if (uio->uio_offset + uio->uio_resid > 34944970752) {
        // lol
        return (EFBIG);
    }

    // get time now so we don't have to query it for every uiomove
    vfs_timestamp(&ts);

    /* Keep writing blocks while there is more data */
    for (error = 0; uio->uio_resid > 0;) {
        error = get_hash_at_block_off(vp, (uio->uio_offset / BLOCKSIZE), &old_hash);
        if (error) {
            return (EJUSTRETURN);
        }

        // if the block has been previously written by this file, and we're not overwriting the whole block
        // copy the old block in first so the unchanging data gets written back
        if ((memcmp(&null_key.key, &old_hash.key, INODE_KEY_LENGTH) != 0)
            && ((uio->uio_offset % BLOCKSIZE) != 0 || uio->uio_resid < BLOCKSIZE)) {
            // copy existing block first
            //
            // if existing value in block doesn't fill entire block, assuming remaining amount of block has
            // been zeroed
            error = kvs_read_block(&old_hash, &bp, mnt);
            if (error) {
                return (EJUSTRETURN);
            }
            memcpy(block_buf, bp->b_data, BLOCKSIZE);
            brelse(bp);
            bp = NULL;
        } else {
            memset(block_buf, 0, BLOCKSIZE);
        }

        /**
         * How much to copy on each mov vopied from ffs .vop_write
         * /sys/ufs/ffs/ffs_vnops.c
         *
         * Seems over complicated...
         * Possibly just change to: resid > blocksize ? xfersize = blocksize : xfersize = resid
         */
        blkoffset = uio->uio_offset % BLOCKSIZE;
        xfersize  = BLOCKSIZE - blkoffset;
        if (uio->uio_resid < xfersize) {
            xfersize = uio->uio_resid;
        }

        /**
         * NOTE: I updated file size here because ffs did
         * design doc stated to update file size at the end but I figured you couldn't exceed the current file
         * size with an incoming write AND have the incoming write be the same as an already written block...
         *
         * If we're past the current file size old_hash should be NULL
         */
        if (uio->uio_offset + xfersize > ip->i_size) {
            // update file size
            ip->i_size = uio->uio_offset + xfersize;
        }

        error = uiomove((char*)block_buf + blkoffset, xfersize, uio);
        if (error) {
            return (EJUSTRETURN);
        }

        get_hash_from_block(block_buf, &new_hash);

        /* if the hash of the old block and new data are the same, don't need to overwrite */
        same_hash = true;
        if (memcmp(&null_key.key, &old_hash.key, INODE_KEY_LENGTH) != 0) {
            for (int i = 0; i < INODE_KEY_LENGTH; i++) {
                if (old_hash.key[i] != new_hash.key[i]) {
                    same_hash = false;
                    break;
                }
            }
        } else {
            same_hash = false;
        }

        if (same_hash) {
            continue;
        }

        /* blocks found to be different */
        error = kvs_write_block(block_buf, &new_hash, mnt);
        if (error) {
            return (EJUSTRETURN);
        }

        /* if we've made it to here, we've overwritten the old block so remove it and update the inode hash*/
        if (memcmp(&null_key.key, &old_hash.key, INODE_KEY_LENGTH) != 0) {
            error = kvs_remove_block(&old_hash, mnt);
            if (error) {
                return (EJUSTRETURN);
            }
        }

        // update dinode hash for this file offset
        // if we're writing a new block, insert to end of file instead
        uint32_t file_blk_offset = uio->uio_offset / BLOCKSIZE;
        if (memcmp(&null_key.key, &old_hash.key, INODE_KEY_LENGTH) != 0) {
            error = insert_key_into_inode(mnt, ip, &new_hash, &file_blk_offset);
        } else {
            error = insert_key_into_inode(mnt, ip, &new_hash, NULL);
        }
        if (error) {
            return (EJUSTRETURN);
        }

        /* Write updated dinode back to disk */
        ip->dinode->di_size      = ip->i_size;
        ip->dinode->di_mtime     = ts.tv_sec;
        ip->dinode->di_mtimensec = ts.tv_nsec;

        inode_dblock = fsbtodb(lblockno_from_ino(mnt, ip->i_number));
        error        = bread(mnt->devvp, inode_dblock, BLOCKSIZE, NOCRED, &bp);
        if (error) {
            return error;
        }
        memcpy(bp->b_data + (file_inode_block_offset(ip->i_number) * sizeof(struct file_dinode)),
               ip->dinode,
               sizeof(struct file_dinode));
        // write the dinode to disk
        error = bwrite(bp);
        if (error) {
            brelse(bp);
            return (error);
        }

        bp = NULL;
    }

    return (0);
}

/*
 *
 * source: sys/ufs/ufs/ufs_vnops.c (ufs_mkdir)
 *
 * TODOS:
 *      - we're using ffs's flags in here and I don't think we need them
 */
static int
ddfs_mkdir(struct vop_mkdir_args* ap)
/* {
    struct vnode *a_dvp;
    struct vnode **a_vpp;
    struct componentname *a_cnp;
    struct vattr *a_vap;
} */
{
    struct vnode* dvp         = ap->a_dvp;
    struct vattr* vap         = ap->a_vap;
    struct componentname* cnp = ap->a_cnp;
    struct ddfs_mount* mnt    = VFSTODDFS(dvp->v_mount);
    struct file_inode *ip, *dp;
    struct vnode* tvp;
    struct buf* bp;
    struct dirtemplate dirtemplate;
    struct direct newdir;
    kvs_key new_dir_key;
    char block_buf[BLOCKSIZE];
    int error, dmode;
    uint32_t dblock;
    uint32_t new_ino;

    dp = VTOI(dvp);
    // if (dp->i_nlink >= UFS_LINK_MAX) {
    //     error = EMLINK;
    //     goto out;
    // }
    dmode = vap->va_mode & 0777;
    dmode |= IFDIR;

    /*
     * Must simulate part of ufs_makeinode here to acquire the inode,
     * but not have it entered in the parent directory. The entry is
     * made later after writing "." and ".." entries.
     */
    // if (dp->i_effnlink < 2) {
    //     error = EINVAL;
    //     goto out;
    // }

    // find an inode for the new directory
    error = find_free_inode(mnt, &new_ino);
    if (error) {
        error = EJUSTRETURN;
        goto out;
    }

    // get an inode + vnode for it
    error = get_node(mnt, &tvp, new_ino);
    if (error) {
        error = EJUSTRETURN;
        goto out;
    }

    vn_seqc_write_begin(tvp);    // i have no idea what this does and I can't find an answer
                                 // think it might let the system know the vnode is being modified
    ip = VTOI(tvp);
    initialize_new_inode(ip);
    ip->i_gid          = dp->i_gid;
    ip->dinode->di_gid = dp->i_gid;
#ifdef SUIDDIR
    {
        /*
         * If we are hacking owners here, (only do this where told to)
         * and we are not giving it TO root, (would subvert quotas)
         * then go ahead and give it to the other user.
         * The new directory also inherits the SUID bit.
         * If user's UID and dir UID are the same,
         * 'give it away' so that the SUID is still forced on.
         */
        if ((dvp->v_mount->mnt_flag & MNT_SUIDDIR) && (dp->i_mode & ISUID) && dp->i_uid) {
            dmode |= ISUID;
            ip->i_uid          = dp->i_uid;
            ip->dinode->di_uid = dp->i_uid;

        } else {
            ip->i_uid          = cnp->cn_cred->cr_uid;
            ip->dinode->di_uid = ip->i_uid;
        }
    }
#else /* !SUIDDIR */
    ip->i_uid          = cnp->cn_cred->cr_uid;
    ip->dinode->di_uid = ip->i_uid;

#endif /* !SUIDDIR */

    ip->i_flag |= IN_ACCESS | IN_CHANGE | IN_UPDATE;
    ip->i_mode           = dmode;
    ip->dinode->di_mode  = dmode;
    tvp->v_type          = VDIR; /* Rest init'd in getnewvnode(). */
    ip->i_nlink          = 2;
    ip->dinode->di_nlink = 2;

    if (cnp->cn_flags & ISWHITEOUT) {
        ip->i_flags |= UF_OPAQUE;
        ip->dinode->di_flags = ip->i_flags;
    }

    /*
     * Bump link count in parent directory to reflect work done below.
     * Should be done before reference is created so cleanup is
     * possible if we crash.
     */
    dp->i_nlink++;
    dp->dinode->di_nlink = dp->i_nlink;
    dp->i_flag |= IN_CHANGE;
    dp->dinode->di_mtimensec = ip->dinode->di_birthnsec;
    dp->dinode->di_mtime     = ip->dinode->di_birthtime;

    /*
     * Initialize directory with "." and ".." from static template.
     */

    dirtemplate            = mastertemplate;
    dirtemplate.dot_ino    = ip->i_number;
    dirtemplate.dotdot_ino = dp->i_number;

    // copy the new directory into a buffer to write to disk
    memset(block_buf, 0, BLOCKSIZE);
    memcpy(block_buf, &dirtemplate, sizeof(dirtemplate));

    // get the hash key
    get_hash_from_block(block_buf, &new_dir_key);

    // write the buffer
    error = kvs_write_block(block_buf, &new_dir_key, mnt);
    if (error)
        return EJUSTRETURN;

    // update the new directory's inode
    ip->i_size          = DIRBLKSIZ;
    ip->dinode->di_size = DIRBLKSIZ;
    ip->i_flag |= IN_SIZEMOD | IN_CHANGE | IN_UPDATE;
    insert_key_into_inode(mnt, ip, &new_dir_key, NULL);

    // write the inode to disk
    dblock = fsbtodb(lblockno_from_ino(mnt, ip->i_number));
    error  = bread(mnt->devvp, dblock, BLOCKSIZE, NOCRED, &bp);
    if (error)
        return error;
    memcpy(bp->b_data + (file_inode_block_offset(ip->i_number) * sizeof(struct file_dinode)),
           ip->dinode,
           sizeof(struct file_dinode));
    bwrite(bp);
    if (error)
        return error;

    // fill in dir entry with data
    if (ddfs_makedirentry(ip, cnp, &newdir)) {
        return EJUSTRETURN;
    }

    // now put the new directory into the parent and write to disk
    error = ddfs_direnter(dvp, tvp, &newdir, cnp);

    // bad:
    if (error == 0) {
        *ap->a_vpp = tvp;
        vn_seqc_write_end(tvp);
    } else {
        dp->i_nlink--;
        dp->dinode->di_nlink = dp->i_nlink;
        dp->i_flag |= IN_CHANGE;
        /*
         * No need to do an explicit VOP_TRUNCATE here, vrele will
         * do this for us because we set the link count to 0.
         */
        ip->i_nlink          = 0;
        ip->dinode->di_nlink = 0;
        ip->i_flag |= IN_CHANGE;
        vn_seqc_write_end(tvp);
        vgone(tvp);
        vput(tvp);
    }
out:
    return (error);
}

/*
 * Vnode op for reading directories.
 * pretty much copied this from ffs with minor changes:
 *      https://github.com/freebsd/freebsd-src/blob/stable/13/sys/ufs/ufs/ufs_vnops.c
 */
static int
ddfs_readdir(struct vop_readdir_args* ap)
/* {
struct vnode *a_vp;
struct uio *a_uio;
struct ucred *a_cred;
int *a_eofflag;
int *a_ncookies;
u_long **a_cookies;
} */
{
    struct vnode* vp = ap->a_vp;
    struct uio* uio  = ap->a_uio;
    kvs_key hash_key;
    struct ddfs_mount* mnt = VFSTODDFS(vp->v_mount);
    struct buf* bp;
    struct file_inode* ip;
    struct direct *dp, *edp;
    unsigned long* cookies;
    struct dirent dstdp;
    off_t offset, startoffset;
    size_t readcnt;
    ssize_t startresid;
    u_int ncookies;
    int error;
    uint32_t file_off;
    uint32_t file_blkoff;

    if (uio->uio_offset < 0)
        return (EINVAL);
    ip = VTOI(vp);
    if (ap->a_ncookies != NULL) {
        if (uio->uio_resid < 0)
            ncookies = 0;
        else
            ncookies = uio->uio_resid;
        if (uio->uio_offset >= ip->i_size)
            ncookies = 0;
        else if (ip->i_size - uio->uio_offset < ncookies)
            ncookies = ip->i_size - uio->uio_offset;
        ncookies        = ncookies / (offsetof(struct direct, d_name) + 4) + 1;
        cookies         = malloc(ncookies * sizeof(*cookies), M_TEMP, M_WAITOK);
        *ap->a_ncookies = ncookies;
        *ap->a_cookies  = cookies;
    } else {
        ncookies = 0;
        cookies  = NULL;
    }
    offset = startoffset = uio->uio_offset;
    startresid           = uio->uio_resid;
    error                = 0;

    file_off = uio->uio_offset;

    while (error == 0 && uio->uio_resid > 0 && uio->uio_offset < ip->i_size) {
        // read dir block
        file_blkoff = byte_off_to_block_off(uio->uio_offset);
        error       = get_hash_at_block_off(vp, file_blkoff, &hash_key);
        if (error)
            return EJUSTRETURN;
        error = kvs_read_block(&hash_key, &bp, mnt);
        if (error)
            return EJUSTRETURN;

        if (uio->uio_offset + BLOCKSIZE > ip->i_size)
            readcnt = ip->i_size - uio->uio_offset;
        else
            readcnt = BLOCKSIZE;

        // WTF is skip count?
        // skipcnt = (size_t)(uio->uio_offset - bp->b_offset) & ~(size_t)(DIRBLKSIZ - 1);
        offset = uio->uio_offset;
        dp     = (struct direct*)bp->b_data;
        edp    = (struct direct*)&bp->b_data[readcnt];
        while (error == 0 && uio->uio_resid > 0 && dp < edp) {

            if (dp->d_reclen <= offsetof(struct direct, d_name)
                || (caddr_t)dp + dp->d_reclen > (caddr_t)edp) {
                error = EIO;
                break;
            }

            dstdp.d_namlen = dp->d_namlen;
            dstdp.d_type   = dp->d_type;

            if (offsetof(struct direct, d_name) + dstdp.d_namlen > dp->d_reclen) {
                error = EIO;
                break;
            }
            if (offset < startoffset || dp->d_ino == 0)
                goto nextentry;
            dstdp.d_fileno = dp->d_ino;
            dstdp.d_reclen = GENERIC_DIRSIZ(&dstdp);
            bcopy(dp->d_name, dstdp.d_name, dstdp.d_namlen);
            /* NOTE: d_off is the offset of the *next* entry. */
            dstdp.d_off = offset + dp->d_reclen;
            dirent_terminate(&dstdp);
            if (dstdp.d_reclen > uio->uio_resid) {
                if (uio->uio_resid == startresid)
                    error = EINVAL;
                else
                    error = EJUSTRETURN;
                break;
            }
            /* Advance dp. */
            error = uiomove((caddr_t)&dstdp, dstdp.d_reclen, uio);
            if (error)
                break;
            if (cookies != NULL) {
                KASSERT(ncookies > 0, ("ddfs_readdir: cookies buffer too small"));
                *cookies = offset + dp->d_reclen;
                cookies++;
                ncookies--;
            }
        nextentry:
            offset += dp->d_reclen;
            dp = (struct direct*)((caddr_t)dp + dp->d_reclen);
        }
        brelse(bp);    // was bqrelse in ffs?
        uio->uio_offset = offset;
    }
    /* We need to correct uio_offset. */
    uio->uio_offset = offset;
    if (error == EJUSTRETURN)
        error = 0;
    if (ap->a_ncookies != NULL) {
        if (error == 0) {
            ap->a_ncookies -= ncookies;
        } else {
            free(*ap->a_cookies, M_TEMP);
            *ap->a_ncookies = 0;
            *ap->a_cookies  = NULL;
        }
    }
    if (error == 0 && ap->a_eofflag)
        *ap->a_eofflag = ip->i_size <= uio->uio_offset;

    return (error);
}

/*
 * taken from ufs
 * https://github.com/freebsd/freebsd-src/blob/stable/13/sys/ufs/ufs/ufs_vnops.c
 */
static int
ddfs_open(struct vop_open_args* ap) {
    struct vnode* vp = ap->a_vp;
    struct file_inode* ip;
    ip = VTOI(vp);
    vnode_create_vobject(vp, ip->dinode->di_size, ap->a_td);
    return (0);
}

static int
ddfs_close(struct vop_close_args* ap) {
    return 0;
}

/*
    No security / permissions -- always return 0 for now
*/
static int
ddfs_access(struct vop_access_args* ap) {
    return 0;
}

/* Sourced from ffs:
 *      https://github.com/freebsd/freebsd-src/blob/stable/13/sys/ufs/ufs/ufs_vnops.c
 */
static int
ddfs_getattr(struct vop_getattr_args* ap)
/* {
struct vnode *a_vp;
struct vattr *a_vap;
struct ucred *a_cred;
} */
{
    struct vnode* vp      = ap->a_vp;
    struct file_inode* ip = VTOI(vp);
    struct vattr* vap     = ap->a_vap;

    /*
     * Copy from inode table
     */
    // vap->va_fsid   = dev2udev(ITOUMP(ip)->um_dev);
    vap->va_fileid = ip->i_number;
    vap->va_mode   = ip->i_mode & ~IFMT;
    vap->va_nlink  = ip->dinode->di_nlink;
    vap->va_uid    = ip->i_uid;
    vap->va_gid    = ip->i_gid;

    // vap->va_rdev              = ip->dinode->di_rdev;
    vap->va_size              = ip->dinode->di_size;
    vap->va_mtime.tv_sec      = ip->dinode->di_mtime;
    vap->va_mtime.tv_nsec     = ip->dinode->di_mtimensec;
    vap->va_birthtime.tv_sec  = ip->dinode->di_birthtime;
    vap->va_birthtime.tv_nsec = ip->dinode->di_birthnsec;
    vap->va_bytes             = ip->dinode->di_blocks * BLOCKSIZE;
    // vap->va_filerev           = ip->dinode->di_modrev;

    vap->va_flags = ip->i_flags;
    // vap->va_gen       = ip->i_gen;
    vap->va_blocksize = vp->v_mount->mnt_stat.f_iosize;
    vap->va_type      = IFTOVT(ip->i_mode);

    return (0);
}

/**
 * .vop_remove() handler
 * Unlinks file name from directory and deletes data from disk if no files reference anymore
 *
 * Sources: code copied from FFS ufs_dirremove() in /sys/ufs/ufs/ufs_lookup.c
 */
static int
ddfs_remove(struct vop_remove_args* ap) {
    /*
        struct vop_remove_args {
            struct vnode *a_dvp;
            struct vnode *a_vp;
            struct componentname *a_cnp;
        }
    */

    struct file_inode* ip;
    struct file_inode* dp;
    struct vnode* vp       = ap->a_vp;
    struct vnode* dvp      = ap->a_dvp;
    struct ddfs_mount* mnt = VFSTODDFS(dvp->v_mount);
    struct direct *ep, *rep;
    struct buf* bp;
    char* dirbuf;
    kvs_key dir_block_key;
    kvs_key blk_key;
    kvs_key null_key = {};
    off_t offset;
    uint32_t dblock;
    int error;

    ip    = VTOI(vp);
    dp    = VTOI(dvp);
    error = 0;

    if (ip) {
        // decrement file's inode ref count
        ip->i_nlink--;
    } else {
        // there *should* be an inode backing this file
        return (EJUSTRETURN);
    }

    /**
     * NOTE: Don't know if this is correct way to get directory entry offset!
     * taken from ufs_lookup.c ufs_dirremove()
     */
    offset = dp->i_offset - dp->i_count;

    error = get_hash_at_block_off(dvp, byte_off_to_block_off(offset), &dir_block_key);
    if (error) {
        return (error);
    }
    error = kvs_read_block(&dir_block_key, &bp, mnt);
    if (error) {
        return (error);
    }

    dirbuf = bp->b_data + offset_within_block(offset);
    ep     = (struct direct*)dirbuf;

    /* Set 'rep' to the entry being removed */
    if (dp->i_offset == 0) {
        rep = ep;
    } else {
        rep = (struct direct*)((char*)ep + ep->d_reclen);
    }

    /**
     * Zero out the file directory entry metadata
     */
    memset(&rep->d_name[0], 0, rep->d_namlen + 1);
    rep->d_namlen = 0;
    rep->d_type   = 0;
    rep->d_ino    = 0;

    if (dp->i_count != 0) {
        /* Collapse new free space into previous entry */
        ep->d_reclen += rep->d_reclen;
        rep->d_reclen = 0;
    }

    // write updated directory to disk
    bwrite(bp);

    /**
     * TODO: Update name cache lookup() uses here
     *
     * I *think* ufs runs fsync to force the directory to be updated
     * Don't know exactly how to update the name cache to not include this file name
     */

    /* now update dinode to match the inode updated */
    if (ip->i_nlink == 0) {
        /**
         * last link removed, remove the file from disk
         *
         * For each key in inode block pointers, remove the hash from disk
         */
        for (int i = 0; i < ip->dinode->di_blocks; i++) {
            error = get_hash_at_block_off(vp, i, &blk_key);
            if (error) {
                return (error);
            }
            error = kvs_remove_block(&blk_key, mnt);
            if (error) {
                return (error);
            }
        }

        /**
         * Go through rest of indirect blocks here...
         *
         * not fully implemented, only delete first indirect block for now
         */
        if (memcmp(&ip->dinode->di_idb1.key, &null_key, INODE_KEY_LENGTH) != 0) {
            kvs_remove_block(&ip->dinode->di_idb1, mnt);
        }

        /* nullify dinode */
        ip->dinode->di_blocks = 0;
        ip->dinode->di_size   = 0;
        ip->dinode->di_nlink  = ip->i_nlink;
    } else {
        ip->dinode->di_nlink = ip->i_nlink;
    }

    bp     = NULL;
    dblock = fsbtodb(lblockno_from_ino(mnt, ip->i_number));
    error  = bread(mnt->devvp, dblock, BLOCKSIZE, NOCRED, &bp);
    if (error) {
        return (error);
    }

    /** NOTE: bug here
     * this clears the inode entry for the file on every remove, even if the inode link count isn't 0
     *
     * luckily we don't implement hard links or symbolic links so doesn't matter
     */
    memset(bp->b_data + (file_inode_block_offset(ip->i_number) * sizeof(struct file_dinode)),
           0,
           sizeof(struct file_dinode));
    error = bwrite(bp);
    if (error) {
        return (error);
    }

    /**
     * TODO: free file inode bitmap
     */

    return (0);
}

/*
 *  Used by ddfsstat utility to check dedup space savings
 */
static int
ddfs_ioctl(struct vop_ioctl_args* ap) {
    struct vnode* vp;
    struct ddfs_sblock* sblock;

    vp     = ap->a_vp;
    sblock = &VFSTODDFS(vp->v_mount)->superblock;
    switch (ap->a_command) {
        case STAT: {
            struct stats* stats      = (struct stats*)ap->a_data;
            stats->total_data_blocks = sblock->total_data_blocks;
            stats->used_data_blocks  = sblock->used_data_blocks;
            stats->total_block_refs  = sblock->total_block_refs;
            return 0;
        }
        default: return (ENOTTY);
    }
}

struct vop_vector ddfs_vnodeops = {
    .vop_default = &default_vnodeops,

    .vop_access       = ddfs_access,
    .vop_close        = ddfs_close,
    .vop_create       = ddfs_create,
    .vop_getattr      = ddfs_getattr,
    .vop_lookup       = vfs_cache_lookup,
    .vop_cachedlookup = ddfs_lookup,
    .vop_open         = ddfs_open,
    .vop_read         = ddfs_read,
    .vop_mkdir        = ddfs_mkdir,
    .vop_readdir      = ddfs_readdir,
    .vop_reclaim      = ddfs_reclaim,
    .vop_write        = ddfs_write,
    .vop_ioctl        = ddfs_ioctl,
    .vop_remove       = ddfs_remove,
    // .vop_rename  = ddfs_rename,

    // .vop_setattr  = ddfs_setattr,
    // .vop_unlock   = ddfs_unlock,

};

VFS_VOP_VECTOR_REGISTER(ddfs_vnodeops);
