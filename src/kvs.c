// clang-format off
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cdefs.h>
#include <sys/kernel.h>

#include "kvs.h"
#include "ddfs.h"

// clang-format on

MALLOC_DEFINE(M_KVS_LAYER, "kvs_blockops", "KVS layer block ops");

static int update_superblock(struct ddfs_mount* mnt, int change, bool ref_only);

/**
 * Lookup inode corresponding to hash key
 *
 * If inode for hash key is found, node is set to non-null in-memory kvs_node
 * otherwise, node is null if not found
 *
 * Return: 0 if successful, error number on error
 */
int
kvs_lookup_block(kvs_key* hash_key, struct kvs_node** node, struct ddfs_mount* mnt) {
    struct vnode* devvp;
    struct buf* bp;
    struct kvs_node* new_kvsn;
    struct inode_list_block* inode_block;
    struct kvs_dinode* found_inode;
    uint32_t inode_lblock_no;
    uint32_t inode_dblock_no;
    uint32_t inode_tbl_idx;
    uint32_t next_inode_lblock_no;
    uint16_t total_entries;
    uint32_t found_entry;
    uint32_t found_lblock;
    int error;

    devvp           = mnt->devvp;
    found_inode     = NULL;
    inode_block     = NULL;
    inode_dblock_no = 0;
    error           = 0;

    /**
     * Possibly perform some caching for hash key first
     *
     * future optimization...
     */

    /* Convert key hash to inode table index by hash % 2^16 */
    inode_tbl_idx   = ((hash_key->key[18] << 8) | hash_key->key[19]) & 0x0000FFFF;
    inode_lblock_no = inode_tbl_idx + mnt->superblock.kvs_inode_table_offset;

    // Read the inode block list and follow the linked list until the end or file found
    do {
        // Read the inode block
        inode_dblock_no = fsbtodb(inode_lblock_no);
        error           = bread(devvp, inode_dblock_no, BLOCKSIZE, NOCRED, &bp);
        if (error) {
            return (error);
        }
        inode_block = (struct inode_list_block*)bp->b_data;

        total_entries        = inode_block->entry_count;
        next_inode_lblock_no = inode_block->next_block;

        // Perform a linear search of the block's entries
        uint16_t entries_read = 0;
        for (uint32_t entry = 0; entry < INODE_PER_BLOCK_COUNT && entries_read < total_entries; entry++) {
            // see if the keys match
            uint32_t data_blk_no = inode_block->entries[entry].data_block;
            if (data_blk_no == 0) {    // block zero is unused so the inode is invalid
                continue;
            }
            struct kvs_key* this_key = &inode_block->entries[entry].key;

            bool key_match = true;
            for (int i = 0; i < INODE_KEY_LENGTH; i++) {
                if (hash_key->key[i] != this_key->key[i]) {
                    key_match = false;
                    break;
                }
            }
            if (key_match) {
                // Keys match, alloc an inode
                found_inode = malloc(sizeof(struct kvs_dinode), M_KVS_LAYER, M_WAITOK | M_ZERO);
                memcpy(found_inode, &inode_block->entries[entry], sizeof(struct kvs_dinode));
                found_entry  = entry;
                found_lblock = inode_lblock_no;
                break;
            }
            entries_read++;
        }

        inode_lblock_no = next_inode_lblock_no + mnt->superblock.data_block_offset;
        brelse(bp);
        bp = NULL;
    } while (next_inode_lblock_no != 0 && found_inode == NULL);

    if (found_inode == NULL) {
        goto lookup_not_found;
    }

    new_kvsn                     = malloc(sizeof(struct kvs_node), M_KVS_LAYER, M_WAITOK | M_ZERO);
    new_kvsn->inode              = found_inode;
    new_kvsn->inode_table_lblock = found_lblock;
    new_kvsn->entry_index        = found_entry;

    *node = new_kvsn;

    return (0);

lookup_not_found:
    /**
     * Signal the block wasn't found by setting node to NULL
     */
    *node = NULL;

    return (0);
}

/**
 * Sets found_block_no to datablock number of a free datablock to use
 * Updates datablock bitmap for returned datablock to used
 *
 * Return: 0 if successful, 1 if given bitmap block was all taken
 */
static int
find_free_data_block(struct ddfs_mount* mnt, uint32_t* found_block_no) {
    struct vnode* devvp;
    struct ddfs_sblock* sblock;
    struct buf* bp;
    uint32_t random_bitmap;
    uint32_t bitmap_off;
    uint32_t num_bitmap_blocks;
    uint32_t total_data_blocks;
    uint32_t bitmap_lblock_no;
    uint32_t bitmap_dblock_no;
    uint32_t current_datablock_number;
    uint32_t datablock_number;
    uint64_t* bitmap;
    int error, found_block;

    devvp             = mnt->devvp;
    sblock            = &mnt->superblock;
    bitmap_off        = sblock->free_bitmap_offset;
    num_bitmap_blocks = sblock->finode_bitmap_offset - bitmap_off;
    total_data_blocks = sblock->total_data_blocks;
    error             = 0;
    found_block       = 0;

    /* start by getting random entry into free datablock bitmap and loading that bitmap block */
    random_bitmap    = random() % num_bitmap_blocks;
    bitmap_lblock_no = random_bitmap + bitmap_off;
    bitmap_dblock_no = fsbtodb(bitmap_lblock_no);

    error = bread(devvp, bitmap_dblock_no, BLOCKSIZE, NOCRED, &bp);
    if (error) {
        return (error);
    }
    bitmap = (uint64_t*)bp->b_data;

    current_datablock_number = random_bitmap * DATABLOCKS_PER_BITMAP_BLOCK;

    /* for each entry in the bitmap block, look for a bit that is currently 0 (free) */
    int bitmap_entry;
    int bit_index;

    for (bitmap_entry = 0;
         bitmap_entry < ENTRIES_PER_BITMAP_BLOCK && current_datablock_number < total_data_blocks;
         bitmap_entry++) {
        for (bit_index = 0; bit_index < BITS_PER_BITMAP_ENTRY && current_datablock_number < total_data_blocks;
             bit_index++) {
            // We reserve datablock 0, don't allocate it
            if (current_datablock_number == 0) {
                current_datablock_number++;
                continue;
            }
            if ((bitmap[bitmap_entry] & (1 << bit_index)) == 0) {
                found_block = 1;
                bitmap[bitmap_entry] |= (1 << bit_index);
                break;
            }
            current_datablock_number++;
        }
        if (found_block != 0) {
            break;
        }
    }

    if (found_block == 0) {
        // this selected bitmap block is totally full, signal to try again
        brelse(bp);
        return (1);
    }

    // write updated datablock bitmap back to disk to reflect found block as taken
    bawrite(bp);

    // Now convert back to datablock/inode number
    datablock_number = random_bitmap * DATABLOCKS_PER_BITMAP_BLOCK;
    datablock_number += (bitmap_entry * BITS_PER_BITMAP_ENTRY) + bit_index;

    *found_block_no = datablock_number;

    return (0);
}

/**
 * Takes a key hash and returns buffer of free inode list block corresponding to key hash.
 *
 * Sets buffer pointer to inode_list_block and stores the inode lblock and inode table entry in kvsn kvs_node
 * Increments the free inode's inode block entry count on success
 *
 * Returns: 0 if successful, error number on error
 */
static int
get_free_inode_entry(struct ddfs_mount* mnt, kvs_key* hash_key, struct buf** bpp, struct kvs_node* kvsn) {
    struct vnode* devvp;
    struct inode_list_block* inode_block;
    struct buf* bp;
    uint32_t inode_tbl_idx;
    uint32_t inode_lblock_no;
    uint32_t inode_dblock_no;
    uint32_t next_inode_lblock_no;
    uint32_t new_inode_lblock_no;
    uint32_t data_blk_no;
    uint32_t entry;
    uint32_t new_inode_block;
    bool found;
    int error;

    devvp = mnt->devvp;
    found = false;
    error = 0;

    /*
        Convert the hash to an inode table index by doing hash % 2^16
    */
    inode_tbl_idx        = ((hash_key->key[18] << 8) | hash_key->key[19]) & 0x0000FFFF;
    inode_lblock_no      = inode_tbl_idx + mnt->superblock.kvs_inode_table_offset;
    next_inode_lblock_no = inode_lblock_no;

    do {
        // Read the inode block
        new_inode_lblock_no = next_inode_lblock_no;
        inode_dblock_no     = fsbtodb(next_inode_lblock_no);
        error               = bread(devvp, inode_dblock_no, BLOCKSIZE, NOCRED, &bp);
        if (error) {
            return (error);
        }
        inode_block = (struct inode_list_block*)bp->b_data;

        next_inode_lblock_no = inode_block->next_block + mnt->superblock.data_block_offset;

        // Perform a linear search of the block's entries
        for (entry = 0; entry < INODE_PER_BLOCK_COUNT; entry++) {
            data_blk_no = inode_block->entries[entry].data_block;
            if (data_blk_no == 0) {    // block zero is unused so the inode is free
                // change the data block value to reserve the inode b/c
                // future calls to this function could select the same block if its 0
                inode_block->entries[entry].data_block = 1;
                found                                  = true;
                inode_block->entry_count++;
                /* save node inode table info here for easy use in write later */
                kvsn->entry_index        = entry;
                kvsn->inode_table_lblock = new_inode_lblock_no;
                *bpp                     = bp;
                return 0;
            }
        }
        if (inode_block->next_block != 0) {
            brelse(bp);
            bp          = NULL;
            inode_block = NULL;
        }
    } while (inode_block->next_block != 0);

    // Failed to find a slot in an existing block, need to create a new inode list block
    while (find_free_data_block(mnt, &new_inode_block)) { /* keep trying */
    }

    // Link the new block into the old one
    inode_block->next_block = new_inode_block;
    bawrite(bp);
    bp = NULL;

    // Read in the new inode block
    new_inode_lblock_no = new_inode_block + mnt->superblock.data_block_offset;
    inode_dblock_no     = fsbtodb(new_inode_lblock_no);
    error               = bread(devvp, inode_dblock_no, BLOCKSIZE, NOCRED, &bp);
    if (error) {
        return (error);
    }

    // Zero out the block
    memset(bp->b_data, 0, BLOCKSIZE);

    inode_block = (struct inode_list_block*)bp->b_data;
    inode_block->entry_count++;
    *bpp                     = bp;
    kvsn->entry_index        = entry;
    kvsn->inode_table_lblock = new_inode_lblock_no;

    return 0;
}

/**
 * Update ddfs superblock used data blocks and used inodes numbers and total block refs
 *
 * Change: should be either 1 or -1
 */
static int
update_superblock(struct ddfs_mount* mnt, int change, bool ref_only) {
    struct vnode* devvp;
    struct buf* bp;
    struct ddfs_sblock* sblock;
    int error;

    devvp = mnt->devvp;
    bp    = NULL;
    error = 0;

    sblock = &mnt->superblock;
    sblock->total_block_refs += change;
    if (!ref_only) {
        sblock->used_data_blocks += change;
        sblock->used_kvs_inodes += change;
    }

    error = bread(devvp, 0, BLOCKSIZE, NOCRED, &bp);
    if (error) {
        return (error);
    }
    memcpy(bp->b_data, sblock, sizeof(struct ddfs_sblock));
    error = bwrite(bp);
    if (error) {
        return (error);
    }

    return (0);
}

/**
 * Find a free block and create an inode for the data block
 * NOTE: Does not actually touch the data block, unlike asgn3. Datablock is not zeroed out, and returned with
 * a ref count of 0
 *
 * Sets node to a filled out kvs_node with the dinode of the new block
 *
 * Returns: 0 if successful, error code on error
 */
int
kvs_create_block(kvs_key* hash_key, struct kvs_node** node, struct ddfs_mount* mnt) {
    struct vnode* devvp;
    struct buf* bp;
    struct kvs_dinode* new_dinode;
    struct kvs_node* new_kvsn;
    struct inode_list_block* inode_block;
    uint32_t new_data_block;
    int error;

    devvp = mnt->devvp;
    error = 0;
    bp    = NULL;

    // begin finding a free block for us to use
    while (find_free_data_block(mnt, &new_data_block)) { /* keep trying */
    }

    // new dinode setup in memory
    new_dinode = malloc(sizeof(struct kvs_dinode), M_KVS_LAYER, M_WAITOK | M_ZERO);
    copy_hash_key(new_dinode->key.key, hash_key->key);
    new_dinode->data_block = new_data_block;
    new_dinode->mod_time   = 0;
    new_dinode->ref_count  = 0;
    /**
     * NOTE: reference count is not set here, make sure to set ref count after receiving node
     */

    // set up in memory kvs_node for the caller to use
    new_kvsn        = malloc(sizeof(struct kvs_node), M_KVS_LAYER, M_WAITOK | M_ZERO);
    new_kvsn->inode = new_dinode;

    // now find free dinode entry
    error = get_free_inode_entry(mnt, hash_key, &bp, new_kvsn);
    if (error) {
        return (error);
    }

    // copy new dinode to inode block and write back to disk
    inode_block = (struct inode_list_block*)bp->b_data;
    memcpy(&inode_block->entries[new_kvsn->entry_index], new_dinode, sizeof(struct kvs_dinode));
    inode_block->entry_count++;
    bawrite(bp);
    bp = NULL;

    update_superblock(mnt, 1, false);

    *node = new_kvsn;

    return (0);
}

/**
 * Write 4KiB block to disk
 *
 * Takes 4KiB char array containing data to write, will overwrite whatever is at key value with buffer
 * the kvs_key struct with hash to lookup
 * and the ddfs mount pointer
 *
 * Returns 0 if successful, errno on error
 */
int
kvs_write_block(char* block_buf, kvs_key* hash_key, struct ddfs_mount* mnt) {
    struct buf* bp;
    struct buf* inode_bp;
    struct kvs_node* kvn;
    struct kvs_dinode* dip;
    struct vnode* devvp;
    struct inode_list_block* inode_block;
    uint32_t inode_lblock_no;
    uint32_t inode_dblock_no;
    uint32_t dblockno;
    int error;

    error = 0;
    kvn   = NULL;
    devvp = mnt->devvp;

    for (int i = 0; i < INODE_KEY_LENGTH; i++) {
    }

    if (block_buf == NULL) {
        // nothing to write
        return (EJUSTRETURN);
    }

    error = kvs_lookup_block(hash_key, &kvn, mnt);
    if (error) {
        return (error);
    }

    if (kvn != NULL) {
        // block was found
        // read in block to buffer cache so that it can get overwritten
        dip      = kvn->inode;
        dblockno = fsbtodb(dip->data_block + mnt->superblock.data_block_offset);
        error    = bread(devvp, dblockno, BLOCKSIZE, NOCRED, &bp);
        if (error) {
            // free kvs node
            if (kvn != NULL) {
                if (kvn->inode != NULL) {
                    free(kvn->inode, M_KVS_LAYER);
                }
                free(kvn, M_KVS_LAYER);
            }

            return (error);
        }

        // increase block reference count and write back to disk
        dip->ref_count++;

        inode_lblock_no = kvn->inode_table_lblock;
        inode_dblock_no = fsbtodb(inode_lblock_no);
        error           = bread(devvp, inode_dblock_no, BLOCKSIZE, NOCRED, &inode_bp);
        if (error) {
            // free kvs node
            if (kvn != NULL) {
                if (kvn->inode != NULL) {
                    free(kvn->inode, M_KVS_LAYER);
                }
                free(kvn, M_KVS_LAYER);
            }

            return (error);
        }
        inode_block = (struct inode_list_block*)inode_bp->b_data;

        memcpy(&(inode_block->entries[kvn->entry_index]), dip, sizeof(struct kvs_dinode));
        bawrite(inode_bp);
        update_superblock(mnt, 1, true);
    } else {

        // block wasn't found, create new block for this key hash
        error = kvs_create_block(hash_key, &kvn, mnt);
        if (error) {
            return (error);
        }

        dip      = kvn->inode;
        dblockno = fsbtodb(dip->data_block + mnt->superblock.data_block_offset);
        error    = bread(devvp, dblockno, BLOCKSIZE, NOCRED, &bp);
        if (error) {
            // free kvs node
            if (kvn != NULL) {
                if (kvn->inode != NULL) {
                    free(kvn->inode, M_KVS_LAYER);
                }
                free(kvn, M_KVS_LAYER);
            }

            return (error);
        }
        memset(bp->b_data, 0, BLOCKSIZE);

        // increase block reference count for new block
        dip->ref_count++;

        inode_lblock_no = kvn->inode_table_lblock;
        inode_dblock_no = fsbtodb(inode_lblock_no);
        error           = bread(devvp, inode_dblock_no, BLOCKSIZE, NOCRED, &inode_bp);
        if (error) {
            // free kvs node
            if (kvn != NULL) {
                if (kvn->inode != NULL) {
                    free(kvn->inode, M_KVS_LAYER);
                }
                free(kvn, M_KVS_LAYER);
            }

            return (error);
        }
        inode_block = (struct inode_list_block*)inode_bp->b_data;

        memcpy(&(inode_block->entries[kvn->entry_index]), dip, sizeof(struct kvs_dinode));
        bawrite(inode_bp);
    }

    // copy buffer of data to write to buffer cache buffer and write back to disk
    memcpy(bp->b_data, block_buf, BLOCKSIZE);
    bawrite(bp);

    // free kvs node
    if (kvn != NULL) {
        if (kvn->inode != NULL) {
            free(kvn->inode, M_KVS_LAYER);
        }
        free(kvn, M_KVS_LAYER);
    }

    return (0);
}

/**
 * Copy data block of hash key into buffer bpp
 *
 * Takes kvs_key hash_key, char buffer, and ddfs mount pointer
 *
 * Returns 0 on success, error number on error
 */
int
kvs_read_block(kvs_key* hash_key, struct buf** bpp, struct ddfs_mount* mnt) {
    struct kvs_node* kvn;
    struct vnode* devvp;
    struct buf* bp;
    uint32_t disk_lblock;
    uint32_t disk_dblock_no;
    int error;

    error = 0;
    kvn   = NULL;
    devvp = mnt->devvp;

    error = kvs_lookup_block(hash_key, &kvn, mnt);
    if (error) {
        return (error);
    }

    if (kvn != NULL) {
        disk_lblock = kvn->inode->data_block + mnt->superblock.data_block_offset;
    } else {
        // shouldn't be possible
        return (EJUSTRETURN);
    }

    disk_dblock_no = fsbtodb(disk_lblock);
    error          = bread(devvp, disk_dblock_no, BLOCKSIZE, NOCRED, &bp);
    if (error) {
        // free kvs node
        if (kvn != NULL) {
            if (kvn->inode != NULL) {
                free(kvn->inode, M_KVS_LAYER);
            }
            free(kvn, M_KVS_LAYER);
        }

        return (error);
    }

    *bpp = bp;

    // free kvs node
    if (kvn != NULL) {
        if (kvn->inode != NULL) {
            free(kvn->inode, M_KVS_LAYER);
        }
        free(kvn, M_KVS_LAYER);
    }

    return (0);
}

/**
 * Remove reference to a data block with given hash key
 * If ref count drops to 0 for the data block, mark data block as free in free data block bitmap
 *
 * Takes the hash to lookup and a ddfs mount pointer
 *
 * Return: 0 if successful, error number on error
 */
int
kvs_remove_block(struct kvs_key* hash_key, struct ddfs_mount* mnt) {
    struct vnode* devvp;
    struct buf* bp;
    struct kvs_node* kvn;
    struct inode_list_block* inode_block;
    uint32_t inode_table_dblock_no;
    uint32_t bitmap_entry, bit_index;
    uint32_t bitmap_data_block, bitmap_dblock_no;
    int error;

    devvp = mnt->devvp;
    kvn   = NULL;
    bp    = NULL;
    error = 0;

    /* begin by lookup up hash key and getting a kvs node for it */
    error = kvs_lookup_block(hash_key, &kvn, mnt);
    if (error) {
        return (error);
    }

    if (kvn == NULL || kvn->inode == NULL) {
        // hash key wasn't found associated with a block
        return (EJUSTRETURN);
    }

    // decrement ref count to this data block
    kvn->inode->ref_count--;

    /* load the inode table to modify */
    inode_table_dblock_no = fsbtodb(kvn->inode_table_lblock);
    error                 = bread(devvp, inode_table_dblock_no, BLOCKSIZE, NOCRED, &bp);
    if (error) {
        if (kvn != NULL) {
            if (kvn->inode != NULL) {
                free(kvn->inode, M_KVS_LAYER);
            }
            free(kvn, M_KVS_LAYER);
        }
        return (error);
    }
    inode_block = (struct inode_list_block*)bp->b_data;

    // if block ref count is now 0, invalidate it by setting its data block to 0
    if (kvn->inode->ref_count == 0) {
        inode_block->entry_count--;
        kvn->inode->data_block = 0;
        memset(&kvn->inode->key.key, 0, INODE_KEY_LENGTH);
    }

    memcpy(&(inode_block->entries[kvn->entry_index]), kvn->inode, sizeof(struct kvs_dinode));
    bwrite(bp);

    // if ref count is 0 and we invalidated the inode, update bitmap to be free as well
    if (kvn->inode->ref_count == 0) {
        // modify bitmask at given inode block to be set to free
        bitmap_data_block = kvn->inode_table_lblock / DATABLOCKS_PER_BITMAP_BLOCK;
        bitmap_dblock_no  = fsbtodb(bitmap_data_block + mnt->superblock.free_bitmap_offset);
        bitmap_entry      = kvn->inode_table_lblock % 512;
        bit_index         = kvn->inode_table_lblock % 64;

        bp    = NULL;
        error = bread(devvp, bitmap_dblock_no, BLOCKSIZE, NOCRED, &bp);
        if (error) {
            if (kvn != NULL) {
                if (kvn->inode != NULL) {
                    free(kvn->inode, M_KVS_LAYER);
                }
                free(kvn, M_KVS_LAYER);
            }
            return (error);
        }
        uint64_t* bitmap = (uint64_t*)bp->b_data;

        bitmap[bitmap_entry] ^= (1 << bit_index);

        error = bwrite(bp);
        if (error) {
            if (kvn != NULL) {
                if (kvn->inode != NULL) {
                    free(kvn->inode, M_KVS_LAYER);
                }
                free(kvn, M_KVS_LAYER);
            }
            return (error);
        }

        // update superblock info for used data blocks
        error = update_superblock(mnt, -1, false);
        if (error) {
            if (kvn != NULL) {
                if (kvn->inode != NULL) {
                    free(kvn->inode, M_KVS_LAYER);
                }
                free(kvn, M_KVS_LAYER);
            }
            return (error);
        }
    } else {
        // update only ref count
        update_superblock(mnt, -1, true);
    }

    if (kvn != NULL) {
        if (kvn->inode != NULL) {
            free(kvn->inode, M_KVS_LAYER);
        }
        free(kvn, M_KVS_LAYER);
    }

    return (0);
}
