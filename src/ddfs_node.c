// clang-format off
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/vnode.h>

#include "kvs.h"
#include "ddfs.h"

// clang-format on

MALLOC_DEFINE(M_DDFSNODE, "DDFS_node_alloc", "DDFS node setup alloc");

extern struct vop_vector ddfs_vnodeops;

static int blknum_vncmp(struct vnode* vp, void* arg);
int get_node(struct ddfs_mount* mnt, struct vnode** vpp, uint32_t ino);
int ddfs_reclaim(struct vop_reclaim_args* ap);

/**
 * Function following vfs_hash_cmp_t as described in /sys/vnode.h
 *
 * Used by vfs_hash_get() while iterating through hash list of vnodes
 * to determine if a given vnode matches the block number
 *
 * Returns true if either the vnode block number doesn't match the given block number
 * or the ddfs node inode (value) ref count is not active
 *
 * NOTE: may want to change comparing to ref count in ddfs node
 * FAT has ref count in denode, may be different than the ref count of an inode
 */
static int
blknum_vncmp(struct vnode* vp, void* arg) {
    uint32_t* ino;
    uint32_t cmp_ino;

    ino     = arg;
    cmp_ino = VTOI(vp)->i_number;

    return (cmp_ino != *ino);
}

/**
 * Return a new, initialized file_inode
 *
 * Hash block number to see if vfs has a vnode already for the given key
 * If so, return a new file_inode with that vnode
 *
 * If not, get a new vnode and return that file_inode
 *
 * Heavily inspired by /sys/fs/msdosfs/msdosfs_denode.c
 */
int
get_node(struct ddfs_mount* mnt, struct vnode** vpp, uint32_t ino) {
    int error;
    struct vnode* nvp;
    struct vnode* vp2;
    struct file_inode* new_inode;
    struct file_dinode* dinode;
    struct mount* mp = mnt->mountp;
    struct buf* bp;
    uint32_t dblock;

    error = vfs_hash_get(mp, ino, LK_EXCLUSIVE, curthread, &nvp, blknum_vncmp, &ino);
    if (error) {
        return (error);
    }
    if (nvp != NULL) {
        // vnode found for the block number
        *vpp = nvp;
        return (0);
    }

    error = getnewvnode("ddfs", mp, &ddfs_vnodeops, &nvp);
    if (error) {
        *vpp = NULL;
        return (error);
    }

    new_inode = malloc(sizeof(struct file_inode), M_DDFSNODE, M_WAITOK | M_ZERO);

    // read in the new dinode from disk and copy the dinode info into new_inode
    dblock = fsbtodb(lblockno_from_ino(mnt, ino));
    error  = bread(mnt->devvp, dblock, BLOCKSIZE, NOCRED, &bp);
    if (error) {
        free(new_inode, M_DDFSNODE);
        return error;
    }
    dinode = malloc(sizeof(struct file_dinode), M_DDFSNODE, M_WAITOK | M_ZERO);
    memcpy(dinode,
           bp->b_data + (file_inode_block_offset(ino) * sizeof(struct file_dinode)),
           sizeof(struct file_dinode));
    brelse(bp);

    /*
     * Perform initialization of vnode and inode
     */
    new_inode->dinode  = dinode;
    new_inode->i_vnode = nvp;
    new_inode->mnt     = mnt;

    new_inode->i_number = ino;
    new_inode->i_size   = dinode->di_size;
    new_inode->i_gen    = dinode->di_gen;
    new_inode->i_flags  = dinode->di_flags;
    new_inode->i_uid    = dinode->di_uid;
    new_inode->i_gid    = dinode->di_gid;
    new_inode->i_mode   = dinode->di_mode;
    new_inode->i_nlink  = dinode->di_nlink;

    nvp->v_type = IFTOVT(new_inode->i_mode);
    nvp->v_data = new_inode;

    if (ino == DDFS_ROOT_INO) {
        nvp->v_vflag |= VV_ROOT;
    }

    // associate new vnode with mount
    lockmgr(nvp->v_vnlock, LK_EXCLUSIVE, NULL);
    error = insmntque(nvp, mp);
    if (error) {
        free(dinode, M_DDFSNODE);
        free(new_inode, M_DDFSNODE);
        *vpp = NULL;
        return (error);
    }

    // insert error handling taken from /sys/fs/fuse/fuse_node.c
    error = vfs_hash_insert(nvp, ino, LK_EXCLUSIVE, curthread, &vp2, blknum_vncmp, &ino);
    if (error) {
        lockmgr(nvp->v_vnlock, LK_RELEASE, NULL);
        free(dinode, M_DDFSNODE);
        free(new_inode, M_DDFSNODE);
        *vpp = NULL;
        return (error);
    }
    if (vp2 != NULL) {
        *vpp = vp2;
        return (0);
    }

    // if null?
    *vpp = nvp;
    return (0);
}

/*
 * First
 *
 */
// int
// create_inode() {}

/**
 * Inactive vnode is being repurposed for new key
 * Free old ddfs node structures in the vnode
 *
 * Return: 0 if success, error code otherwise
 */
int
ddfs_reclaim(struct vop_reclaim_args* ap) {
    struct vnode* vp         = ap->a_vp;
    struct file_inode* inode = VTOI(vp);

    // remove vnode from hash
    vfs_hash_remove(vp);

    // free in memory inode for this vnode
    // this should never be null after kvs_root is working properly
    if (inode->dinode != NULL) {
        free(inode->dinode, M_DDFSNODE);
        inode->dinode = NULL;
    }

    // free file_inode
    free(inode, M_DDFSNODE);
    vp->v_data = NULL;

    return (0);
}
