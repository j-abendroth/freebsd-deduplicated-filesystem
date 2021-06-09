// clang-format off
// Not sure which of these we need - copied them all from FAT 
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cdefs.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/iconv.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/vnode.h>

#include <geom/geom.h>
#include <geom/geom_vfs.h>

#include "kvs.h"
#include "ddfs.h"
#include "dir.h"

// clang-format on

extern struct vop_vector ddfs_vnodeops;
extern int get_node(struct ddfs_mount* mnt, struct vnode** vpp, uint32_t ino);

static int mount_ddfs(struct vnode* devvp, struct mount* mp);
int ddfs_vget(struct mount* mp, ino_t ino, int flags, struct vnode** vpp);

MALLOC_DEFINE(M_DDFSMNT, "ddfs_mount", "DDFS mount structure");

/*
    Decide what we're doing: updating, mounting, etc
    Then, read superblock and initialize in-memory structs
    Initialize the mount structure for the filesystem

    Code largely taken from msdosfs_mount:
    https://github.com/freebsd/freebsd-src/blob/releng/13.0/sys/fs/msdosfs/msdosfs_vfsops.c
*/
static int
ddfs_mount(struct mount* mp) {
    struct vnode* devvp;
    struct thread* td;    // used by NDINIT
    int error = 0;
    char* from;
    struct nameidata ndp;

    td = curthread;
    /*  perform filteropt() to filter out unsupported operations

        CODE HERE

    */

    // perform some checks ??
    if (mp->mnt_flag & MNT_UPDATE) {
        // do nothing for now --
        // would normally allow one to change from read-only to write or vice versa
        // or change the device name
        return ENOTSUP;
    } else {
        /*
            Not an update, or updating the name: look up the name
            and verify that it refers to a sensible disk device.
        */
        // get mount option name
        if (vfs_getopt(mp->mnt_optnew, "from", (void**)&from, NULL))
            return (EINVAL);
        // initializes namei, increase reference count of devvp vnode
        // importantly, also LOCKS the vnode
        NDINIT(&ndp, LOOKUP, FOLLOW | LOCKLEAF, UIO_SYSSPACE, from, td);
        error = namei(&ndp);
        if (error)
            return (error);
        devvp = ndp.ni_vp;
        NDFREE(&ndp, NDF_ONLY_PNBUF);

        // check if the vnode represents a disk device and error out if not
        if (!vn_isdisk_error(devvp, &error)) {
            vput(devvp);
            return (error);
        }

        // mount the fs
        if ((error = mount_ddfs(devvp, mp)) != 0) {
            vrele(devvp);
            /* Call unmount? */
            return error;
        };
    }
    vfs_mountedfrom(mp, from);
    return (error);
}

/*
    Most of this code is sourced from the mount functions of msdosfs_vfsops.c or ffs_vfsops.c
    https://github.com/freebsd/freebsd-src/blob/releng/13.0/sys/fs/msdosfs/msdosfs_vfsops.c
    https://github.com/freebsd/freebsd-src/blob/releng/13.0/sys/ufs/ffs/ffs_vfsops.c
*/
static int
mount_ddfs(struct vnode* devvp, struct mount* mp) {
    struct ddfs_sblock* sbp;
    struct ddfs_mount* mnt;
    struct buf* bp;
    struct cdev* dev;
    struct g_consumer* consumer_geom;
    int error;
    int ronly = 0;    // never read only (for now anyway)

    // taken from msdosfs -- i think this checks if something is already mounted at this location
    dev = devvp->v_rdev;
    if (atomic_cmpset_acq_ptr((uintptr_t*)&dev->si_mountpt, 0, (uintptr_t)mp) == 0) {
        VOP_UNLOCK(devvp);
        return (EBUSY);
    }

    // Create a new geom consumer for our filesystem
    // and attach it to the provider at the mount point specified in devvp
    g_topology_lock();
    error = g_vfs_open(devvp, &consumer_geom, "ddfs", ronly ? 0 : 1);
    g_topology_unlock();

    // fail out if we couldn't attach to the provider
    if (error != 0) {
        atomic_store_rel_ptr((uintptr_t*)&dev->si_mountpt, 0);
        VOP_UNLOCK(devvp);
        return (error);
    }

    // Create mount struct and initialize it
    mnt                = malloc(sizeof(struct ddfs_mount), M_DDFSMNT, M_ZERO | M_WAITOK);
    mnt->mountp        = mp;
    mnt->devvp         = devvp;
    mnt->dev           = dev;
    mnt->consumer_geom = consumer_geom;
    dev_ref(dev);                          // increase ref count of our driver
    mnt->mnt_bufobj = &devvp->v_bufobj;    // get the vnodes buffers
    VOP_UNLOCK(devvp);

    // set the max I/O size in the mount struct
    if (dev->si_iosize_max != 0)
        mp->mnt_iosize_max = dev->si_iosize_max;
    if (mp->mnt_iosize_max > maxphys)
        mp->mnt_iosize_max = maxphys;

    /*
        Read the superblock and verify it is ddfs fs -
        error out otherwise
    */
    error = bread(devvp, 0, BLOCKSIZE, NOCRED, &bp);
    if (error)
        goto error_exit;
    sbp = (struct ddfs_sblock*)bp->b_data;

    if (sbp->fs_magic != DDFSMAGIC) {
        error = EINVAL;
        goto error_exit;
    }
    /*
        The file system is verified, begin initializing data structures
    */

    /* Print superblock info for debugging purposes */

    // copy our superblock into our mount struct
    memcpy(&mnt->superblock, sbp, sizeof(struct ddfs_sblock));

    // copy the hash bitmap into memory
    // WARNING: if we want to use this feature => convert bitmap to char array!
    uint32_t blk_no = fsbtodb(sbp->hash_bitmap_offset);
    uint32_t bytes  = HASH_BITMAP_ARRAY_SIZE * sizeof(uint64_t);
    brelse(bp);
    bp    = NULL;
    error = bread(devvp, blk_no, bytes, NOCRED, &bp);
    if (error)
        goto error_exit;
    memcpy(&mnt->hash_bitmap, bp->b_data, bytes);
    brelse(bp);
    bp = NULL;

    // save our mount structure into the mount object
    mp->mnt_data = mnt;

    return 0;

error_exit:
    if (bp)
        brelse(bp);
    if (consumer_geom != NULL) {
        g_topology_lock();
        g_vfs_close(consumer_geom);
        g_topology_unlock();
    }
    if (mnt) {
        free(mnt, M_DDFSMNT);
        mp->mnt_data = NULL;
    }
    atomic_store_rel_ptr((uintptr_t*)&dev->si_mountpt, 0);
    dev_rel(dev);
    return (error);
}

/*
    Unmount and free in-memory structs
    flush any dirty buffers?

    code sourced HEAVILY from msdosds_vfsops unmount
    https://github.com/freebsd/freebsd-src/blob/releng/13.0/sys/fs/msdosfs/msdosfs_vfsops.c

*/
static int
ddfs_unmount(struct mount* mp, int mntflags) {
    struct ddfs_mount* mnt;
    mnt       = VFSTODDFS(mp);
    int error = 0;
    int flags = 0;

    // suspend further writes to the file system
    error = vfs_write_suspend_umnt(mp);
    if (error != 0)
        return (error);

    // flushes vnode buffers...?
    if ((mntflags & MNT_FORCE) != 0)
        flags |= FORCECLOSE;
    error = vflush(mp, 0, flags, curthread);
    if (error != 0 && error != ENXIO) {
        vfs_write_resume(mp, VR_START_WRITE);
        return (error);
    }

    vfs_write_resume(mp, VR_START_WRITE);    // why would we reallow writes?
    /*
        Close our fs geom, release mount point, release the device vnode,
        release the device (?), free the mount struct
    */
    g_topology_lock();
    g_vfs_close(mnt->consumer_geom);
    g_topology_unlock();
    atomic_store_rel_ptr((uintptr_t*)&mnt->dev->si_mountpt, 0);
    vrele(mnt->devvp);    // decrease the disk's vnode reference count
    dev_rel(mnt->dev);    // decrease ref count of our fs
    free(mnt, M_DDFSMNT);
    mp->mnt_data = NULL;

    // I have no idea what this is
    MNT_ILOCK(mp);
    mp->mnt_flag &= ~MNT_LOCAL;
    MNT_IUNLOCK(mp);
    return (error);
}

/* Just return stats about fs by putting it in sbp*/
static int
ddfs_statfs(struct mount* mp, struct statfs* sbp) {
    struct ddfs_mount* mnt;
    mnt = VFSTODDFS(mp);
    // These are the stats we can set:
    // ------------------------------------------------------
    // uint32_t f_version;     /* structure version number */
    // uint32_t f_type;        /* type of filesystem */
    // uint64_t f_flags;       /* copy of mount exported flags */
    // uint64_t f_bsize;       /* filesystem fragment size */
    // uint64_t f_iosize;      /* optimal transfer block size */
    // uint64_t f_blocks;      /* total data blocks in filesystem */
    // uint64_t f_bfree;       /* free blocks in filesystem */
    // int64_t f_bavail;       /* free blocks avail to non-superuser */
    // uint64_t f_files;       /* total file nodes in filesystem */
    // int64_t f_ffree;        /* free nodes avail to non-superuser */
    // uint64_t f_syncwrites;  /* count of sync writes since mount */
    // uint64_t f_asyncwrites; /* count of async writes since mount */
    // uint64_t f_syncreads;   /* count of sync reads since mount */
    // uint64_t f_asyncreads;  /* count of async reads since mount */
    // uint64_t f_spare[10];   /* unused spare */
    // uint32_t f_namemax;     /* maximum filename length */
    // uid_t f_owner;          /* user that mounted the filesystem */
    // fsid_t f_fsid;          /* filesystem id */

    sbp->f_iosize  = mnt->superblock.block_size;
    sbp->f_blocks  = mnt->superblock.total_data_blocks;
    sbp->f_bfree   = mnt->superblock.total_data_blocks - mnt->superblock.used_data_blocks;
    sbp->f_files   = mnt->superblock.used_file_inodes;
    sbp->f_namemax = MAX_FILENAME_LEN;
    return (0);
}

/*
    Flush fs io buffers

    Code taken from msdosfs_sync:
    https://github.com/freebsd/freebsd-src/blob/releng/13.0/sys/fs/msdosfs/msdosfs_vfsops.c


    We're calling VOP_SYNC on each vnode to write it back
*/
static int
ddfs_sync(struct mount* mp, int waitfor) {
    struct ddfs_mount* mnt = VFSTODDFS(mp);
    struct vnode *vp, *nvp;
    // struct file_inode* node;
    struct thread* td = curthread;
    int error, allerror;
    error = allerror = 0;
/*
    Write back modified nodes
*/
loop:
    // Loop thru vnode list in mount struct and return each vnode to vp
    MNT_VNODE_FOREACH_ALL(vp, mp, nvp) {
        // vnode with no type
        if (vp->v_type == VNON) {
            VI_UNLOCK(vp);
            continue;
        }

        // get file_inode and see if we have modified the vnode, if not, just unlock it
        // should prob add flags to our node
        // node = vp->v_data;
        if (vp->v_bufobj.bo_dirty.bv_cnt == 0 || waitfor == MNT_LAZY) {
            VI_UNLOCK(vp);
            continue;
        }

        // gets a vnode from the free list
        // (vnodes are kept on a free list when not in use, but they still refer to
        // valid files)
        error = vget(vp, LK_EXCLUSIVE | LK_NOWAIT | LK_INTERLOCK);
        if (error) {
            if (error == ENOENT) {
                MNT_VNODE_FOREACH_ALL_ABORT(mp, nvp);
                goto loop;
            }
            continue;
        }
        // -------------------------------------------------------

        // write back each vnode back to disk
        error = VOP_FSYNC(vp, waitfor, td);
        if (error)
            allerror = error;
        VOP_UNLOCK(vp);    // WHERE is this actually being locked??????????????????????????????
        vput(vp);          // decrease the vnode's reference count
    }

    /*
        Tell the disk driver to write back its dirty buffers
    */
    if (waitfor != MNT_LAZY) {
        vn_lock(mnt->devvp, LK_EXCLUSIVE | LK_RETRY);
        error = VOP_FSYNC(mnt->devvp, waitfor, td);
        VOP_UNLOCK(mnt->devvp);
        if (error)
            allerror = error;
    }

    // Suspend further writes to the filesystem
    if (allerror == 0 && waitfor == MNT_SUSPEND) {
        MNT_ILOCK(mp);
        mp->mnt_kern_flag |= MNTK_SUSPEND2 | MNTK_SUSPENDED;
        MNT_IUNLOCK(mp);
    }
    return (allerror);
}

/* The root vnode of the filesystem used for pathname translation

    From Aidian via Piazza:
        AFAIK here’s root needs:
            1. retrieve cached vnode with vfs_hash_get. if found, return it, otherwise, goto step 2
            2. allocate a new vnode; getnewvnode
            3. lock the vnode; vn_lock
            4. associate the vnode with our filesystem mount; insmntque
            5. insert new vnode into the vfs hash; vfs_hash_insert
            6. allow vnode lock to be shared; VN_LOCK_ASHARE
            7. set root flag and type == directory

    msdosfs:
    - https://github.com/freebsd/freebsd-src/blob/releng/13.0/sys/fs/msdosfs/msdosfs_vfsops.c


    TODO: this currently returns a vnode with no backing inode
*/
static int
ddfs_root(struct mount* mp, int flags, struct vnode** vpp) {
    struct ddfs_mount* mnt = VFSTODDFS(mp);
    int error;

    if ((error = get_node(mnt, vpp, DDFS_ROOT_INO)) != 0) {
        return error;
    };

    return 0;
}

int
ddfs_vget(struct mount* mp, ino_t ino, int flags, struct vnode** vpp) {
    int error;
    error = get_node((struct ddfs_mount*)mp->mnt_data, vpp, ino);
    if (error) {
        return error;
    }
    return 0;
}

static struct vfsops ddfs_vfsops = {
    .vfs_mount   = ddfs_mount,
    .vfs_statfs  = ddfs_statfs,
    .vfs_sync    = ddfs_sync,
    .vfs_unmount = ddfs_unmount,
    .vfs_root    = ddfs_root,
    .vfs_vget    = ddfs_vget,
};

VFS_SET(ddfs_vfsops, ddfs, 0);
MODULE_VERSION(ddfs, 1);
