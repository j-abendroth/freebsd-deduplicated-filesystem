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

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vnode_pager.h>


#include "kvs.h"
#include "ddfs.h"
#include "dir.h"

// clang-format on

extern int get_hash_at_block_off(struct vnode* vp, uint32_t off, kvs_key* key);
extern int kvs_read_block(kvs_key* hash_key, struct buf** bpp, struct ddfs_mount* mnt);
extern int kvs_write_block(char* block_buf, kvs_key* hash_key, struct ddfs_mount* mnt);

static int ddfs_lookup_(struct vnode* dvp, struct vnode** vpp, struct componentname* cnp);
int ddfs_lookup(struct vop_cachedlookup_args* ap);

int
ddfs_lookup(struct vop_cachedlookup_args* ap) {
    return (ddfs_lookup_(ap->a_dvp, ap->a_vpp, ap->a_cnp));
}

/*
 * TODOS:
 * 	- may need to change the way bmask works -- def double check that!!
 *	- there are checks for BYTE_ORDER => idk if we want to use this
 *
 * Most of the following code taken from ufs_lookup_()
 * https://github.com/freebsd/freebsd-src/blob/stable/13/sys/ufs/ufs/ufs_lookup.c
 */
static int
ddfs_lookup_(struct vnode* vdp, struct vnode** vpp, struct componentname* cnp) {
    struct file_inode* dp; /* inode for directory being searched */
    struct ddfs_mount* mnt;
    struct buf* bp;         /* a buffer of directory entries */
    struct direct* ep;      /* the current directory entry */
    int entryoffsetinblock; /* offset of ep in bp's buffer */
    enum { NONE, COMPACT, FOUND } slotstatus;
    doff_t slotoffset; /* offset of area with free space */
    doff_t i_diroff;   /* cached i_diroff value. */
    doff_t i_offset;   /* cached i_offset value. */
    int slotsize;      /* size of area at slotoffset */
    int slotfreespace; /* amount of space free in slot */
    int slotneeded;    /* size of the entry we're seeking */
    int numdirpasses;  /* strategy for directory search */
    doff_t endsearch;  /* offset to end directory search */
    doff_t prevoff;    /* prev entry dp->i_offset */
    struct vnode* pdp; /* saved dp during symlink work */
    struct vnode* tdp; /* returned by VFS_VGET */
    doff_t enduseful;  /* pointer past last used dir slot */
    u_long bmask;      /* block offset mask */
    int namlen, error;
    // struct ucred* cred = cnp->cn_cred;
    int flags   = cnp->cn_flags;
    int nameiop = cnp->cn_nameiop;
    ino_t ino /*, ino1 */;
    int ltype;
    kvs_key key;

    if (vpp != NULL)
        *vpp = NULL;

    dp  = VTOI(vdp);
    mnt = dp->mnt;
    // if (dp->i_effnlink == 0) // not using this variable in our inode rn
    //     return (ENOENT);

    /*
     * Create a vm object if vmiodirenable is enabled.
     * Alternatively we could call vnode_create_vobject
     * in VFS_VGET but we could end up creating objects
     * that are never used.
     */

    // this is highly questionable! ---------------------------------
    vnode_create_vobject(vdp, dp->dinode->di_size, cnp->cn_thread);
    // this is highly questionable! ---------------------------------

    // bmask = vdp->v_mount->mnt_stat.f_iosize - 1;
    bmask = BLOCKSIZE - 1;

    // restart:
    bp         = NULL;
    slotoffset = -1;

    /*
     * We now have a segment name to search for, and a directory to search.
     *
     * Suppress search for slots unless creating
     * file and at end of pathname, in which case
     * we watch for a place to put the new file in
     * case it doesn't already exist.
     */
    ino           = 0;
    i_diroff      = dp->i_diroff;
    slotstatus    = FOUND;
    slotfreespace = slotsize = slotneeded = 0;
    if ((nameiop == CREATE || nameiop == RENAME) && (flags & ISLASTCN)) {
        slotstatus = NONE;
        slotneeded = DIRECTSIZ(cnp->cn_namelen);    // The DIRSIZ macro gives the minimum record length
                                                    // which will hold* the directory entry.
    }

    /*
     * If there is cached information on a previous search of
     * this directory, pick up where we last left off.
     * We cache only lookups as these are the most common
     * and have the greatest payoff. Caching CREATE has little
     * benefit as it usually must search the entire directory
     * to determine that the entry does not exist. Caching the
     * location of the last DELETE or RENAME has not reduced
     * profiling time and hence has been removed in the interest
     * of simplicity.
     */
    if (nameiop != LOOKUP || i_diroff == 0 || i_diroff >= dp->i_size) {
        entryoffsetinblock = 0;
        i_offset           = 0;
        numdirpasses       = 1;
    } else {
        i_offset = i_diroff;
        if ((entryoffsetinblock = i_offset & bmask)
            && (error = get_hash_at_block_off(vdp, i_offset / BLOCKSIZE, &key))) {
            return (error);
        }

        if ((error = kvs_read_block(&key, &bp, mnt)) != 0) {
            return error;
        }
        numdirpasses = 2;
        nchstats.ncs_2passes++;
    }
    prevoff   = i_offset;
    endsearch = roundup2(dp->i_size, DIRBLKSIZ);
    enduseful = 0;
searchloop:
    while (i_offset < endsearch) {
        /*
         * If necessary, get the next directory block.
         */
        if ((i_offset & bmask) == 0) {
            if (bp != NULL)
                brelse(bp);
            if ((error = get_hash_at_block_off(vdp, i_offset / BLOCKSIZE, &key)) != 0) {
                return error;
            }
            if ((error = kvs_read_block(&key, &bp, mnt)) != 0) {
                return error;
            }
            entryoffsetinblock = 0;
        }
        /*
         * If still looking for a slot, and at a DIRBLKSIZE
         * boundary, have to start looking for free space again.
         */
        if (slotstatus == NONE && (entryoffsetinblock & (DIRBLKSIZ - 1)) == 0) {
            slotoffset    = -1;
            slotfreespace = 0;
        }
        /*
         * Get pointer to next entry.
         * Full validation checks are slow, so we only check
         * enough to insure forward progress through the
         * directory.
         */
        // we will not perform validation checks for now

        ep = (struct direct*)((char*)bp->b_data + entryoffsetinblock);
        if (ep->d_reclen == 0 || ep->d_reclen > DIRBLKSIZ - (entryoffsetinblock & (DIRBLKSIZ - 1))) {
            int i;

            i = DIRBLKSIZ - (entryoffsetinblock & (DIRBLKSIZ - 1));
            i_offset += i;
            entryoffsetinblock += i;
            continue;
        }

        /*
         * If an appropriate sized slot has not yet been found,
         * check to see if one is available. Also accumulate space
         * in the current block so that we can determine if
         * compaction is viable.
         */
        if (slotstatus != FOUND) {
            int size = ep->d_reclen;

            if (ep->d_ino != 0)
                size -= DIRSIZ(ep);
            if (size > 0) {
                if (size >= slotneeded) {
                    slotstatus = FOUND;
                    slotoffset = i_offset;
                    slotsize   = ep->d_reclen;
                } else if (slotstatus == NONE) {
                    slotfreespace += size;
                    if (slotoffset == -1)
                        slotoffset = i_offset;
                    if (slotfreespace >= slotneeded) {
                        slotstatus = COMPACT;
                        slotsize   = i_offset + ep->d_reclen - slotoffset;
                    }
                }
            }
        }

        /*
         * Check for a name match.
         */
        if (ep->d_ino) {
            namlen = ep->d_namlen;

            // bcmp() compares the names
            if (namlen == cnp->cn_namelen && (cnp->cn_nameptr[0] == ep->d_name[0])
                && !bcmp(cnp->cn_nameptr, ep->d_name, (unsigned)namlen)) {
                /*
                 * Save directory entry's inode number and
                 * reclen in ndp->ni_ufs area, and release
                 * directory buffer.
                 */
                if (vdp->v_mount->mnt_maxsymlinklen > 0 && ep->d_type == DT_WHT) {
                    slotstatus = FOUND;
                    slotoffset = i_offset;
                    slotsize   = ep->d_reclen;
                    enduseful  = dp->i_size;
                    cnp->cn_flags |= ISWHITEOUT;
                    numdirpasses--;
                    goto notfound;
                }
                ino = ep->d_ino;
                goto found;
            }
        } else {
        }

        prevoff = i_offset;
        i_offset += ep->d_reclen;
        entryoffsetinblock += ep->d_reclen;
        if (ep->d_ino)
            enduseful = i_offset;
    }

notfound:

    /*
     * If we started in the middle of the directory and failed
     * to find our target, we must check the beginning as well.
     */
    if (numdirpasses == 2) {
        numdirpasses--;
        i_offset  = 0;
        endsearch = i_diroff;
        goto searchloop;
    }
    if (bp != NULL)
        brelse(bp);
    /*
     * If creating, and at end of pathname and current
     * directory has not been removed, then can consider
     * allowing file to be created.
     */
    if ((nameiop == CREATE || nameiop == RENAME
         || (nameiop == DELETE && (cnp->cn_flags & DOWHITEOUT) && (cnp->cn_flags & ISWHITEOUT)))
        && (flags & ISLASTCN)) {
        /*
         * Access for write is interpreted as allowing
         * creation of files in the directory.
         *
         * XXX: Fix the comment above.
         */

        // permission check
        // if (flags & WILLBEDIR) {
        //     error = VOP_ACCESSX(vdp, VWRITE | VAPPEND, cred, cnp->cn_thread);
        // } else {
        //     error = VOP_ACCESS(vdp, VWRITE, cred, cnp->cn_thread);
        // }
        // if (error)
        //     return (error);
        /*
         * Return an indication of where the new directory
         * entry should be put.  If we didn't find a slot,
         * then set dp->i_count to 0 indicating
         * that the new slot belongs at the end of the
         * directory. If we found a slot, then the new entry
         * can be put in the range from dp->i_offset to
         * dp->i_offset + dp->i_count.
         */
        if (slotstatus == NONE) {
            dp->i_offset = roundup2(dp->i_size, DIRBLKSIZ);
            dp->i_count  = 0;
            enduseful    = dp->i_offset;
        } else if (nameiop == DELETE) {
            dp->i_offset = slotoffset;
            if ((dp->i_offset & (DIRBLKSIZ - 1)) == 0)
                dp->i_count = 0;
            else
                dp->i_count = dp->i_offset - prevoff;
        } else {
            dp->i_offset = slotoffset;
            dp->i_count  = slotsize;
            if (enduseful < slotoffset + slotsize)
                enduseful = slotoffset + slotsize;
        }
        dp->i_endoff = roundup2(enduseful, DIRBLKSIZ);
        /*
         * We return with the directory locked, so that
         * the parameters we set up above will still be
         * valid if we actually decide to do a direnter().
         * We return ni_vp == NULL to indicate that the entry
         * does not currently exist; we leave a pointer to
         * the (locked) directory inode in ndp->ni_dvp.
         * The pathname buffer is saved so that the name
         * can be obtained later.
         *
         * NB - if the directory is unlocked, then this
         * information cannot be used.
         */
        cnp->cn_flags |= SAVENAME;
        return (EJUSTRETURN);
    }
    /*
     * Insert name into cache (as non-existent) if appropriate.
     */
    if ((cnp->cn_flags & MAKEENTRY) != 0)
        cache_enter(vdp, NULL, cnp);
    return (ENOENT);

found:
    // if (dd_ino != NULL)
    //     *dd_ino = ino;
    if (numdirpasses == 2)
        nchstats.ncs_pass2++;
    /*
     * Check that directory length properly reflects presence
     * of this entry.
     */
    if (i_offset + DIRSIZ(ep) > dp->i_size) {
        dp->i_size          = i_offset + DIRSIZ(ep);
        dp->dinode->di_size = dp->i_size;
        dp->i_flags |= IN_SIZEMOD | IN_CHANGE | IN_UPDATE;
    }
    brelse(bp);

    /*
     * Found component in pathname.
     * If the final component of path name, save information
     * in the cache as to where the entry was found.
     */
    if ((flags & ISLASTCN) && nameiop == LOOKUP)
        dp->i_diroff = rounddown2(i_offset, DIRBLKSIZ);

    /*
     * If deleting, and at end of pathname, return
     * parameters which can be used to remove file.
     */
    if (nameiop == DELETE && (flags & ISLASTCN)) {
        if (flags & LOCKPARENT)
            ASSERT_VOP_ELOCKED(vdp, __FUNCTION__);

        if (VOP_ISLOCKED(vdp) == LK_EXCLUSIVE) {
            /*
             * Return pointer to current entry in
             * dp->i_offset, and distance past previous
             * entry (if there is a previous entry in this
             * block) in dp->i_count.
             *
             * We shouldn't be setting these in the
             * WANTPARENT case (first lookup in rename()), but any
             * lookups that will result in directory changes will
             * overwrite these.
             */
            SET_I_OFFSET(dp, i_offset);
            if ((I_OFFSET(dp) & (DIRBLKSIZ - 1)) == 0)
                SET_I_COUNT(dp, 0);
            else
                SET_I_COUNT(dp, I_OFFSET(dp) - prevoff);
        }
        // if (dd_ino != NULL)
        //     return (0);

        /*
         * Save directory inode pointer in ndp->ni_dvp for
         * dirremove().
         */
        if ((error = VFS_VGET(vdp->v_mount, ino, LK_EXCLUSIVE, &tdp)) != 0)
            return (error);
        // this is just a permission check, always allow it for now
        // error = ufs_delete_denied(vdp, tdp, cred, cnp->cn_thread);
        // if (error) {
        //     vput(tdp);
        //     return (error);
        // }
        if (dp->i_number == ino) {
            VREF(vdp);
            *vpp = vdp;
            vput(tdp);
            return (0);
        }

        *vpp = tdp;
        return (0);
    }

    /*
     * If rewriting (RENAME), return the inode and the
     * information required to rewrite the present directory
     * Must get inode of directory entry to verify it's a
     * regular file, or empty directory.
     */
    if (nameiop == RENAME && (flags & ISLASTCN)) {
        // permission checking
        // if (flags & WILLBEDIR) {
        //     error = VOP_ACCESSX(vdp, VWRITE | VAPPEND, cred, cnp->cn_thread);
        // } else {
        //     error = VOP_ACCESS(vdp, VWRITE, cred, cnp->cn_thread);
        // }
        // if (error)
        //     return (error);
        /*
         * Careful about locking second inode.
         * This can only occur if the target is ".".
         */
        SET_I_OFFSET(dp, i_offset);
        if (dp->i_number == ino)
            return (EISDIR);
        // if (dd_ino != NULL)
        //     return (0);
        if ((error = VFS_VGET(vdp->v_mount, ino, LK_EXCLUSIVE, &tdp)) != 0)
            return (error);

        // permissions - skip for now
        // error = ufs_delete_denied(vdp, tdp, cred, cnp->cn_thread);
        // if (error) {
        //     vput(tdp);
        //     return (error);
        // }
        *vpp = tdp;
        cnp->cn_flags |= SAVENAME;
        return (0);
    }
    // if (dd_ino != NULL)
    //     return (0);

    /*
     * Step through the translation in the name.  We do not `vput' the
     * directory because we may need it again if a symbolic link
     * is relative to the current directory.  Instead we save it
     * unlocked as "pdp".  We must get the target inode before unlocking
     * the directory to insure that the inode will not be removed
     * before we get it.  We prevent deadlock by always fetching
     * inodes from the root, moving down the directory tree. Thus
     * when following backward pointers ".." we must unlock the
     * parent directory before getting the requested directory.
     * There is a potential race condition here if both the current
     * and parent directories are removed before the VFS_VGET for the
     * inode associated with ".." returns.  We hope that this occurs
     * infrequently since we cannot avoid this race condition without
     * implementing a sophisticated deadlock detection algorithm.
     * Note also that this simple deadlock detection scheme will not
     * work if the filesystem has any hard links other than ".."
     * that point backwards in the directory structure.
     */
    pdp = vdp;
    if (flags & ISDOTDOT) {
        error = vn_vget_ino(pdp, ino, cnp->cn_lkflags, &tdp);
        if (error)
            return (error);

        /*
         * Recheck that ".." entry in the vdp directory points
         * to the inode we looked up before vdp lock was
         * dropped.
         */

        // we will skip this step for now

        // error = ufs_lookup_ino(pdp, NULL, cnp, &ino1);
        // if (error) {
        //     vput(tdp);
        //     return (error);
        // }
        // if (ino1 != ino) {
        //     vput(tdp);
        //     goto restart;
        // }

        *vpp = tdp;
    } else if (dp->i_number == ino) {
        VREF(vdp); /* we want ourself, ie "." */
        /*
         * When we lookup "." we still can be asked to lock it
         * differently.
         */
        ltype = cnp->cn_lkflags & LK_TYPE_MASK;
        if (ltype != VOP_ISLOCKED(vdp)) {
            if (ltype == LK_EXCLUSIVE)
                vn_lock(vdp, LK_UPGRADE | LK_RETRY);
            else /* if (ltype == LK_SHARED) */
                vn_lock(vdp, LK_DOWNGRADE | LK_RETRY);
            /*
             * Relock for the "." case may left us with
             * reclaimed vnode.
             */
            if (VN_IS_DOOMED(vdp)) {
                vrele(vdp);
                return (ENOENT);
            }
        }
        *vpp = vdp;
    } else {
        error = VFS_VGET(pdp->v_mount, ino, cnp->cn_lkflags, &tdp);
        if (error == 0 && VTOI(tdp)->i_mode == 0) {
            vgone(tdp);
            vput(tdp);
            error = ENOENT;
        }
        if (error)
            return (error);
        *vpp = tdp;
    }

    /*
     * Insert name into cache if appropriate.
     */
    if (cnp->cn_flags & MAKEENTRY)
        cache_enter(vdp, *vpp, cnp);
    return (0);
}