# JRA FreeBSD Deduplicating Filesystem

## About

As a group, we built a FFS-like hierarchical indexed file system as a capstone project for our Embedded Operating Systems course. The goal was to build a filesystem which mimicked FFS, and provided data deduplication. The filesystem is designed to run on FreeBSD 13.0, and take over an entire drive for its use. For an explanation of how our file system works, see our design document in `/docs`

## Filesystem

### Build info

- Use 'make' from the root folder of the repo to build the kernel module. Then run 'sudo kldload ./ddfs.ko' or `sudo make load` again
- alternatively, run 'sudo make load' twice (for some reason compilation always fails the first time)

### DDFS usage:

- sudo kldload ./ddfs.ko or 'make load'
- sudo mount -t ddfs /dev/your_device /your/mount/point

### Functionality:

- Our filesystem is capable of mounting and unmounting successfully
- We have lookup(), read(), write(), create(), readdir(), getattr(), and remove() functioning
- deduplication is fully functional

### Missing Functionality:

- files are limited in size to 828KB because we did not have enough time to get all of the indirect blocks working (3 direct and 1 indirect block are implemented)
- we do not support creation of additional hard links for files
- permissions are omitted
- truncate is unimplemented
- we were not able to edit our files -- we can rewrite but not edit (I think this is because we cannot seek into our files)

## Tools

### Build info

To build the tools, navigate to /tools and run 'make'

### mkddfs Usage:

- To create the filesystem, run (it may take several minutes to write everything):
  - sudo ./mkkvfs /disk-name

### ddfsstat

ddfsstat allows you to see how much space deduplication as saved you!

- to retrieve space saving stats, run:
  - ./ddfsstat /your/file/system/mount/point

### Known bugs

- due to a bug in find_free_inode(), total file inodes are currently limited to about 30

### Citations:

- code sourced from msdosfs, ffs
- examples looked at in the above + iso, tempfs
- specific citations in the sourcecode
