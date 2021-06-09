# Test Scripts
Run 'make' to build test scripts.

## mktestfs
### Description:  
Writes the first 12KB of files in /src to the filesystem  
### Usage:  
First, make sure you have built the filesystem with mkddfs (you don't have to do this every time)
- run: sudo ./mktestfs /dev/device

## rdtest
### Description
Reads the files in /src and compares them with our version on disk, prints out whether the files match
### Usage
Run mktestfs to initialize the filesystem with current versions of source files.
- run: ./rdtest /mounted/filesystem/path
### Bugs
- For some reason the program always hangs at first until you hit 'enter'
- The first file always says it doesn't match, but as far as I can tell it does, so I think we can disregard it.