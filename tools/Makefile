CC = cc
CFLAGS  = -Wall -Wextra -Wpedantic -Wshadow -std=c99 -lm -lcrypto

default: mkddfs ddfs_stat

mkddfs:  mkddfs.c
	$(CC) $(CFLAGS) -o mkddfs mkddfs.c

ddfs_stat: ddfs_stat.c
	$(CC) $(CFLAGS) -o ddfsstat ddfs_stat.c

clean: 
	rm mkddfs ddfsstat
