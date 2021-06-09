CC = cc
FLAGS = -Wall -Wextra -Wpedantic -Wshadow -std=c99 -lcrypto

all: mktestfs rdtest wrtest

mktestfs: mktestfs.c
	$(CC) $(FLAGS) -o mktestfs mktestfs.c

rdtest: ddfs_read_test_new.c
	$(CC) $(FLAGS) -o rdtest ddfs_read_test_new.c

wrtest: ddfs_write_test.c
	$(CC) $(FLAGS) -o wrtest ddfs_write_test.c

clean:
	rm mktestfs rdtest wrtest
