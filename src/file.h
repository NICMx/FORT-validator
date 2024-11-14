#ifndef SRC_FILE_H_
#define SRC_FILE_H_

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * The entire contents of the file, loaded into a buffer.
 *
 * Instances of this struct are expected to live on the stack.
 */
struct file_contents {
	unsigned char *buffer;
	size_t buffer_size;
};

int file_open(char const *, FILE **, struct stat *);
int file_write(char const *, char const *, FILE **);
int file_write_txt(char const *, char const *);
int file_write_bin(char const *, unsigned char const *, size_t);
void file_close(FILE *);

int file_load(char const *, struct file_contents *, bool);
void file_free(struct file_contents *);

int file_exists(char const *);

int file_rm_f(char const *);
int file_rm_rf(char const *);
int file_mkdir(char const *, bool);
void file_ln(char const *, char const *);

struct cache_sequence {
	char *prefix;
	unsigned long next_id;
	size_t pathlen;
	bool free_prefix;
};

void cseq_init(struct cache_sequence *, char *, bool);
char *cseq_next(struct cache_sequence *);

/*
 * Remember that this API is awkward:
 *
 * 1. Check errno after the loop.
 * 2. Probably also check S_ISDOTS() during the loop.
 * 3. Do closedir() even on error.
 */
#define FOREACH_DIR_FILE(dir, file) for (				\
		errno = 0, file = readdir(dir);				\
		file != NULL;						\
		errno = 0, file = readdir(dir)				\
	)

#define S_ISDOTS(file) \
	(strcmp((file)->d_name, ".") == 0 || strcmp((file)->d_name, "..") == 0)

#endif /* SRC_FILE_H_ */
