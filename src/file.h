#ifndef SRC_FILE_H_
#define SRC_FILE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>

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
int file_write(char const *, FILE **, struct stat *);
void file_close(FILE *);

int file_load(char const *, struct file_contents *);
void file_free(struct file_contents *);

bool file_valid(char const *);

#endif /* SRC_FILE_H_ */
