#ifndef SRC_FILE_H_
#define SRC_FILE_H_

#include <stdbool.h>
#include <stdio.h> /* FILE, remove() */
#include <sys/types.h> /* stat, closedir(), mkdir() */
#include <sys/stat.h> /* stat, mkdir() */
#include <unistd.h> /* stat(), rmdir() */

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
int file_write(char const *, FILE **);
void file_close(FILE *);

int file_load(char const *, struct file_contents *);
void file_free(struct file_contents *);

bool file_valid(char const *);
long file_get_modification_time(char const *);

typedef int (*process_file_cb)(char const *, void *);
int process_file_or_dir(char const *, char const *, bool, process_file_cb,
    void *);

typedef int (*pr_errno_cb)(int, const char *, ...);
bool valid_file_or_dir(char const *, bool, bool, pr_errno_cb);

int create_dir_recursive(char const *);
int delete_dir_recursive_bottom_up(char const *);

#endif /* SRC_FILE_H_ */
