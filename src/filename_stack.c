#include "filename_stack.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_key_t filenames_key;

struct filename_stack {
	/* This can be NULL. Abort all operations if this is the case. */
	char const **filenames;
	unsigned int len;
	unsigned int size;
};

static void
fnstack_discard(void *arg)
{
	struct filename_stack *files = arg;
	free(files->filenames);
	free(files);
}

/** Initializes this module. Call once per runtime lifetime. */
void
fnstack_init(void)
{
	int error;

	error = pthread_key_create(&filenames_key, fnstack_discard);
	if (error) {
		fprintf(stderr,
		    "Fatal: Errcode %d while attempting to initialize thread variable.\n",
		    error);
		exit(error);
	}
}

/** Initializes the current thread's fnstack. Call once per thread. */
void
fnstack_store(void)
{
	struct filename_stack *files;
	int error;

	files = malloc(sizeof(struct filename_stack));
	if (files == NULL)
		return;

	files->filenames = malloc(32 * sizeof(char *));
	if (files->filenames == NULL) {
		free(files);
		return;
	}

	files->len = 0;
	files->size = 32;

	error = pthread_setspecific(filenames_key, files);
	if (error)
		fprintf(stderr, "pthread_setspecific() returned %d.", error);
}

static struct filename_stack *
get_file_stack(void)
{
	struct filename_stack *files;

	files = pthread_getspecific(filenames_key);
	if (files == NULL)
		fprintf(stderr, "This thread lacks a files stack.\n");

	return files;
}

static char const *
get_filename(char const *file_path)
{
	char *slash = strrchr(file_path, '/');
	return (slash != NULL) ? (slash + 1) : file_path;
}

/**
 * Call this function every time you're about to start processing a new file.
 * Any pr_err()s and friends will now include the new file name.
 * Use fnstack_pop() to revert back to the previously stacked file name.
 */
void
fnstack_push(char const *file_path)
{
	struct filename_stack *files;
	char const **tmp;

	files = get_file_stack();
	if (files == NULL || files->filenames == NULL)
		return;

	if (files->len >= files->size) {
		tmp = realloc(files->filenames, 2 * files->size * sizeof(char *));
		if (tmp == NULL) {
			/* Oh noes */
			free(files->filenames);
			files->filenames = NULL;
			return;
		}

		files->filenames = tmp;
		files->size *= 2;
	}

	files->filenames[files->len++] = get_filename(file_path);
}

char const *
fnstack_peek(void)
{
	struct filename_stack *files;

	files = get_file_stack();
	if (files == NULL || files->filenames == NULL || files->len == 0)
		return NULL;

	return files->filenames[files->len - 1];
}

void
fnstack_pop(void)
{
	struct filename_stack *files;

	files = get_file_stack();
	if (files == NULL || files->filenames == NULL || files->len == 0)
		return;

	files->len--;
}
