#include "thread_var.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <sys/socket.h>

static pthread_key_t state_key;
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

/** Initializes this entire module. Call once per runtime lifetime. */
void
thvar_init(void)
{
	int error;

	error = pthread_key_create(&state_key, NULL);
	if (error) {
		fprintf(stderr,
		    "Fatal: Errcode %d while initializing the validation state thread variable.\n",
		    error);
		exit(error);
	}

	error = pthread_key_create(&filenames_key, fnstack_discard);
	if (error) {
		fprintf(stderr,
		    "Fatal: Errcode %d while initializing the file name stack thread variable.\n",
		    error);
		exit(error);
	}
}

/* Puts @state in the current thread's variable pool. Call once per thread. */
int
state_store(struct validation *state)
{
	int error;

	error = pthread_setspecific(state_key, state);
	if (error)
		fprintf(stderr, "pthread_setspecific() returned %d.", error);

	return error;
}

/* Returns the current thread's validation state. */
struct validation *
state_retrieve(void)
{
	struct validation *state;

	state = pthread_getspecific(state_key);
	if (state == NULL)
		fprintf(stderr, "Programming error: This thread lacks a validation state.\n");

	return state;
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
	/* char *slash = strrchr(file_path, '/'); */
	return /* (slash != NULL) ? (slash + 1) : */ file_path;
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

/* Returns the file name on the top of the file name stack. */
char const *
fnstack_peek(void)
{
	struct filename_stack *files;

	files = get_file_stack();
	if (files == NULL || files->filenames == NULL || files->len == 0)
		return NULL;

	return files->filenames[files->len - 1];
}

/* Reverts the last fnstack_push(). */
void
fnstack_pop(void)
{
	struct filename_stack *files;

	files = get_file_stack();
	if (files == NULL || files->filenames == NULL || files->len == 0)
		return;

	files->len--;
}

static char const *
addr2str(int af, void *addr, char *(*buffer_cb)(struct validation *))
{
	struct validation *state;

	state = state_retrieve();
	if (!state)
		return NULL;

	return inet_ntop(af, addr, buffer_cb(state), INET6_ADDRSTRLEN);
}

/**
 * Returns @addr, converted to a printable string. Intended for minimal clutter
 * address printing.
 *
 * The buffer the string is stored in was allocated in a thread variable, so it
 * will be overridden the next time you call this function. Also, you should not
 * free it.
 *
 * The buffer is the same as v6addr2str()'s, so don't mix them either.
 */
char const *
v4addr2str(struct in_addr *addr)
{
	return addr2str(AF_INET, addr, validation_get_ip_buffer1);
}

/**
 * Same as v4addr2str(), except a different buffer is used.
 */
char const *
v4addr2str2(struct in_addr *addr)
{
	return addr2str(AF_INET, addr, validation_get_ip_buffer2);
}

/**
 * See v4addr2str().
 */
char const *
v6addr2str(struct in6_addr *addr)
{
	return addr2str(AF_INET6, addr, validation_get_ip_buffer1);
}

/**
 * See v4addr2str2().
 */
char const *
v6addr2str2(struct in6_addr *addr)
{
	return addr2str(AF_INET6, addr, validation_get_ip_buffer2);
}
