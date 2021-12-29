#include "thread_var.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "config.h"

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
int
thvar_init(void)
{
	int error;

	error = pthread_key_create(&state_key, NULL);
	if (error) {
		pr_op_err(
		    "Fatal: Errcode %d while initializing the validation state thread variable.",
		    error);
		return error;
	}

	/*
	 * Hm. It's a little odd.
	 * fnstack_discard() is not being called on program termination.
	 * Not sure if this is an implementation quirk.
	 * We'll just have to delete it manually.
	 */
	error = pthread_key_create(&filenames_key, fnstack_discard);
	if (error) {
		pr_op_err(
		    "Fatal: Errcode %d while initializing the file name stack thread variable.",
		    error);
		return error;
	}

	return 0;
}

/* Puts @state in the current thread's variable pool. Call once per thread. */
int
state_store(struct validation *state)
{
	int error;

	error = pthread_setspecific(state_key, state);
	if (error)
		pr_op_err("pthread_setspecific() returned %d.", error);

	return error;
}

/*
 * Returns the current thread's validation state.
 *
 * The state is stored in the thread because it's needed in both extremely high
 * and extremely low level functions; it would cause catastrophic clutter if
 * passed around in argument lists.
 *
 * Cannot return NULL.
 */
struct validation *
state_retrieve(void)
{
	struct validation *state;

	state = pthread_getspecific(state_key);
	if (state == NULL)
		pr_crit("Programming error: This thread lacks a validation state.");

	return state;
}

/** Initializes the current thread's fnstack. Call once per thread. */
void
fnstack_init(void)
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
		pr_op_err("pthread_setspecific() returned %d.", error);
}

void
fnstack_cleanup(void)
{
	struct filename_stack *files;
	int error;

	files = pthread_getspecific(filenames_key);
	if (files == NULL)
		return;

	fnstack_discard(files);

	error = pthread_setspecific(filenames_key, NULL);
	if (error)
		pr_op_err("pthread_setspecific() returned %d.", error);
}

/**
 * Call this function every time you're about to start processing a new file.
 * Any pr_op_err()s and friends will now include the new file name.
 * Use fnstack_pop() to revert back to the previously stacked file name.
 * @file is not cloned; it's expected to outlive the push/pop operation.
 */
void
fnstack_push(char const *file)
{
	struct filename_stack *files;
	char const **tmp;

	files = pthread_getspecific(filenames_key);
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

	files->filenames[files->len++] = file;
}

/**
 * See fnstack_push().
 *
 * This function cannot claim a reference for @uri, so @uri will have to outlive
 * the push/pop.
 */
void
fnstack_push_uri(struct rpki_uri *uri)
{
	fnstack_push(uri_val_get_printable(uri));
}

/* Returns the file name on the top of the file name stack. */
char const *
fnstack_peek(void)
{
	struct filename_stack *files;

	files = pthread_getspecific(filenames_key);
	if (files == NULL || files->filenames == NULL || files->len == 0)
		return NULL;

	return files->filenames[files->len - 1];
}

/* Reverts the last fnstack_push(). */
void
fnstack_pop(void)
{
	struct filename_stack *files;

	files = pthread_getspecific(filenames_key);
	if (files == NULL || files->filenames == NULL || files->len == 0)
		return;

	files->len--;
}

static char const *
addr2str(int af, void const *addr, char *(*buffer_cb)(struct validation *))
{
	return inet_ntop(af, addr, buffer_cb(state_retrieve()),
	    INET6_ADDRSTRLEN);
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
v4addr2str(struct in_addr const *addr)
{
	return addr2str(AF_INET, addr, validation_get_ip_buffer1);
}

/**
 * Same as v4addr2str(), except a different buffer is used.
 */
char const *
v4addr2str2(struct in_addr const *addr)
{
	return addr2str(AF_INET, addr, validation_get_ip_buffer2);
}

/**
 * See v4addr2str().
 */
char const *
v6addr2str(struct in6_addr const *addr)
{
	return addr2str(AF_INET6, addr, validation_get_ip_buffer1);
}

/**
 * See v4addr2str2().
 */
char const *
v6addr2str2(struct in6_addr const *addr)
{
	return addr2str(AF_INET6, addr, validation_get_ip_buffer2);
}
