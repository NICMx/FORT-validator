#include "thread_var.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "alloc.h"
#include "config.h"

static pthread_key_t state_key;
static pthread_key_t filenames_key;
static pthread_key_t repository_key;

struct filename_stack {
	/* This can be NULL. Abort all operations if this is the case. */
	char const **filenames;
	unsigned int len;
	unsigned int size;
};

struct working_repo {
	char const *uri;
	unsigned int level;
};

static void
fnstack_discard(void *arg)
{
	struct filename_stack *files = arg;
	free(files->filenames);
	free(files);
}

static void
working_repo_discard(void *arg)
{
	struct working_repo *repo = arg;
	free(repo);
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

	error = pthread_key_create(&repository_key, working_repo_discard);
	if (error) {
		pr_op_err(
		    "Fatal: Errcode %d while initializing the 'working repository' thread variable.",
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
 * Returns the current thread's validation state. Never returns NULL by
 * contract.
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

	files = pmalloc(sizeof(struct filename_stack));

	files->filenames = pmalloc(32 * sizeof(char *));
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
 *
 * Sample usage:
 *
 * 	void
 * 	test_fnstack(void)
 * 	{
 * 		fnstack_push("text.txt");
 * 		pr_val_info("Message 1");
 * 		fnstack_push("image.png");
 * 		pr_val_info("Message 2");
 * 		fnstack_pop();
 * 		pr_val_info("Message 3");
 * 		fnstack_pop();
 * 	}
 *
 * Prints
 *
 * 	text.txt: Message 1
 * 	image.png: Message 2
 * 	text.txt: Message 3
 */
void
fnstack_push(char const *file)
{
	struct filename_stack *files;

	files = pthread_getspecific(filenames_key);
	if (files == NULL || files->filenames == NULL)
		return;

	if (files->len >= files->size) {
		files->filenames = prealloc(files->filenames,
		    2 * files->size * sizeof(char *));
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

/** Initializes the current thread's working repo. Call once per thread. */
void
working_repo_init(void)
{
	struct working_repo *repo;
	int error;

	repo = pmalloc(sizeof(struct working_repo));

	repo->uri = NULL;
	repo->level = 0;

	error = pthread_setspecific(repository_key, repo);
	if (error)
		pr_op_err("pthread_setspecific() returned %d.", error);
}

void
working_repo_cleanup(void)
{
	struct working_repo *repo;
	int error;

	repo = pthread_getspecific(repository_key);
	if (repo == NULL)
		return;

	working_repo_discard(repo);

	error = pthread_setspecific(repository_key, NULL);
	if (error)
		pr_op_err("pthread_setspecific() returned %d.", error);
}

/*
 * Call whenever a certificate has more than one repository where its childs
 * live (rsync or RRDP).
 */
void
working_repo_push(char const *location)
{
	struct working_repo *repo;

	repo = pthread_getspecific(repository_key);
	if (repo == NULL)
		return;

	repo->uri = location;
}

/*
 * Set the current repository level, must be called before trying to fetch the
 * repository.
 *
 * The level "calculation" must be done by the caller.
 */
void
working_repo_push_level(unsigned int level)
{
	struct working_repo *repo;

	repo = pthread_getspecific(repository_key);
	if (repo == NULL)
		return;

	repo->level = level;
}

char const *
working_repo_peek(void)
{
	struct working_repo *repo;

	repo = pthread_getspecific(repository_key);

	return repo == NULL ? NULL : repo->uri;
}

unsigned int
working_repo_peek_level(void)
{
	struct working_repo *repo;

	repo = pthread_getspecific(repository_key);

	return repo->level;
}

/*
 * Call once the certificate's repositories were downloaded (either successful
 * or erroneously).
 */
void
working_repo_pop(void)
{
	struct working_repo *repo;

	repo = pthread_getspecific(repository_key);
	if (repo == NULL)
		return;

	repo->uri = NULL;
	repo->level = 0;
}

static char const *
addr2str(int af, void const *addr, char *(*buffer_cb)(struct validation *))
{
	struct validation *state = state_retrieve();
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
