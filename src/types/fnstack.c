#include "fnstack.h"

#include <pthread.h>

#include "log.h"

#define FNSTACK_SIZE 8

static pthread_key_t filenames_key;

struct filename_stack {
	char const *filenames[FNSTACK_SIZE];
	int len;
};

/* Initializes this entire module. Call once per runtime lifetime. */
void
fnstack_setup(void)
{
	int error;

	/*
	 * Hm. It's a little odd.
	 * fnstack_discard() is not being called on program termination.
	 * Not sure if this is an implementation quirk.
	 * We'll just have to delete it manually.
	 */
	error = pthread_key_create(&filenames_key, free);
	if (error)
		pr_err(
		    "Cannot initialize file name stack thread variable: %s. "
		    "File name logging will be disabled.",
		    strerror(error)
		);
}

/* Initializes the current thread's fnstack. Call once per validation thread. */
void
fnstack_init(void)
{
	struct filename_stack *files;
	int error;

	files = pmalloc(sizeof(struct filename_stack));
	files->len = 0;

	error = pthread_setspecific(filenames_key, files);
	if (error) {
		pr_err("pthread_setspecific() failed: %s. "
		    "File name logging will be disabled for this thread.",
		    strerror(error));
		free(files);
	}
}

/*
 * Call this function every time you're about to start processing a new file.
 * Any pr_err()s and friends will now include the new file name.
 * Use fnstack_pop() to revert back to the previously stacked file name.
 * @file is not cloned; it's expected to outlive the push/pop operation.
 *
 * Sample usage:
 *
 * 	void
 * 	test_fnstack(void)
 * 	{
 * 		fnstack_push("text.txt");
 * 		pr_inf("Message 1");
 * 		fnstack_push("image.png");
 * 		pr_inf("Message 2");
 * 		fnstack_pop();
 * 		pr_inf("Message 3");
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
	if (!files)
		return;

	files->len++;
	if (files->len <= 0)
		return;
	if (FNSTACK_SIZE < files->len) {
		pr_crit("File name stack is full!");
		return;
	}

	files->filenames[files->len - 1] = file;
}

/* See fnstack_push(). @map needs to outlive the push/pop. */
void
fnstack_push_map(struct cache_mapping const *map)
{
	fnstack_push(uri_str(&map->url));
}

/* Returns the file name on the top of the file name stack. */
char const *
fnstack_peek(void)
{
	struct filename_stack *files;

	files = pthread_getspecific(filenames_key);
	if (!files || files->len <= 0 || FNSTACK_SIZE < files->len)
		return NULL;

	return files->filenames[files->len - 1];
}

/* Reverts the last fnstack_push(). */
void
fnstack_pop(void)
{
	struct filename_stack *files;

	files = pthread_getspecific(filenames_key);
	if (!files)
		return;

	files->len--;
	if (files->len == -1) {
		pr_crit("File name stack underflow!");
		return;
	}
}
