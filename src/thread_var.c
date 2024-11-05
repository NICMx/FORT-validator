#include "thread_var.h"

#include <pthread.h>

#include "alloc.h"
#include "log.h"

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

/*
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

/* See fnstack_push(). @map needs to outlive the push/pop. */
void
fnstack_push_map(struct cache_mapping const *map)
{
	fnstack_push(map_val_get_printable(map));
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
