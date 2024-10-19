#include "rsync.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stream.h>
#include <sys/wait.h>
#include <syslog.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "log.h"

#define STDERR_WRITE(fds) fds[0][1]
#define STDOUT_WRITE(fds) fds[1][1]
#define STDERR_READ(fds)  fds[0][0]
#define STDOUT_READ(fds)  fds[1][0]

static pid_t spawner;		/* The process that spawns rsync runs */

static int readfd;		/* Our end of the spawner-to-parent pipe */
static pthread_mutex_t readlock = PTHREAD_MUTEX_INITIALIZER;

static int writefd;		/* Our end of the parent-to-spawner pipe */
static pthread_mutex_t writelock = PTHREAD_MUTEX_INITIALIZER;

static int rsync(char const *, char const *);

static int
run_child(int readfd, int writefd)
{
	unsigned char zero = 0;
	struct read_stream stream;
	char *url, *path;
	int error;

	read_stream_init(&stream, readfd);

	do {
		error = read_string(&stream, &url);
		if (error || url == NULL)
			break;
		error = read_string(&stream, &path);
		if (error || path == NULL) {
			free(url);
			break;
		}

		error = rsync(url, path);

		free(url);
		free(path);

		error = full_write(writefd, &zero, 1);
	} while (!error);

	read_stream_close(&stream);
	close(writefd);
	free_rpki_config();
	log_teardown();
	return error;
}

void
rsync_setup(void)
{
	static const int RDFD = 0;
	static const int WRFD = 1;
	int parent2spawner[2];	/* Pipe: Parent writes, spawner reads */
	int spawner2parent[2];	/* Pipe: Spawner writes, parent reads */
	int flags;

	if (pipe(parent2spawner) < 0) {
		pr_op_err("Cannot create pipe: %s", strerror(errno));
		goto fail1;
	}
	if (pipe(spawner2parent) < 0) {
		pr_op_err("Cannot create pipe: %s", strerror(errno));
		goto fail2;
	}

	flags = fcntl(spawner2parent[RDFD], F_GETFL);
	if (flags < 0) {
		pr_op_err("Cannot retrieve pipe flags: %s", strerror(errno));
		goto fail3;
	}
	if (fcntl(spawner2parent[RDFD], F_SETFL, flags | O_NONBLOCK) < 0) {
		pr_op_err("Cannot enable O_NONBLOCK: %s", strerror(errno));
		goto fail3;
	}

	fflush(stdout);
	fflush(stderr);

	spawner = fork();
	if (spawner < 0) {
		pr_op_err("Cannot fork rsync spawner: %s", strerror(errno));
		goto fail3;
	}

	if (spawner == 0) { /* Client code */
		close(parent2spawner[WRFD]);
		close(spawner2parent[RDFD]);
		exit(run_child(parent2spawner[RDFD], spawner2parent[WRFD]));
	}

	/* Parent code */
	close(parent2spawner[RDFD]);
	close(spawner2parent[WRFD]);
	readfd = spawner2parent[RDFD];
	writefd = parent2spawner[WRFD];
	return;

fail3:	close(spawner2parent[RDFD]);
	close(spawner2parent[WRFD]);
fail2:	close(parent2spawner[RDFD]);
	close(parent2spawner[WRFD]);
fail1:	pr_op_warn("rsync will not be available.");
	readfd = writefd = 0;
}

int
rsync_download(char const *url, char const *path)
{
	mutex_lock(&writelock);

	if (writefd == 0)
		goto fail1;
	if (write_string(writefd, url) != 0)
		goto fail2;
	if (write_string(writefd, path) != 0)
		goto fail2;

	mutex_unlock(&writelock);
	return 0; // XXX go pick some other task

fail2:	close(readfd);
	close(writefd);
	readfd = writefd = 0;
fail1:	mutex_unlock(&writelock);
	return EIO;
}

/* Returns the number of rsyncs that have ended since the last query */
unsigned int
rsync_finished(void)
{
	unsigned char buf[8];
	ssize_t result;

	mutex_lock(&readlock);
	result = (readfd != 0) ? read(readfd, buf, sizeof(buf)) : 0;
	mutex_unlock(&readlock);

	return (result >= 0) ? result : 0;
}

static int
wait_child(char const *name, pid_t pid)
{
	int status;
	int error;

again:	status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		error = errno;
		pr_op_err("Could not wait for %s: %s", name, strerror(error));
		return error;
	}

	if (WIFEXITED(status)) {
		/* Happy path (but also sad path sometimes) */
		error = WEXITSTATUS(status);
		pr_val_debug("%s ended. Result: %d", name, error);
		return error ? EIO : 0;
	}

	if (WIFSIGNALED(status)) {
		pr_op_warn("%s interrupted by signal %d.",
		    name, WTERMSIG(status));
		return EINTR;
	}

	if (WIFCONTINUED(status)) {
		/*
		 * Testing warning:
		 * I can't trigger this branch. It always exits or signals;
		 * SIGSTOP then SIGCONT doesn't seem to wake up waitpid().
		 * It's concerning because every sample code I've found assumes
		 * waitpid() returning always means the subprocess ended, so
		 * they never retry. But that contradicts all documentation,
		 * yet seems to be accurate to reality.
		 */
		pr_op_debug("%s has resumed.", name);
		goto again;
	}

	/* Dead code */
	pr_op_err("Unknown waitpid() status; giving up %s.", name);
	return EINVAL;
}

void
rsync_teardown(void)
{
	if (readfd)
		close(readfd);
	if (writefd)
		close(writefd);
	readfd = writefd = 0;
	wait_child("rsync spawner", spawner);
}

/*
 * Duplicate parent FDs, to pipe rsync output:
 * - fds[0] = stderr
 * - fds[1] = stdout
 */
static void
duplicate_fds(int fds[2][2])
{
	/* Use the loop to catch interruptions */
	while ((dup2(STDERR_WRITE(fds), STDERR_FILENO) == -1)
		&& (errno == EINTR)) {}
	close(STDERR_WRITE(fds));
	close(STDERR_READ(fds));

	while ((dup2(STDOUT_WRITE(fds), STDOUT_FILENO) == -1)
	    && (errno == EINTR)) {}
	close(STDOUT_WRITE(fds));
	close(STDOUT_READ(fds));
}

static void
prepare_rsync_args(char **args, char const *url, char const *path)
{
	size_t i = 0;

	/*
	 * execvp() is not going to tweak these strings;
	 * stop angsting over the const-to-raw conversion.
	 */

	/* XXX review */
	args[i++] = (char *)config_get_rsync_program();
#ifdef UNIT_TESTING
	/* Note... --bwlimit does not seem to exist in openrsync */
	args[i++] = "--bwlimit=1K";
	args[i++] = "-vvv";
#else
	args[i++] = "-rtz";
	args[i++] = "--omit-dir-times";
	args[i++] = "--contimeout";
	args[i++] = "20";
	args[i++] = "--max-size";
	args[i++] = "20MB";
	args[i++] = "--timeout";
	args[i++] = "15";
	args[i++] = "--include=*/";
	args[i++] = "--include=*.cer";
	args[i++] = "--include=*.crl";
	args[i++] = "--include=*.gbr";
	args[i++] = "--include=*.mft";
	args[i++] = "--include=*.roa";
	args[i++] = "--exclude=*";
#endif
	args[i++] = (char *)url;
	args[i++] = (char *)path;
	args[i++] = NULL;
}

static int
execvp_rsync(char const *url, char const *path, int fds[2][2])
{
	char *args[20];

	prepare_rsync_args(args, url, path);
	duplicate_fds(fds);

	if (execvp(args[0], args) < 0)
		return errno;

	return EINVAL; /* Unreachable, but whatever */
}

static int
create_pipes(int fds[2][2])
{
	int error;

	if (pipe(fds[0]) == -1) {
		error = errno;
		pr_op_err_st("Piping rsync stderr: %s", strerror(error));
		return -error;
	}

	if (pipe(fds[1]) == -1) {
		error = errno;

		/* Close pipe previously created */
		close(fds[0][0]);
		close(fds[0][1]);

		pr_op_err_st("Piping rsync stdout: %s", strerror(error));
		return -error;
	}

	return 0;
}

static long
get_current_millis(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		pr_crit("clock_gettime() returned %d", errno);
	return 1000L * now.tv_sec + now.tv_nsec / 1000000L;
}

static void
log_buffer(char const *buffer, ssize_t read, bool is_error)
{
	char *cpy, *cur, *tmp;

	cpy = pmalloc(read + 1);

	strncpy(cpy, buffer, read);
	cpy[read] = '\0';

	/* Break lines to one line at log */
	cur = cpy;
	while ((tmp = strchr(cur, '\n')) != NULL) {
		*tmp = '\0';
		if(strlen(cur) == 0) {
			cur = tmp + 1;
			continue;
		}
		if (is_error)
			pr_val_err("[RSYNC exec] %s", cur);
		else
			pr_val_debug("[RSYNC exec] %s", cur);
		cur = tmp + 1;
	}
	free(cpy);
}

#define DROP_FD(f, fail)		\
	do {				\
		pfd[f].fd = -1;		\
		error |= fail;		\
	} while (0)
#define CLOSE_FD(f, fail)		\
	do {				\
		close(pfd[f].fd);	\
		DROP_FD(f, fail);	\
	} while (0)

/*
 * Consumes (and throws away) all the bytes in read streams @fderr and @fdout,
 * then closes them once they reach end of stream.
 *
 * Returns: ok -> 0, error -> 1, timeout -> 2.
 */
static int
exhaust_read_fds(int fderr, int fdout)
{
	struct pollfd pfd[2];
	int error, nready, f;
	long epoch, delta, timeout;

	memset(&pfd, 0, sizeof(pfd));
	pfd[0].fd = fderr;
	pfd[0].events = POLLIN;
	pfd[1].fd = fdout;
	pfd[1].events = POLLIN;

	error = 0;

	epoch = get_current_millis();
	delta = 0;
	timeout = 1000 * config_get_rsync_transfer_timeout();

	while (1) {
		nready = poll(pfd, 2, timeout - delta);
		if (nready == 0)
			goto timed_out;
		if (nready == -1) {
			error = errno;
			if (error == EINTR)
				continue;
			pr_val_err("rsync bad poll: %s", strerror(error));
			error = 1;
			goto fail;
		}

		for (f = 0; f < 2; f++) {
			if (pfd[f].revents & POLLNVAL) {
				pr_val_err("rsync bad fd: %i", pfd[f].fd);
				DROP_FD(f, 1);

			} else if (pfd[f].revents & POLLERR) {
				pr_val_err("Generic error during rsync poll.");
				CLOSE_FD(f, 1);

			} else if (pfd[f].revents & (POLLIN|POLLHUP)) {
				char buffer[4096];
				ssize_t count;

				count = read(pfd[f].fd, buffer, sizeof(buffer));
				if (count == -1) {
					error = errno;
					if (error == EINTR)
						continue;
					pr_val_err("rsync buffer read error: %s",
					    strerror(error));
					CLOSE_FD(f, 1);
					continue;
				}

				if (count == 0)
					CLOSE_FD(f, 0);
				log_buffer(buffer, count, pfd[f].fd == fderr);
			}
		}

		if (pfd[0].fd == -1 && pfd[1].fd == -1)
			return error; /* Happy path! */

		delta = get_current_millis() - epoch;
		if (delta < 0) {
			pr_val_err("This clock does not seem monotonic. "
			    "I'm going to have to give up this rsync.");
			error = 1;
			goto fail;
		}
		if (delta >= timeout)
			goto timed_out; /* Read took too long */
	}

timed_out:
	pr_val_err("rsync transfer timeout exhausted");
	error = 2;
fail:	for (f = 0; f < 2; f++)
		if (pfd[f].fd != -1)
			close(pfd[f].fd);
	return error;
}

/*
 * Completely consumes @fds' streams, and closes them.
 *
 * Originally, this was meant to redirect rsync's output to syslog:
 * ac56d70c954caf49382f5f28ff4a017e859e2e0a
 * (ie. we need to exhaust the streams because we dup2()'d them.)
 *
 * Later, @job repurposed this code to fix #74.
 */
static int
exhaust_pipes(int fds[2][2])
{
	close(STDERR_WRITE(fds));
	close(STDOUT_WRITE(fds));
	return exhaust_read_fds(STDERR_READ(fds), STDOUT_READ(fds));
}

/* rsync @url @path */
static int
rsync(char const *url, char const *path)
{
	/* Descriptors to pipe stderr (first element) and stdout (second) */
	int fork_fds[2][2];
	pid_t child_pid;
	int error;

	error = create_pipes(fork_fds);
	if (error)
		return error;

	fflush(stdout);
	fflush(stderr);

	child_pid = fork();
	if (child_pid < 0) {
		error = errno;
		pr_op_err_st("Couldn't spawn the rsync process: %s",
		    strerror(error));
		/* Close all ends from the created pipes */
		close(STDERR_READ(fork_fds));
		close(STDOUT_READ(fork_fds));
		close(STDERR_WRITE(fork_fds));
		close(STDOUT_WRITE(fork_fds));
		return error;
	}

	if (child_pid == 0)
		exit(execvp_rsync(url, path, fork_fds)); /* Child code */

	/* Parent code */

	error = exhaust_pipes(fork_fds);
	if (error)
		kill(child_pid, SIGTERM); /* Stop the child */

	return wait_child("rsync", child_pid);
}
