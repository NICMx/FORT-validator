#include "rsync.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stream.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <syslog.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "log.h"
#include "types/array.h"

#include "asn1/asn1c/ber_decoder.h"
#include "asn1/asn1c/der_encoder.h"
#include "asn1/asn1c/RsyncRequest.h"

#define RSP /* rsync spawner prefix */ "[rsync spawner] "

static char const *rsync_args[20]; /* Last must be NULL */

static const int RDFD = 0;
static const int WRFD = 1;

#define STDERR_WRITE(fds) fds[0][1]
#define STDOUT_WRITE(fds) fds[1][1]
#define STDERR_READ(fds)  fds[0][0]
#define STDOUT_READ(fds)  fds[1][0]

static pid_t spawner;	/* The subprocess that spawns rsync runs */

static int readfd;	/* Parent's end of the spawner-to-parent pipe */
static pthread_mutex_t readlock = PTHREAD_MUTEX_INITIALIZER;

static int writefd;	/* Parent's end of the parent-to-spawner pipe */
static pthread_mutex_t writelock = PTHREAD_MUTEX_INITIALIZER;

/*
 * "Spawner to parent" socket.
 * Socket used by the spawner to communicate with the parent.
 */
struct s2p_socket {
	/* Spawner's end of the parent-to-spawner pipe */
	struct read_stream rd;
	/* Spawner's end of the spawner-to-parent pipe */
	int wr;
	/* Scratchpad buffer for stream read */
	struct RsyncRequest *rr;
};

struct rsync_task {
	int pid;
	char *url;
	char *path;
	int stdoutfd;	/* Child rsync's standard output */
	int stderrfd;	/* Child rsync's standard error */
	struct timespec expiration;

	LIST_ENTRY(rsync_task) lh;
};

LIST_HEAD(rsync_task_list, rsync_task);

struct rsync_tasks {
	struct rsync_task_list active;
	int a; /* total active */

	struct rsync_task_list queued;
};

#ifndef LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(var, ls, lh, tmp)				\
    for (								\
        var = LIST_FIRST(ls), tmp = (var ? LIST_NEXT(var, lh) : NULL);	\
        var != NULL;							\
        var = tmp, tmp = (var ? LIST_NEXT(var, lh) : NULL)		\
    )
#endif

static void
void_task(struct rsync_task *task, struct s2p_socket *s2p)
{
	static const unsigned char one = 1;

	free(task->url);
	free(task->path);
	free(task);

	if (s2p->wr != -1 && write(s2p->wr, &one, 1) < 0) {
		pr_op_err(RSP "Cannot message parent process: %s", strerror(errno));

		close(s2p->wr);
		s2p->wr = -1;
		/* Can't signal finished rsyncs anymore; reject future ones. */
		rstream_close(&s2p->rd, true);
	}
}

static void
finish_task(struct rsync_tasks *tasks, struct rsync_task *task,
    struct s2p_socket *s2p)
{
	LIST_REMOVE(task, lh);
	tasks->a--;
	void_task(task, s2p);
}

static void
init_pfd(struct pollfd *pfd, int fd)
{
	pfd->fd = fd;
	pfd->events = POLLIN;
	pfd->revents = 0;
}

static struct pollfd *
create_pfds(int request_fd, struct rsync_task_list *tasks, size_t tn)
{
	struct pollfd *pfds;
	struct rsync_task *task;
	size_t p;

	pfds = pmalloc((2 * tn + 1) * sizeof(struct pollfd));
	p = 0;

	init_pfd(&pfds[p++], request_fd);
	LIST_FOREACH(task, tasks, lh) {
		init_pfd(&pfds[p++], task->stdoutfd);
		init_pfd(&pfds[p++], task->stderrfd);
	}

	return pfds;
}

static int
create_pipes(int fds[2][2])
{
	int error;

	if (pipe(fds[0]) < 0) {
		error = errno;
		pr_op_err_st(RSP "Piping rsync stderr: %s", strerror(error));
		return error;
	}

	if (pipe(fds[1]) < 0) {
		error = errno;
		pr_op_err_st(RSP "Piping rsync stdout: %s", strerror(error));
		close(fds[0][0]);
		close(fds[0][1]);
		return error;
	}

	return 0;
}

static void
prepare_rsync_args(char **args, char const *url, char const *path)
{
	size_t i;

	/*
	 * execvp() is not going to tweak these strings;
	 * stop angsting over the const-to-raw conversion.
	 */

	for (i = 0; rsync_args[i] != NULL; i++)
		args[i] = (char *)rsync_args[i];
	args[i++] = (char *)url;
	args[i++] = (char *)path;
	args[i++] = NULL;
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
fork_rsync(struct rsync_task *task)
{
	int fork_fds[2][2];
	int error;

	error = create_pipes(fork_fds);
	if (error)
		return error;

	fflush(stdout);
	fflush(stderr);

	task->pid = fork();
	if (task->pid < 0) {
		error = errno;
		pr_op_err_st(RSP "Couldn't spawn the rsync process: %s",
		    strerror(error));
		close(STDERR_READ(fork_fds));
		close(STDOUT_READ(fork_fds));
		close(STDERR_WRITE(fork_fds));
		close(STDOUT_WRITE(fork_fds));
		return error;
	}

	if (task->pid == 0) /* Child code */
		exit(execvp_rsync(task->url, task->path, fork_fds));

	/* Parent code */

	close(STDERR_WRITE(fork_fds));
	close(STDOUT_WRITE(fork_fds));
	task->stderrfd = STDERR_READ(fork_fds);
	task->stdoutfd = STDOUT_READ(fork_fds);
	return 0;
}

static void
activate_task(struct rsync_tasks *tasks, struct rsync_task *task,
    struct s2p_socket *s2p, struct timespec *now)
{
	ts_add(&task->expiration, now, 1000 * config_rsync_timeout());

	if (fork_rsync(task) != 0) {
		void_task(task, s2p);
		return;
	}

	LIST_INSERT_HEAD(&tasks->active, task, lh);
	tasks->a++;
}

static void
post_task(struct s2p_socket *s2p, struct rsync_tasks *tasks,
    struct timespec *now)
{
	struct rsync_task *task;

	task = pzalloc(sizeof(struct rsync_task));
	task->url = pstrndup((char *)s2p->rr->url.buf, s2p->rr->url.size);
	task->path = pstrndup((char *)s2p->rr->path.buf, s2p->rr->path.size);

	if (tasks->a >= config_rsync_max()) {
		LIST_INSERT_HEAD(&tasks->queued, task, lh);
		pr_op_debug(RSP "Queued new task.");
	} else {
		activate_task(tasks, task, s2p, now);
		pr_op_debug(RSP "Got new task: %d", task->pid);
	}
}

static void
read_tasks(struct s2p_socket *s2p, struct rsync_tasks *tasks,
    struct timespec *now)
{
	struct read_stream *in;
	ssize_t consumed;
	size_t offset;
	asn_dec_rval_t decres;
	int error;

	in = &s2p->rd;

	do {
		consumed = read(in->fd, in->buffer + in->len,
		    in->capacity - in->len);
		if (consumed < 0) {
			error = errno;
			if (error != EAGAIN && error != EWOULDBLOCK)
				rstream_close(in, true);
			return;
		}
		if (consumed == 0) { /* EOS */
			rstream_close(in, true);
			return;
		}

		in->len += consumed;

		for (offset = 0; offset < in->len;) {
			decres = ber_decode(&asn_DEF_RsyncRequest,
			    (void **)&s2p->rr,
			    in->buffer + offset, in->len - offset);
			offset += decres.consumed;
			switch (decres.code) {
			case RC_OK:
				post_task(s2p, tasks, now);
				ASN_STRUCT_RESET(asn_DEF_RsyncRequest, s2p->rr);
				break;
			case RC_WMORE:
				goto break_for;
			case RC_FAIL:
				rstream_close(in, true);
				return;
			}
		}

break_for:	if (offset > in->len)
			pr_crit("read_tasks off:%zu len:%zu", offset, in->len);
		in->len -= offset;
		memmove(in->buffer, in->buffer + offset, in->len);
	} while (true);
}

static void
handle_parent_fd(struct s2p_socket *s2p, struct pollfd *pfd,
    struct rsync_tasks *tasks, struct timespec *now)
{
	if (s2p->rd.fd == -1)
		return;

	if (pfd->revents & POLLNVAL) {
		pr_op_err(RSP "bad parent fd: %i", pfd->fd);
		rstream_close(&s2p->rd, false);

	} else if (pfd->revents & POLLERR) {
		pr_op_err(RSP "Generic error during parent fd poll.");
		rstream_close(&s2p->rd, true);

	} else if (pfd->revents & (POLLIN | POLLHUP)) {
		read_tasks(s2p, tasks, now);
	}
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
		if (strlen(cur) == 0) {
			cur = tmp + 1;
			continue;
		}
		if (is_error)
			pr_op_err("[RSYNC exec] %s", cur);
		else
			pr_op_debug("[RSYNC exec] %s", cur);
		cur = tmp + 1;
	}
	free(cpy);
}

/* 0 = still more to read; 1 = stream down */
static int
log_rsync_output(struct pollfd *pfd, size_t p)
{
	char buffer[1024];
	ssize_t count;
	int error;

	count = read(pfd->fd, buffer, sizeof(buffer));
	if (count == 0)
		goto down; /* EOF */
	if (count == -1) {
		error = errno;
		if (error == EINTR)
			return 0; /* Dunno; retry */
		pr_op_err(RSP "rsync buffer read error: %s", strerror(error));
		goto down; /* Error */
	}

	log_buffer(buffer, count, (p & 1) == 0);
	return 0; /* Keep going */

down:	close(pfd->fd);
	pfd->fd = -1;
	return 1;
}

/* Returns 1 if the stream ended */
static int
handle_rsync_fd(struct pollfd *pfd, size_t p)
{
	if (pfd->fd == -1) {
		pr_op_debug(RSP "File descriptor already closed.");
		return 1;
	}

	if (pfd->revents & POLLNVAL) {
		pr_op_err(RSP "rsync bad fd: %i", pfd->fd);
		return 1;
	}

	if (pfd->revents & POLLERR) {
		pr_op_err(RSP "Generic error during rsync poll.");
		close(pfd->fd);
		return 1;
	}

	if (pfd->revents & (POLLIN | POLLHUP))
		return log_rsync_output(pfd, p);

	return 0;
}

static int
wait_subprocess(char const *name, pid_t pid)
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
		pr_op_debug("%s ended. Result: %d", name, error);
		return error ? EIO : 0;
	}

	if (WIFSIGNALED(status)) {
		pr_op_warn("%s interrupted by signal %d (%s).",
		    name, WTERMSIG(status), strsignal(WTERMSIG(status)));
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

static void
kill_subprocess(struct rsync_task *task)
{
	if (task->stdoutfd != -1)
		close(task->stdoutfd);
	if (task->stderrfd != -1)
		close(task->stderrfd);
	kill(task->pid, SIGTERM);
}

static void
activate_queued(struct rsync_tasks *tasks, struct s2p_socket *s2p,
    struct timespec *now)
{
	struct rsync_task *task;

	task = LIST_FIRST(&tasks->queued);
	if (task == NULL)
		return;

	pr_op_debug(RSP "Activating queued task %s -> %s.",
	    task->url, task->path);
	LIST_REMOVE(task, lh);
	activate_task(tasks, task, s2p, now);
}

/* Returns true if the task died. */
static bool
maybe_expire(struct rsync_tasks *tasks, struct rsync_task *task,
    struct s2p_socket *s2p, struct timespec *now)
{
	struct timespec epoch;

	ts_add(&epoch, now, 100);
	if (ts_cmp(&epoch, &task->expiration) < 0)
		return false;

	pr_op_debug(RSP "Task %d ran out of time.", task->pid);
	kill_subprocess(task);
	wait_subprocess("rsync", task->pid);
	finish_task(tasks, task, s2p);
	activate_queued(tasks, s2p, now);

	return true;
}

static int
spawner_run(
    int request_fd,	/* Requests from parent to us (spawner) */
    int response_fd	/* Responses from us (spawner) to parent */
) {
	struct s2p_socket s2p;	/* Channel to parent */

	struct pollfd *pfds;	/* Channels to children */
	size_t p, pfds_count;
	struct timespec now, expiration;
	int timeout;

	int events;

	struct rsync_tasks tasks;
	struct rsync_task *task, *tmp;

	int error;

	rstream_init(&s2p.rd, request_fd, 1024);
	s2p.wr = response_fd;
	s2p.rr = NULL;

	LIST_INIT(&tasks.active);
	LIST_INIT(&tasks.queued);
	tasks.a = 0;
	error = 0;

	ts_now(&now);

	do {
		/*
		 * 0: request pipe
		 * odd: stdouts
		 * even > 0: stderrs
		 */
		pfds = create_pfds(s2p.rd.fd, &tasks.active, tasks.a);
		pfds_count = 2 * tasks.a + 1;
		expiration.tv_sec = now.tv_sec + 10;
		expiration.tv_nsec = now.tv_nsec;
		LIST_FOREACH(task, &tasks.active, lh)
			if ((ts_cmp(&now, &task->expiration) < 0) &&
			    (ts_cmp(&task->expiration, &expiration) < 0))
				expiration = task->expiration;

		timeout = ts_delta(&now, &expiration);
		pr_op_debug(RSP "Timeout decided: %dms", timeout);
		events = poll(pfds, pfds_count, timeout);
		if (events < 0) {
			error = errno;
			free(pfds);
			break;
		}

		ts_now(&now);

		if (events == 0) { /* Timeout */
			pr_op_debug(RSP "Woke up because of timeout.");
			LIST_FOREACH_SAFE(task, &tasks.active, lh, tmp)
				maybe_expire(&tasks, task, &s2p, &now);
			goto cont;
		}

		pr_op_debug(RSP "Woke up because of input.");
		p = 1;
		LIST_FOREACH_SAFE(task, &tasks.active, lh, tmp) {
			if (maybe_expire(&tasks, task, &s2p, &now))
				continue;

			if (handle_rsync_fd(&pfds[p], p)) {
				pr_op_debug(RSP "Task %d: Stdout closed.",
				    task->pid);
				task->stdoutfd = -1;
			}
			p++;
			if (handle_rsync_fd(&pfds[p], p)) {
				pr_op_debug(RSP "Task %d: Stderr closed.",
				    task->pid);
				task->stderrfd = -1;
			}
			p++;
			if (task->stdoutfd == -1 && task->stderrfd == -1) {
				pr_op_debug(RSP "Both stdout & stderr are closed; ending task %d.",
				    task->pid);
				wait_subprocess("rsync", task->pid);
				finish_task(&tasks, task, &s2p);
				activate_queued(&tasks, &s2p, &now);
			}
		}
		handle_parent_fd(&s2p, &pfds[0], &tasks, &now);

cont:		free(pfds);
	} while ((s2p.rd.fd != -1 || tasks.a > 0));
	pr_op_debug(RSP "The parent stream is closed and there are no rsync tasks running. Cleaning up...");

	LIST_FOREACH_SAFE(task, &tasks.active, lh, tmp) {
		kill_subprocess(task);
		wait_subprocess("rsync", task->pid);
		finish_task(&tasks, task, &s2p);
	}
	LIST_FOREACH_SAFE(task, &tasks.queued, lh, tmp) {
		LIST_REMOVE(task, lh);
		void_task(task, &s2p);
	}

	rstream_close(&s2p.rd, true);
	if (s2p.wr != -1)
		close(s2p.wr);

	free_rpki_config();
	log_teardown();
	return error;
}

static int
nonblock_pipe(int *fds)
{
	int error;
	int flags;

	if (pipe(fds) < 0) {
		error = errno;
		pr_op_err("Cannot create pipe: %s", strerror(error));
		return error;
	}

	flags = fcntl(fds[RDFD], F_GETFL);
	if (flags < 0) {
		error = errno;
		pr_op_err("Cannot retrieve pipe flags: %s", strerror(error));
		goto cancel;
	}
	if (fcntl(fds[RDFD], F_SETFL, flags | O_NONBLOCK) < 0) {
		error = errno;
		pr_op_err("Cannot enable O_NONBLOCK: %s", strerror(error));
		goto cancel;
	}

	return 0;

cancel:	close(fds[RDFD]);
	close(fds[WRFD]);
	return error;
}

void
rsync_setup(char const *program, ...)
{
	int parent2spawner[2];	/* Pipe: Parent writes, spawner reads */
	int spawner2parent[2];	/* Pipe: Spawner writes, parent reads */

	va_list args;
	array_index i;
	char const *arg;

	if (program != NULL) {
		rsync_args[0] = arg = program;
		va_start(args, program);
		for (i = 1; arg != NULL; i++) {
			arg = va_arg(args, char const *);
			rsync_args[i] = arg;
		}
		va_end(args);
	} else {
		/* XXX review */
		/* XXX Where is --delete? */
		i = 0;
		rsync_args[i++] = config_get_rsync_program();
		rsync_args[i++] = "-rtz";
		rsync_args[i++] = "--omit-dir-times";
		rsync_args[i++] = "--contimeout";
		rsync_args[i++] = "20";
		rsync_args[i++] = "--max-size";
		rsync_args[i++] = "20MB";
		rsync_args[i++] = "--timeout";
		rsync_args[i++] = "15";
		rsync_args[i++] = "--include=*/";
		rsync_args[i++] = "--include=*.cer";
		rsync_args[i++] = "--include=*.crl";
		rsync_args[i++] = "--include=*.gbr";
		rsync_args[i++] = "--include=*.mft";
		rsync_args[i++] = "--include=*.roa";
		rsync_args[i++] = "--exclude=*";
		rsync_args[i++] = NULL;
	}

	if (nonblock_pipe(parent2spawner) != 0)
		goto fail1;
	if (nonblock_pipe(spawner2parent) != 0)
		goto fail2;

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
		exit(spawner_run(parent2spawner[RDFD], spawner2parent[WRFD]));
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
	readfd = writefd = -1;
}

static int
send_to_spawner(const void *buffer, size_t size, void *arg)
{
	return stream_full_write(writefd, buffer, size);
}

/* Queues rsync; doesn't wait. Call rsync_finished() later.  */
int
rsync_queue(char const *url, char const *path)
{
	struct RsyncRequest req;
	asn_enc_rval_t result;
	int error;

	if (RsyncRequest_init(&req, url, path) < 0)
		return EINVAL;

	mutex_lock(&writelock);

	if (writefd == -1) {
		error = EIO;
		goto end;
	}

	result = der_encode(&asn_DEF_RsyncRequest, &req, send_to_spawner, NULL);
	if (result.encoded == -1) {
		close(writefd);
		writefd = -1;
		error = EIO;
		goto end;
	}

	error = 0;
end:	mutex_unlock(&writelock);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_RsyncRequest, &req);
	return error;
}

/* Returns the number of rsyncs that have ended since the last query */
unsigned int
rsync_finished(void)
{
	unsigned char buf[8];
	ssize_t result;

	mutex_lock(&readlock);
	result = (readfd != -1) ? read(readfd, buf, sizeof(buf)) : 0;
	mutex_unlock(&readlock);

	return (result >= 0) ? result : 0;
}

void
rsync_teardown(void)
{
	if (readfd != -1)
		close(readfd);
	if (writefd != -1)
		close(writefd);
	readfd = writefd = -1;
	wait_subprocess("rsync spawner", spawner);
}
