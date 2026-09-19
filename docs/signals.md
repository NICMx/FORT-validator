---
title: signals
---

# {{ page.title }}

This page documents the signals Fort overrides.

## Program Error signals

["Program Error" signals](https://sourceware.org/glibc/manual/latest/html_node/Program-Error-Signals.html) are raised by the operating system when it detects Fort has a programming error. They result in a core dump and a crash. In an ideal bugless world, they should never happen (unless you raise them manually).

For the sake of sanity, Fort needs to catch Program Error signals to perform an emergency cleanup before it crashes. The cleanup consists of removing temporary `--output*` files and (more importantly) unlocking the cache.

The rest of the cache is not cleant, which means certain cache nodes might be left in an inconsistent state, which simply means Fort will have to redownload them from scratch the next time it validates the relevant publication points.

Fort recognizes and cleans up after itself when receiving the following standard Program Error signals:

- `SIGFPE`
- `SIGILL`
- `SIGSEGV`
- `SIGBUS`
- `SIGABRT`
- `SIGIOT`
- `SIGTRAP`
- `SIGSYS`
- `SIGSTKFLT`

Fort does not recognize other (likely nonstandard) Program Error signals your operating system might raise. If you get one of these, and you need to restart Fort, it will need you to unlock the cache manually.

<!-- TODO Probably document how to do that: 1. Ensure no Fort instance is working in the cache, 2. rm /path/to/cache/.lock. -->

## Regular Termination signals

["Termination" signals](https://sourceware.org/glibc/manual/latest/html_node/Termination-Signals.html) are means to ask a process to end itself. The most likely recognizable one is `SIGINT`, which is what kills a running foreground command when you hit `Control+C`.

"**Regular** Termination" signals, in the context of Fort, is all Termination signals except [`SIGTERM`](#sigterm).

Similar to Program Error signals, Fort needs to catch Regular Termination signals to perform a callback cleanup before it ends. The cleanup consists of removing temporary `--output*` files and (more importantly) unlocking the cache.

The rest of the cache is not cleant, which means certain cache nodes might be left in an inconsistent state, which simply means Fort will have to redownload them from scratch the next time it validates the relevant publication points.

Fort recognizes and cleans up after itself when receiving the following standard Regular Termination signals:

- `SIGINT`
- `SIGQUIT`
- `SIGHUP`

Fort does not recognize other (likely nonstandard) Regular Termination signals you might raise. If you send one of these to Fort, and you need to restart it, it will need you to unlock the cache manually.

Per the Unix jurisprudence, Fort is also incapable of catching `SIGKILL` and `SIGSTOP`. These will also require a manual cache unlock.

## `SIGTERM`

Fort has a special meaning for `SIGTERM`: "Finish the current ongoing validation cycle (if there is one), perform a full cleanup (which means no memory leaks and a perfectly consistent cache), then end." It's the most graceful possible way to kill Fort.

Of course, it might come at the expense of a possible wait that should be, at the most, in the realm of minutes. If Fort hasn't died after a healthy validation timespan, you might have run into a bug, and might want to force kill it with a different signal.

<!-- TODO point to the Prometheus stat that tracks average validation timespan -->

As a user, you don't need to force yourself to raise `SIGTERM`. It exists mostly for the sake of memory leak testing during development.

## `SIGUSR1`

Fort has a special meaning for `SIGUSR1`: "Kick off a validation cycle, if one is not running already." It does not kill Fort.

## `SIGUSR2`

`SIGUSR2` is reserved.

As of version 2.0, Fort honors `SIGUSR2`'s default behavior, so it treats it like a [Regular Termination signal](#regular-termination-signals), prepending a quick emergency cleanup before insta-terminating.

However, this behavior should not be relied upon, as we might find in the future a more productive use for this signal.
