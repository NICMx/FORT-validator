---
title: Basic Usage
description: This is probably all you need, an RTR server will serve the ROAs resulting from a validation rooted at the trust anchors defined by the TALs contained at directory '--tal'.
---

# {{ page.title }}

This is probably all you need: fetch the RIR TALs and then start an RTR server that will serve the ROAs resulting from a validation rooted at the trust anchors defined by the TALs contained at directory `--tal`:

{% highlight bash %}
fort --init-tals --tal <path to store TAL files>

fort \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache> \
	--server.address <your intended RTR server address> \
	--server.port <your intended RTR server port>
{% endhighlight %}

> ![img/warn.svg](img/warn.svg) In case the RTR server will be bound to a privileged port (eg. to default [`--server.port`](usage.html#--serverport)=323) and you don't want to run FORT validator as root, see [Non root port binding](#non-root-port-binding).

This will run Fort validator as standalone (perform validation and exit) and print ROAs to CSV file:

{% highlight bash %}
fort \
	--mode standalone \
	--output.roa <path to output file in CSV format> \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache>
{% endhighlight %}

This will run Fort validator using a [SLURM file](https://tools.ietf.org/html/rfc8416):

{% highlight bash %}
fort \
	--slurm <path to a SLURM file> \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache> \
	--server.address <your intended RTR server address> \
	--server.port <your intended RTR server port>
{% endhighlight %}

These are some examples to run Fort with distinct configurations; see [Program Arguments](usage.html) for more details.

## Non root port binding

By default, RTR server binds to port 323, which is a privileged port (ports lower than 1024 are restricted); so the most simple solutions are:
- Set [`--server.port`](usage.html#--serverport) to an available port greater than 1024.
- Leave the default server port and run FORT validator as root.

In case you don't wish to use another port nor execute FORT validator as root, there are other alternatives, such as **capabilities**.

The capability needed is `CAP_NET_BIND_SERVICE`, which allows to bind a socket to "Internet domain privileged ports" (port numbers less than 1024).

For Linux you need:
- A recent kernel compiled with POSIX capabilities.
- The `setcap` and `getcap` utilities.

> **Warnings**:
> - With the "capabilities" method, any nonprivileged user can run FORT on priviliged ports. You can restrict the execution of the FORT binary using credentials (`chmod`, `chown`).
> - Everytime you compile the sources, you need to apply this patch for the new binary of FORT validator.

### Steps

As root, execute this command to add the capability to the installed FORT validator binary:

{% highlight bash %}
root# setcap cap_net_bind_service=+ep `which fort`
{% endhighlight %}

You can check if the capability was added by executing `getcap`, it should result in something like this:

{% highlight bash %}
root# getcap `which fort`
/usr/local/bin/fort = cap_net_bind_service+ep
{% endhighlight %}

Now FORT validator can be bound to the default port (323) without being executed as root.

In case you want to remove the capability to the installed FORT binary, execute the next command (as root):

{% highlight bash %}
root# setcap cap_net_bind_service=-ep `which fort`
{% endhighlight %}

### Alternative method (LINUX or BSD)

You can use another method (NAT or firewall) to redirect traffic from port 323 to any other port where FORTR service is bound as RTR server, but such methods are out of the scope of these documents.

## Tuning memory (Linux & glibc)

> ![img/warn.svg](img/warn.svg) This quirk applies to glibc, you can check if your OS has it by running (from a command line): `$ ldd --version`

FORT validator is currently a multithreaded program (it spawns a thread to validate each configured TAL), and there's a known behavior in GNU C Library (glibc) regarding multithreading and the memory usage growth. This is not precisely an issue nor something to be concerned about, unless the host machine has quite a limited memory (as of today, this isn't probably a common scenario). 

When a new thread is spawned it has its own "arena" available to handle the memory allocations; so, when multiple threads are created, is likely to have the same amount of arenas. Every `malloc`'d and `free`'d block at each thread, will be done in a memory space (a.k.a "arena") reserved for the thread.

Once a memory block is released using `free`, there's no warranty that such memory be returned to the OS, thus the program's memory usage isn't necessarily decreased (in this case, the "arena" size isn't decreased). See more about [glibc `free`](https://www.gnu.org/software/libc/manual/html_node/Freeing-after-Malloc.html).

Most of FORT Validator allocations are temporary since they're needed at the validation cycles, this causes a logarithmic growth on the program memory usage. Only a part of that memory is really allocated, the other part consist of free space that hasn't been returned to the OS yet.

glibc has the _[Tunables](https://www.gnu.org/software/libc/manual/html_node/Tunables.html)_ feature. One of the things that can be tuned is precisely the maximum number of "arenas" that the program will use. There are many other things that can be tuned, but they are out of scope of this document.

Basically, limiting the number of arenas helps to avoid the memory growth. This can be achieved by setting the environment variable `MALLOC_ARENA_MAX`, please read more at [Memory Allocation Tunables](https://www.gnu.org/software/libc/manual/html_node/Memory-Allocation-Tunables.html#index-glibc_002emalloc_002earena_005fmax).

The recommended value in order to avoid a high performance cost, is `MALLOC_ARENA_MAX=2`. In order to set this value in the current session, this can be executed from the command line:

{% highlight bash %}
export MALLOC_ARENA_MAX=2
# Now run fort
fort --tal=/etc/tals ...
{% endhighlight %}
