---
title: Basic Usage
description: This is probably all you need, an RTR server will serve the ROAs resulting from a validation rooted at the trust anchors defined by the TALs contained at directory '--tal'.
---

# {{ page.title }}

First you'll need the Trust Anchor Locator (TAL) files. If you don't have them already, you can download them with [`--init-tals`](usage.html#--init-tals):

{% highlight bash %}
fort --init-tals --tal <directory in which TALs will be stored>
{% endhighlight %}

Then start the validator and RTR Server with

{% highlight bash %}
fort \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache> \
	--server.address <your intended RTR server address> \
	--server.port <your intended RTR server port>
{% endhighlight %}

> ![img/warn.svg](img/warn.svg) The RTR Server's default port (323) is privileged. Obviously, you don't want to use root, so either change the port (&ge; 1024), jail Fort, redirect the traffic by way of a NAT, or [grant Fort `CAP_NET_BIND_SERVICE`](#granting-the-cap_net_bind_service-capability-to-fort).

Alternatively, this will run Fort in [standalone mode](usage.html#--mode) (ie. single full RPKI validation then exit), while printing the ROAs to a CSV file:

{% highlight bash %}
fort \
	--mode standalone \
	--output.roa <path to output file in CSV format> \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache>
{% endhighlight %}

Add [SLURM files](https://tools.ietf.org/html/rfc8416) using [`--slurm`](usage.html#--slurm) in either server or standalone modes:

{% highlight bash %}
fort \
	--slurm <path to a SLURM file> \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache> \
	--server.address <your intended RTR server address> \
	--server.port <your intended RTR server port>
{% endhighlight %}

See [Program Arguments](usage.html) for a more exhaustive option list.

## Granting the `CAP_NET_BIND_SERVICE` capability to Fort

For Linux you need:
- A recent kernel compiled with POSIX capabilities.
- The `setcap` and `getcap` utilities.

> ![img/warn.svg](img/warn.svg)
> 
> - With the "capabilities" method, any nonprivileged user can run Fort on priviliged ports. You can restrict the execution of the Fort binary using credentials (`chmod`, `chown`).
> - Every time you compile the sources, you need to apply this patch for the new binary of Fort.

### Steps

As root, execute this command to add the capability to the installed Fort binary:

{% highlight bash %}
root# setcap cap_net_bind_service=+ep `which fort`
{% endhighlight %}

You can check if the capability was added by executing `getcap`:

{% highlight bash %}
root# getcap `which fort`
/usr/local/bin/fort = cap_net_bind_service+ep
{% endhighlight %}

Now Fort can be bound to a priviliged port without needing root.

If you want to remove the capability from the installed Fort binary, execute the following command (as root):

{% highlight bash %}
root# setcap cap_net_bind_service=-ep `which fort`
{% endhighlight %}

## Tuning memory (Linux & glibc)

> ![img/warn.svg](img/warn.svg) This quirk applies to glibc, you can check if your OS has it by running (from a command line): `$ ldd --version`

Fort is currently a multithreaded program (it spawns a thread to validate each configured TAL), and there's a known behavior in GNU C Library (glibc) regarding multithreading and the memory usage growth. This is not precisely an issue nor something to be concerned about, unless the host machine has quite a limited memory (as of today, this isn't probably a common scenario). 

When a new thread is spawned it has its own "arena" available to handle the memory allocations; so, when multiple threads are created, is likely to have the same amount of arenas. Every `malloc`'d and `free`'d block at each thread, will be done in a memory space (a.k.a "arena") reserved for the thread.

Once a memory block is released using `free`, there's no warranty that such memory be returned to the OS, thus the program's memory usage isn't necessarily decreased (in this case, the "arena" size isn't decreased). See more about [glibc `free`](https://www.gnu.org/software/libc/manual/html_node/Freeing-after-Malloc.html).

Most of Fort's allocations are temporary since they're needed at the validation cycles, this causes a logarithmic growth on the program memory usage. Only a part of that memory is really allocated, the other part consist of free space that hasn't been returned to the OS yet.

glibc has the _[Tunables](https://www.gnu.org/software/libc/manual/html_node/Tunables.html)_ feature. One of the things that can be tuned is precisely the maximum number of "arenas" that the program will use. There are many other things that can be tuned, but they are out of scope of this document.

Basically, limiting the number of arenas helps to avoid the memory growth. This can be achieved by setting the environment variable `MALLOC_ARENA_MAX`, please read more at [Memory Allocation Tunables](https://www.gnu.org/software/libc/manual/html_node/Memory-Allocation-Tunables.html#index-glibc_002emalloc_002earena_005fmax).

The recommended value in order to avoid a high performance cost, is `MALLOC_ARENA_MAX=2`. In order to set this value in the current session, this can be executed from the command line:

{% highlight bash %}
export MALLOC_ARENA_MAX=2
# Now run Fort
fort --tal=/etc/tals ...
{% endhighlight %}
