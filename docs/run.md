---
title: Basic Usage
---

# {{ page.title }}

This is probably all you need, an RTR server will serve the ROAs resulting from a validation rooted at the trust anchors defined by the TALs contained at directory `--tal`:

{% highlight bash %}
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

```
# setcap cap_net_bind_service=+ep `which fort`
```

You can check if the capability was added by executing `getcap`, it should result in something like this:

```
# getcap `which fort`
/usr/local/bin/fort = cap_net_bind_service+ep
```

Now FORT validator can be bound to the default port (323) without being executed as root.

In case you want to remove the capability to the installed FORT binary, execute the next command (as root):

```
# setcap cap_net_bind_service=-ep `which fort`
```

### Alternative method (LINUX or BSD)

You can use another method (NAT or firewall) to redirect traffic from port 323 to any other port where FORT service is bound as RTR server, but such methods are out of the scope of these documents.
