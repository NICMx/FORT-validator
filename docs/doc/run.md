---
title: Running Fort
---

[Documentation](index.html) > {{ page.title }}

# {{ page.title }}

This is probably all you need, an RTR server will serve the ROAs resulting from a validation rooted at the trust anchors defined by the TALs contained at directory `--tal`:

{% highlight bash %}
fort \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache> \
	--server.address <your intended RTR server address> \
	--server.port <your intended RTR server port>
{% endhighlight %}

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

These are some examples to run Fort with distinct configurations; see [usage](usage.html) for more details.