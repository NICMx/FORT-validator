---
title: Running Fort
---

[Documentation](index.html) > {{ page.title }}

# {{ page.title }}

This is probably all you need:

{% highlight bash %}
fort \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache> \
	--server.address <your intended RTR server address>
	--server.port <your intended RTR server port>
{% endhighlight %}

See [usage](usage.html) for more details.
