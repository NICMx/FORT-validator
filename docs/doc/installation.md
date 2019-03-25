---
---

# Compilation and Installation

## Index

1. [Install dependencies](#install-dependencies)
	1. [libcrypto](#libcrypto)
	2. [tomlc99](#tomlc99)
	3. [rsync](#rsync)
2. [Install Fort](#install-fort)
	1. [libcmscodec](#libcmscodec)
	2. [Validator](#validator)
	3. [RTR Server](#rtr-server)

## Install dependencies

### libcrypto

Either [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/)

### tomlc99

[tomlc99](https://github.com/cktan/tomlc99)

### libcmscodec

{% highlight bash %}
git clone https://github.com/ydahhrk/libcmscodec.git
cd libcmscodec
./autogen.sh
./configure
make
sudo make install
{% endhighlight %}

### rsync

[rsync](http://rsync.samba.org/)

## Install Fort

There are no packages just yet.

### Validator

{% highlight bash %}
git clone https://github.com/ydahhrk/rpki-validator.git
cd rpki-validator
./autogen.sh
./configure
make
sudo make install
{% endhighlight %}

### RTR-Server

{% highlight bash %}
git clone https://github.com/ydahhrk/rtr-server.git
cd rtr-server
./autogen.sh
./configure
make
sudo make install
{% endhighlight %}
