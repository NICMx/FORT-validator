---
title: Compilation and Installation
---

# {{ page.title }}

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

{% highlight bash %}
git clone https://github.com/ydahhrk/rpki-validator.git
cd rpki-validator
./autogen.sh
./configure
make
sudo make install
{% endhighlight %}

## OpenBSD

{% highlight bash %}
# pkg_add libexecinfo jansson rsync
$ 
$ ftp <libcmscodec tar url>
$ tar xvzf libcmscodec-<version>.tar.gz
$ cd libcmscodec
$ ./configure
$ make
# make install
$ cd ..
$ ftp <fort tar url>
$ tar xvzf fort-<version>.tar.gz
$ cd fort
$ # clang is needed because of gnu11.
$ env CC=clang CFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib ./configure
$ make
# make install
{% endhighlight %}
