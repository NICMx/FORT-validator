---
title: Compilation and Installation
---

[Documentation](index.html) > {{ page.title }}

# {{ page.title }}

> TODO update with proper .tar.gz releases, once they are created

## Index

1. [Dependencies](#dependencies)
2. [Option 1: Installing the Debian package](#option-1-installing-the-debian-package)
3. [Option 2: Compiling and installing the release tarball](#option-2-compiling-and-installing-the-release-tarball)
	1. [Debian version](#debian-version)
	2. [OpenBSD version](#openbsd-version)
4. [Option 3: Compiling and installing the git repository](#option-3-compiling-and-installing-the-git-repository)

## Dependencies

> Note: I'm only including this section in case you intend to install Fort in an unlisted OS (and therefore need a little research). For Debians and OpenBSD, just follow the steps in the sections below.

The dependencies are

1. [jansson](http://www.digip.org/jansson/)
2. libcrypto (Either [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/))
3. [rsync](http://rsync.samba.org/)

## Option 1: Installing the Debian package

> TODO Upload to Debian, add more archs

{% highlight bash %}
wget https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort_{{ site.fort-latest-version }}-1_amd64.deb
sudo apt install ./fort_{{ site.fort-latest-version }}-1_amd64.deb
{% endhighlight %}

Aside from the `fort` binary documented elsewhere in this documentation, the Debian package also ships with a systemd service, which is just the binary ran as a daemon. You can [configure](usage.html#--configuration-file) it at `/etc/fort/config.json`.

{% highlight bash %}
sudo service fort start
service fort status
tail /var/log/syslog
sudo service fort stop
{% endhighlight %}

etc.

## Option 2: Compiling and installing the release tarball

### Debian version

{% highlight bash %}
sudo apt install autoconf automake build-essential libjansson-dev libssl-dev pkg-config rsync

wget https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
sudo make install
{% endhighlight %}

### OpenBSD version

{% highlight bash %}
su
pkg_add jansson libexecinfo rsync # OpenBSD already ships with LibreSSL
exit

ftp https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
# clang is needed because of gnu11.
env CC=clang CFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib ./configure
make
su
make install
exit
{% endhighlight %}

## Option 3: Compiling and installing the git repository

{% highlight bash %}
sudo apt install autoconf automake build-essential git libjansson-dev libssl-dev pkg-config rsync

git clone https://github.com/NICMx/FORT-validator.git
cd FORT-validator/
./autogen.sh
./configure
make
sudo make install
{% endhighlight %}
