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
4. [Option 3: Compiling the git repositories](#option-3-compiling-the-git-repositories)

## Dependencies

> Note: I'm only including this section in case you intend to install Fort in an unlisted OS (and therefore need a little research). For Debians and OpenBSD, just follow the steps in the sections below.

The dependencies are

1. [jansson](http://www.digip.org/jansson/)
2. libcrypto (Either [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/))
3. [rsync](http://rsync.samba.org/)

The build dependencies are

- [autoconf](https://www.gnu.org/software/autoconf/)
- [automake](https://www.gnu.org/software/automake/)
- unzip (or [git](https://git-scm.com/))

(Some builds do not need all these dependencies.)

## Option 1: Installing the Debian package

> TODO Upload to Debian, add more archs and/or host these links on Github releases properly.

{% highlight bash %}
wget https://www.dropbox.com/s/7c0rs49ewcu6m93/fort_0.0.1-1_amd64.deb
sudo apt install ./fort_0.0.1-1_amd64.deb
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
sudo apt install autoconf automake build-essential libjansson-dev libssl-dev pkg-config rsync unzip

mkdir fort
cd fort/
wget https://github.com/NICMx/FORT-validator/archive/master.zip
# tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
unzip master.zip
cd FORT-validator-master/
./autogen.sh
./configure
make
sudo make install
cd ../../
{% endhighlight %}

### OpenBSD version

> TODO: The autotools are weird in this OS.
> 
> They require some global variables the installer doesn't setup on its own for some reason, and then spew error messages encouraging long deprecated macros. WTF?
> 
> For now, I'm working around this by running the `autogen.sh`s in Debian. It probably needn't be fixed, since the releases are going to ship with the `autogen.sh`s already executed anyway.

{% highlight bash %}
su
# OpenBSD already ships with LibreSSL
pkg_add jansson libexecinfo rsync unzip
exit

mkdir fort
cd fort/
ftp https://github.com/NICMx/FORT-validator/archive/master.zip
# tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
unzip master.zip
cd FORT-validator-master
./autogen.sh # Run this elsewhere
# clang is needed because of gnu11.
env CC=clang CFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib ./configure
make
su
make install
exit
cd ../../
{% endhighlight %}

## Option 3: Compiling the git repositories

{% highlight bash %}
sudo apt install autoconf automake build-essential git libjansson-dev libssl-dev pkg-config rsync

git clone https://github.com/NICMx/FORT-validator.git
cd FORT-validator/
./autogen.sh
./configure
make
sudo make install
cd ../
{% endhighlight %}

