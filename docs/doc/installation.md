---
title: Compilation and Installation
---

[Documentation](index.html) > {{ page.title }}

# {{ page.title }}

> TODO update with proper .tar.gz releases, once they are created

## Index

1. [Dependencies](#dependencies)
2. [Debian-based distributions](#debian-based-distributions)
3. [OpenBSD](#openbsd)

## Dependencies

> Note: I'm only including this section in case you intend to install Fort in an unlisted OS (and therefore need a little research). For Debians and OpenBSD, just follow the steps in the sections below.

The dependencies are

1. [jansson](http://www.digip.org/jansson/)
2. [libcmscodec](https://github.com/NICMx/libcmscodec)
3. libcrypto (Either [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/))
4. [rsync](http://rsync.samba.org/)

There's also [autoconf](https://www.gnu.org/software/autoconf/) and unzip (or [git](https://git-scm.com/)), but those are only needed for installation paperwork.

## Debian-based distributions

I haven't actually tried this in all the Debian-based distributions. Tested in Ubuntu 18.

{% highlight bash %}
########### normal dependencies ###########
# autoconf 2.69 or higher, please.
sudo apt install autoconf libjansson-dev libssl-dev rsync

############### libcmscodec ###############
mkdir libcmscodec
cd libcmscodec/
wget https://github.com/NICMx/libcmscodec/releases/download/beta1/libcmscodec-beta1.tar.gz
tar xvzf libcmscodec-beta1.tar.gz
cd libcmscodec-beta1/
./configure
make
sudo make install
sudo ldconfig
cd ../../

################## fort ###################
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

## OpenBSD

> TODO: The autotools are weird in this OS.
> 
> They require some global variables the installer doesn't setup on its own for some reason, and then spew error messages encouraging long deprecated macros. WTF?
> 
> For now, I'm working around this by running the `autogen.sh`s in Debian. It probably needn't be fixed, since the releases are going to ship with the `autogen.sh`s already executed anyway.

> TODO: test this again

{% highlight bash %}
########### normal dependencies ###########
su
# OpenBSD ships with LibreSSL
# autoconf 2.69 or higher, please.
pkg_add autoconf automake jansson libexecinfo rsync unzip
exit

# Adjust depending on the choices you made above.
export AUTOCONF_VERSION=2.69
export AUTOMAKE_VERSION=1.9

############### libcmscodec ###############
mkdir libcmscodec
cd libcmscodec/
ftp https://github.com/NICMx/libcmscodec/releases/download/beta1/libcmscodec-{{ site.libcmscodec-latest-version }}.tar.gz
tar xvzf libcmscodec-{{ site.libcmscodec-latest-version }}.tar.gz
cd libcmscodec-{{ site.libcmscodec-latest-version }}/
./configure
make
su
make install
exit
cd ../../

################## fort ###################
mkdir fort
cd fort/
ftp https://github.com/NICMx/FORT-validator/archive/master.zip
# tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
unzip master.zip
cd FORT*
ksh ./autogen.sh
# clang is needed because of gnu11.
env CC=clang CFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib ./configure
make
su
make install
exit
cd ../../
{% endhighlight %}
