---
title: Compilation and Installation
description: Guide to compile and install FORT Validator.
---

# {{ page.title }}

## Index

1. [Dependencies](#dependencies)
2. [Option 1: Installing the package](#option-1-installing-the-package)
	1. [Debian package](#debian-package)
	2. [FreeBSD package](#freebsd-package)
	3. [RHEL package](#rhel-package)
3. [Option 2: Compiling and installing the release tarball](#option-2-compiling-and-installing-the-release-tarball)
	1. [Debian](#debian)
	2. [OpenBSD](#openbsd)
	3. [RHEL](#rhel)
	4. [FreeBSD](#freebsd)
4. [Option 3: Compiling and installing the git repository](#option-3-compiling-and-installing-the-git-repository)
5. [Option 4: Docker container](#option-4-docker-container)
6. [Fetching the TALs](#fetching-the-tals)

## Dependencies

1. [jansson](http://www.digip.org/jansson/)
2. libcrypto (Either [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/) >= 1.1)
3. [rsync](http://rsync.samba.org/)
4. [libcurl](https://curl.haxx.se/libcurl/)
5. [libxml2](http://www.xmlsoft.org/)
6. [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/)

Fort currently supports *64-bit* Operating Systems. A 32-bit OS may face the [Year 2038 problem](https://en.wikipedia.org/wiki/Year_2038_problem) when handling certificate dates, and there's no workaround for this at the moment.

## Option 1: Installing the package

### Debian package

Last tested in Debian 12:

```bash
wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort_{{ site.fort-latest-version }}-1_amd64.deb
sudo apt install ./fort_{{ site.fort-latest-version }}-1_amd64.deb
```

The Debian package includes a systemd service that kicks off automatically after installation:

```bash
$ service fort status
● fort.service - FORT RPKI validator
     Loaded: loaded (/lib/systemd/system/fort.service; enabled; preset: enabled)
     Active: active (running) since Wed 2025-09-17 10:12:26 CDT; 1min 39s ago
       Docs: man:fort(8)
             https://nicmx.github.io/FORT-validator/
   Main PID: 690 (fort)
      Tasks: 29 (limit: 1093)
     Memory: 608.6M
        CPU: 22.960s
     CGroup: /system.slice/fort.service
             ├─690 /usr/bin/fort --configuration-file /etc/fort/config.json
             ├─741 rsync -rtz --delete --omit-dir-times --contimeout=20 --max-size=20MB --timeout=15 "--include=*/" "--include=*.cer" "--include=>
             └─743 rsync -rtz --delete --omit-dir-times --contimeout=20 --max-size=20MB --timeout=15 "--include=*/" "--include=*.cer" "--include=>

Sep 17 10:12:26 debian12 systemd[1]: Started fort.service - FORT RPKI validator.
```

You can [configure](usage.html#--configuration-file) it at `/etc/fort/config.json`.

There's also a version [available in the official Debian repositories](https://tracker.debian.org/pkg/fort-validator), though it's not maintained by the Fort team. Fetch it like a normal package:

```bash
sudo apt install fort-validator
```

### FreeBSD package

FORT Validator is available in the FreeBSD ports tree since October 2021.  The port maintainer closely follows the development of FORT.  Updates to the FreeBSD port appear shortly after FORT releases.  Binary packages can be installed in the usual way:

```bash
pkg install fort
```

If you prefer to build software from ports, this works too:

```bash
cd /usr/ports/net/fort
make install clean
```

A default configuration will be installed in `/usr/local/etc/fort/fort-config.json`.  The package is careful not to overwrite an existing configuration.

To use FORT on FreeBSD, you will need the Trust Anchor Locator (TAL) files.  You can download these by running `fort --init-tals` as follows:

```bash
fort --init-tals --tal /usr/local/etc/fort/tal
```

When you have downloaded the TAL files, you can start the RTR server and validator with the included service script:

```bash
sysrc fort_enable=YES # or edit /etc/rc.conf manually
service fort start
```

The default configuration will bind the RTR server to localhost on port 8323.

### RHEL package

Last tested in Rocky 8.9 and 9.3:

```bash
curl -O https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}-1.el8.x86_64.rpm
sudo dnf install fort-{{ site.fort-latest-version }}-1.el8.x86_64.rpm
```

The FORT validator service is not started by default:

```bash
sudo systemctl start fort
```

Configuration at [`/etc/fort/config.json`](usage.html#--configuration-file).

## Option 2: Compiling and installing the release tarball

### Debian

```bash
sudo apt install -y build-essential pkg-config rsync libjansson-dev \
	libssl-dev libcurl4-openssl-dev libxml2-dev libmicrohttpd-dev

wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
sudo make install
```

Last tested in Debian 12.12.

### OpenBSD

```bash
su
pkg_add curl jansson rsync libmicrohttpd libxml
exit

ftp https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
su
make install
exit
```

Last tested in OpenBSD 7.7.

### RHEL

```bash
# Needed by crb enable.
sudo dnf install -y epel-release
# Needed by libmicrohttpd-devel.
# In rockylinux9, it's also needed by jansson-devel.
sudo crb enable

sudo dnf install -y gcc make pkgconfig rsync jansson-devel \
	openssl-devel libcurl-devel libxml2-devel libmicrohttpd-devel

wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
sudo make install
```

Last tested in rockylinux 8.9 and 9.3.

### FreeBSD

```bash
sudo pkg install autotools curl jansson pkgconf rsync libxml2 libmicrohttpd
fetch https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/

export CFLAGS=-I/usr/local/include
./configure
make
sudo make install
```

Last tested in FreeBSD 14.3.

## Option 3: Compiling and installing the git repository

First, get the dependencies, and also `git` and the autotools. For Debian, this would be

```bash
# Git, autotools
sudo apt install -y autoconf automake build-essential git 
# Fort dependencies
sudo apt install -y pkg-config rsync libjansson-dev libssl-dev \
	libcurl4-openssl-dev libxml2-dev libmicrohttpd-dev
```

Then download, compile and install:

```bash
git clone https://github.com/NICMx/FORT-validator.git
cd FORT-validator/
./autogen.sh
./configure
make
sudo make install
```

## Option 4: Docker container

It's in [Docker Hub](https://hub.docker.com/r/nicmx/fort-validator). Pull with

```bash
docker pull nicmx/fort-validator:latest
```

A basic example to run the container using the default values, reading from a local TAL directory (i.e. `host/path/to/tals`), and binding to the local port `8323`:

```bash
docker run --name fort-validator -v host/path/to/tals:/etc/fort/tal:ro -p 8323:323 -d fort-validator
```

## Fetching the TALs

```bash
fort --init-tals --tal /etc/fort/tal
```

More details [here](usage.html#--init-tals).
