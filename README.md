# FORT

An RPKI Validator and RTR Server.

**This software is in beta**

## Installation

Dependencies:

1. libcrypto ([LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/))
1. [jansson](https://github.com/akheron/jansson)
3. [libcmscodec](https://github.com/ydahhrk/libcmscodec)
4. [rsync](http://rsync.samba.org/)

After all the dependencies are installed, run:

```
./autogen.sh
./configure
make
make install
```

More documentation at [https://nicmx.github.io/FORT-validator/](https://nicmx.github.io/FORT-validator/).

## Usage

```
fort \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache> \
	--server.address <your intended RTR server address> \
	--server.port <your intended RTR server port>
```

An RTR server will serve the ROAs resulting from a validation rooted at the trust anchors defined by the TALs contained at directory `--tal`.
