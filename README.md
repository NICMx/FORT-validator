# FORT

An RPKI Validator and RTR Server.

## Installation

Dependencies:

1. libcrypto ([LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/) >= 1.1)
2. [jansson](https://github.com/akheron/jansson)
3. [rsync](http://rsync.samba.org/)

The validator is currently supported in *64-bit* OS. A 32-bit OS may face the [Year 2038 problem](https://en.wikipedia.org/wiki/Year_2038_problem) when handling dates at certificates.

After all the dependencies are installed, run:

```
./autogen.sh
./configure
make
make install
```

More documentation at [https://nicmx.github.io/FORT-validator/](https://nicmx.github.io/FORT-validator/).

## Usage

Use the following command to run an RTR server that will serve the ROAs resulting from a validation rooted at the trust anchors defined by the TALs contained at directory `--tal`:

```
fort \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache> \
	--server.address <your intended RTR server address> \
	--server.port <your intended RTR server port>
```

Run Fort validator as standalone (perform validation and exit) and print ROAs to CSV file:

```
fort \
	--mode standalone \
	--output.roa <path to output file in CSV format> \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache>
```

Run Fort validator using a [SLURM file](https://tools.ietf.org/html/rfc8416):

```
fort \
	--slurm <path to a SLURM file> \
	--tal <path to your TAL files> \
	--local-repository <path where you want to keep your local cache> \
	--server.address <your intended RTR server address> \
	--server.port <your intended RTR server port>
```

Visit the [Usage](https://nicmx.github.io/FORT-validator/doc/usage.html) section at the docs to know all the possible Fort configurations, these are some usage examples.