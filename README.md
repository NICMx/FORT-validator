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

## RTR Configuration

> TODO Update this

The RTR server reads the configuration from a JSON file, learn about it at FORT's site [RTR Server arguments](https://nicmx.github.io/FORT-validator/doc/rtr-server.html).

Here's an example of a valid configuration file (assuming that the CSV file returned by FORT's validator is located at `/tmp/fort/roas.csv`):

```javascript
{
  "listen": {
    "address": "127.0.0.1",
    "port": "8323",
    "queue": 10
  },
  "vrps": {
    "location": "/tmp/fort/roas.csv",
    "checkInterval": 60
  }
}
```

## Execution

> TODO Update this

The executable needs only one argument: the location of the configuration file. So, assuming that the configuration file is located at `/home/fort/rtr.conf`, use the flag `-f` to indicate such location and run the server:

```
$ rtr_server -f /home/fort/rtr.conf
```

That's it! The server will be listening on the configured port for any RTR client that wishes to establish a connection and exchange for validated ROA payloads.
