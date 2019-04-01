# FORT RTR server

An RTR server compliant to [RFC 6810](https://tools.ietf.org/html/rfc6810) (at least for now).

More documentation about FORT at FORT's site [https://nicmx.github.io/FORT-validator/](https://nicmx.github.io/FORT-validator/).

**Still under development!**

## Installation

Dependencies:

1. [jansson](https://github.com/akheron/jansson)

After all the dependencies are installed, run:
```
./autogen.sh
./configure
make
make install
```

## Configuration

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

The executable needs only one argument: the location of the configuration file. So, assuming that the configuration file is located at `/home/fort/rtr.conf`, use the flag `-f` to indicate such location and run the server:

```
$ rtr_server -f /home/fort/rtr.conf
```

That's it! The server will be listening on the configured port for any RTR client that wishes to establish a connection and exchange for validated ROA payloads.