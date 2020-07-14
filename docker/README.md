# FORT Validator Docker image

Docker image for [NICMx/FORT-validator](https://github.com/NICMx/FORT-validator) (using the [latest release](https://github.com/NICMx/FORT-validator/releases/latest)), based on Alpine Linux.

Special thanks to [ximon18](https://github.com/ximon18) for its [contribution](https://github.com/NICMx/FORT-validator/issues/17).

**This image doesn't include TAL (Trust Anchor Locator) files.** They must be obtained somewhere else (here's [an example](https://github.com/NICMx/FORT-validator/tree/master/examples/tal)).

## Build

Just run a simple:

```
docker build -t fort:latest .
```

## Usage

By default, the container uses a configuration file located (inside the container) at `/etc/fort/fort.conf`. The file content is:

```
{
  "tal":"/etc/fort/tal",
  "local-repository":"/var/local/fort"
}
```

Here's a basic usage example to run FORT validator mostly with default values (runs as RTR server by default, bound to port 323):

```
docker run --name fort -v host/path/to/tals:/etc/fort/tal:ro -p 323:323 -d fort
```

At this example:
- `host/path/to/tals` is the path a the host machine where the TALs are located (`-v` mounts the content at the container, the last value `:ro` is to use it as read only). Inside the container, by default `fort` will seek the TALs at `/etc/fort/tal`.
- The host port `323` is mapped to the container port `323`, which is the default value where the RTR server will be bound to (see [`--server.port`](https://nicmx.github.io/FORT-validator/usage.html#--serverport)).
- `-d` runs the container in daemon mode.

When using `-d` to run the service in the background the logs can be tailed like so:

```
docker logs -f fort
```

## Examples

The container can receive more configuration arguments, useful to set more [Program Arguments](https://nicmx.github.io/FORT-validator/usage.html).

1. Store the local cache at the host machine (using the path `path/to/cache`) and run as RTR server:

```
docker run --name fort -v path/to/tals:/etc/fort/tal:ro \
           -v path/to/cache:/var/local/fort \
           -p 323:323 -d fort
```

2. Use your own config file:

```
docker run --name fort -v path/to/config/file:/etc/fort/fort.conf:ro -p 323:323 -d fort
```

3. Use your own command arguments:

```
docker run --name fort -v path/to/tals:/etc/fort/tal:ro -p 323:323 -ti fort [args]
```

3.1. Using the [`--help`](https://nicmx.github.io/FORT-validator/usage.html#--help) argument:

```
docker run --name fort --rm -ti fort -- -help
```

3.2. Running once and printing the resulting valid ROAs to standard output:

```
docker run --name fort --rm -v path/to/tals:/etc/fort/tal:ro \
           -ti fort --tal /etc/fort/tal --mode standalone --output.roa -
```

3.3. Using a SLURM file (located at `path/to/slurm/my.slurm`):

```
docker run --name fort -rm -v path/to/tals:/etc/fort/tal:ro -v path/to/slurm:/tmp:ro \
           -p 323:323 -ti fort --slurm /tmp/my.slurm
```
