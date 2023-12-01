# FORT Validator Docker Image

This is [NICMx/FORT-validator](https://github.com/NICMx/FORT-validator)'s official Docker image. It's updated on every release.

Special thanks to [ximon18](https://github.com/ximon18) for his [contribution](https://github.com/NICMx/FORT-validator/issues/17).

> Note: Thanks to [ARIN's RPA policy update](https://www.arin.net/announcements/20220926/), FORT's Docker image is now (as of version 1.5.4) allowed to ship with all 5 RIR TALs. This means it is no longer necessary to configure them separately.

## Getting the image

To pull the official docker image, run

```bash
docker pull nicmx/fort-validator:latest
```

If you want to build the image yourself, run the following command in the current directory:

```bash
docker build -t fort-validator:latest .
```

## Usage

In case it isn't obvious: **This will download a large amount of data; don't run it on a metered connection.**

```bash
docker run --name fort-validator --publish 323:323 --detach nicmx/fort-validator
```

Host port `323` is mapped to container port `323`, which is the [RTR server's default binding port](https://nicmx.github.io/FORT-validator/usage.html#--serverport). Once the first validation cycle is complete, your routers will be able to access the VRP table through this service.

Default [configuration](https://nicmx.github.io/FORT-validator/usage.html#--configuration-file):

```json
{
	"tal":"/etc/fort/tal",
	"local-repository":"/var/local/fort"
}
```

`--detach` runs the container in daemon mode. You can access the logs like so:

```bash
docker logs -f fort-validator
```

## Examples

Store the local cache in the host machine's `/path/to/cache` directory:

```bash
docker run \
	--name fort-validator \
	--publish 323:323 \
	--volume /path/to/cache:/var/local/fort \
	--detach \
	nicmx/fort-validator
```

Use your own configuration file:

```bash
docker run \
	--name fort-validator \
	--publish 323:323 \
	--volume /path/to/fort-config.json:/etc/fort/fort.conf:ro \
	--detach \
	nicmx/fort-validator
```

Append command line arguments:

```bash
docker run \
	--name fort-validator \
	--publish 323:323 \
	--tty --interactive \
	nicmx/fort-validator \
	[args]
```

Print [`--help`](https://nicmx.github.io/FORT-validator/usage.html#--help):

```bash
docker run \
	--name fort-validator \
	--rm \
	--tty --interactive \
	nicmx/fort-validator \
	--help
```

Perform full validation, then print the VRP table to standard output:

```bash
docker run \
	--name fort-validator \
	--rm \
	--tty --interactive \
	nicmx/fort-validator \
	--configuration-file /etc/fort/fort.conf --mode standalone --output.roa -
```
