---
title: Stats
---

# {{ page.title }}

Enable the Prometheus server with [`--prometheus.port`](usage.html#--prometheusport) and [`--mode=server`](usage.html#--mode):

```bash
$ fort --mode=server --prometheus.port=8000 /path/to/tal
$ curl localhost:8000/metrics
fort_rtr_ready 1 1757646873
fort_rtr_current_connections 0 1757646873
fort_valid_vrps_total{ta="test",proto="ipv4"} 44 1757646873
fort_valid_vrps_total{ta="test",proto="ipv6"} 66 1757646873
# EOF
```

The implementation is still very fresh, and prioritizes minimal monitoring over exhaustive reporting. Therefore, there are not many stats yet. Please request your preferred values via the [issue tracker](https://github.com/NICMx/FORT-validator/issues).

## `fort_rtr_ready`

- Type: Gauge (effectively boolean)

Starts as 0, becomes 1 when the validator has a complete VRP table to serve via RTR.

## `fort_rtr_current_connections`

- Type: Gauge

Number of presently open connections with RTR clients.

## `fort_valid_vrps_total{ta="<TA>",proto="<IP>"}`

- Type: Gauge

Total number of VRPs generated from TA `<TA>` and protocol `<IP>` during the previous validation cycle.

Labels:

- `<TA>` is the TAL's file name, minus extension. (The `<TA>` of "`/etc/fort/tal/ripe-ncc.tal`" would be `ripe-ncc`.)
- `IP` is either `ipv4` or `ipv6`.
