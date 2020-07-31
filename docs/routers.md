---
title: Routers
description: Configuration guide for FORT Validator interaction with routers through RTR protocol.
---
 
# {{ page.title }}

## Index

1. [Introduction](#introduction)
2. [Server configuration](#server-configuration)
3. [Router configuration](#router-configuration)
4. [Behavior](#behavior)
	1. [(Re)start](#restart)
	2. [Continuous validation](#continuous-validation)

## Introduction

Just as mentioned at [Introduction to Fort](intro-fort.html), the validated ROAs prefixes and BGPsec router certificates are served so that any router can request them. This is where the RTR protocol comes in.

Fort validator supports RTR version 0 ([RFC 6810](https://tools.ietf.org/html/rfc6810)) and version 1 ([RFC 8210](https://tools.ietf.org/html/rfc8210)). It depends on the router RTR implementation which version to use during the data exchange.

## Server configuration

The most relevant program arguments for the communication of Fort validator with the routers are:
- [`--mode`](usage.html#--mode): must have the value `server` in order to run FORT validator as RTR server.
- [`--server.address`](usage.html#--serveraddress): network address where the server will listen for routers.
- [`--server.port`](usage.html#--serverport): port or service (see `‘$ man services’`) where the server will listen for routers.
- [`--server.backlog`](usage.html#--serverbacklog): max number of outstanding connections in the server listen queue.
- [`--server.interval.validation`](usage.html#--serverintervalvalidation): wait time (in seconds) between validations cycles. It also affects on how often the server could send update notifications to the routers (if there are updates as result of the last validation cycle).
- [`--server.interval.refresh`](usage.html#--serverintervalrefresh): "This parameter tells the router how long to wait before next attempting to poll the cache and between subsequent attempts" (definition of _"Refresh Interval"_ from [RFC 8210 section 6](https://tools.ietf.org/html/rfc8210#section-6)).
- [`--server.interval.retry`](usage.html#--serverintervalretry): "This parameter tells the router how long to wait before retrying a failed Serial Query or Reset Query." (definition of _"Retry Interval"_ from [RFC 8210 section 6](https://tools.ietf.org/html/rfc8210#section-6)).
- [`--server.interval.expire`](usage.html#--serverintervalexpire): "This parameter tells the router how long it can continue to use the current version of the data while unable to perform a successful subsequent query" (definition of _"Expire Interval"_ from [RFC 8210 section 6](https://tools.ietf.org/html/rfc8210#section-6)).

## Router configuration

Each router has its own way to configure its connection with an RTR server, but the basic data needed to configure this is:
- **Server address and port**: where the RTR server is located (configured at [`--server.address`](usage.html#--serveraddress) and [`--server.port`](usage.html#--serverport)).
- **Refresh interval**: how often does the router will ask for updates to the server.
- **Preference**: if multiple RTR servers are allowed, this indicates the preference order of each one of them. This way the router will go for updates according to such order.

Here are a few links to the RPKI configuration docs at some routers:
- [FRR](http://docs.frrouting.org/en/latest/bgp.html#prefix-origin-validation-using-rpki)
- [Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/command/irg-cr-book/bgp-a1.html#wp2807841905)
- [Juniper](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/validation-edit-routing-options.html)
- [BIRD](https://bird.network.cz/?get_doc&v=20&f=bird-6.html#ss6.13)

## Behavior

### (Re)start

When Fort validator is run for the first time, the RTR server will listen for router connections at [`--server.address`](usage.html#--serveraddress):[`--server.port`](usage.html#--serverport) once its first validation cycle ends.

If a router tries to establish a connection with Fort before the first validation cycle ends, Fort won't respond at all, causing the router to wait some time (this will depend on each router) before asking for updates again.

Once FORT validator ends its first validation cycle, it will share the resulting data (also known as "Validated ROA Payloads" or VRPs) with any router that establishes an RTR connection.

> ![img/warn.svg](img/warn.svg) **TIP:** When Fort validator is run for the first time, wait a couple of minutes to connect the router, so that it can fetch all the valid data once the connection is established.

### Continuous validation

FORT validator will keep fetching and validating the repositories data once every [`--server.interval.validation`](usage.html#--serverintervalvalidation) seconds. If there are any updates at the VRPs, FORT will notify the routers so that they can request the updates; it's up to the routers to attend or ignore this notification message.

Beside the notifications sent by the RTR server, the routers can periodically ask for updates. This can be configured at the router (see [Router configuration](#router-configuration)) and/or at the server (see [`--server.interval.refresh`](usage.html#--serverintervalrefresh)).
