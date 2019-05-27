---
title: SLURM
---

[Documentation](index.html) > {{ page.title }}

# {{ page.title }} 

## Introduction

There are reasons why you might legitimately want to modify the RPKI assertions validated and published by an RTR server:

- To assert the validity of private IP addresses and/or AS numbers for local use. (Since they are outside of the scope of the global RPKI.)
- To override temporarily incorrect or outdated global RPKI data.

The "Simplified Local Internet Number Resource Management with the RPKI" (SLURM) is a [standard](https://tools.ietf.org/html/rfc8416) means to accomplish this. In a nutshell, it's just a bunch of JSON files with which you can filter out or append arbitrary ROAs to Fort's RTR payload.

Note that, with the exception of the following section, most of this document is just a summary of [RFC 8416](https://tools.ietf.org/html/rfc8416). You can find more details there.

## Handling of SLURM Files

The SLURM files are defined by the [`--slurm`](usage.html#--slurm) flag. If the flag points to a file, the configuration is extracted from that single file. If it points to a directory, the configuration is the aggregation of the contents of its contained `.slurm` files.

None of the entries of the SLURM configuration are allowed to collide with each other. If there is a collision, the overall SLURM configuration is invalidated.

Fort reloads the SLURM files during every validation cycle. If the new configuration is invalid, **it is treated as nonexistent**. Note that this means that an isolated mistake will temporarily drop all your SLURM overrides. This is intended to change in a future revision of Fort, in which the validator will fall back to the previous valid SLURM configuration on error.

> TODO: open an issue for that. Giving the users the opportunity to argue it is probably a good idea.

## SLURM File Definition

### Root

Each SLURM file is a JSON-formatted collection of filters and/or additions. Each of the members shown is mandatory:

```
{
	"slurmVersion": 1,

	"validationOutputFilters": {
		"prefixFilters": [ <Removed ROAs> ],
		"bgpsecFilters": []
	},

	"locallyAddedAssertions": {
		"prefixAssertions": [ <Added ROAs> ],
		"bgpsecAssertions": []
	}
}
```

The root object contains a `slurmVersion` field (which, for now, must be set to 1), a listing of filters called `validationOutputFilters`, and a listing of additions called `locallyAddedAssertions`. Fort does not yet support BGPsec, so `bgpsecFilters` and `bgpsecAssertions` must be empty.

### `prefixFilters`

`<Removed ROAs>` expands to a sequence of (zero or more) JSON objects, each of which follows this pattern:

```
{
	"prefix": <IP prefix>,
	"asn": <AS number>,
	"comment": <Explanatory comment; ignored by Fort for now>
}
```

Any ROAs that match `prefix` and `asn` will be invalidated. A ROA matches `prefix` by having an equal or more specific IP prefix, and `asn` by having the same AS number.

One of `prefix` and `asn` can be absent. On absence, any prefix matches `prefix`, and any AS number matches `asn`.

`comment` is always optional.

### `prefixAssertions`

`<Added ROAs>` expands to a sequence of (zero or more) JSON objects, each of which follows this pattern:

```
{
	"prefix": <IP prefix>,
	"asn": <AS number>,
	"maxPrefixLength": <Prefix length>
	"comment": <Explanatory comment; ignored by Fort for now>
}
```

Will force Fort into believing that the [`prefix`, `asn`, `maxPrefixLength`] ROA validated successfully.

`prefix` and `asn` are mandatory, `maxPrefixLength` and `comment` are not. `maxPrefixLength` defaults to `prefix`'s length.

## SLURM File Example

```
{
	"slurmVersion": 1,

	"validationOutputFilters": {
		"prefixFilters": [
			{
				"prefix": "192.0.2.0/24",
				"comment": "All VRPs encompassed by prefix"
			}, {
				"asn": 64496,
				"comment": "All VRPs matching ASN"
			}, {
				"prefix": "198.51.100.0/24",
				"asn": 64497,
				"comment": "All VRPs encompassed by prefix, matching ASN"
			}
		],
		"bgpsecFilters": []
	},

	"locallyAddedAssertions": {
		"prefixAssertions": [
			{
				"asn": 64496,
				"prefix": "198.51.100.0/24",
				"comment": "My important route"
			}, {
				"asn": 64496,
				"prefix": "2001:DB8::/32",
				"maxPrefixLength": 48,
				"comment": "My important de-aggregated routes"
			}
		],
		"bgpsecAssertions": []
	}
	}
```
