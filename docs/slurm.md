---
title: SLURM
---

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

## SLURM File Definition

### Root

Each SLURM file is a JSON-formatted collection of filters and/or additions. Each of the members shown is mandatory:

```
{
	"slurmVersion": 1,

	"validationOutputFilters": {
		"prefixFilters": [ <Removed ROAs> ],
		"bgpsecFilters": [ <Removed Router Keys> ]
	},

	"locallyAddedAssertions": {
		"prefixAssertions": [ <Added ROAs> ],
		"bgpsecAssertions": [ <Added Router Keys> ]
	}
}
```

The root object contains a `slurmVersion` field (which, for now, must be set to 1), a listing of filters called `validationOutputFilters`, and a listing of additions called `locallyAddedAssertions`.

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

### `bgpsecFilters`

`<Removed Router Keys>` expands to a sequence of (zero or more) JSON objects, each of which follows this pattern:

```
{
	"asn": <AS number>,
	"SKI": <Base64 of some SKI>,
	"comment": <Explanatory comment; ignored by Fort for now>
}
```

Any Router Keys that match `asn` and `SKI` will be invalidated. A Router Key matches `asn` by having the same AS number and `SKI` by having the same decoded Subject Key Identifier.

One of `asn` and `SKI` can be absent. On absence, any AS number matches `asn`, and any Subject Key Identifier matches `SKI`.

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

### `bgpsecAssertions`

`<Added Router Keys>` expands to a sequence of (zero or more) JSON objects, each of which follows this pattern:

```
{
	"asn": <AS number>,
	"SKI": <Base64 of some SKI>,
	"routerPublicKey": <Base64 of some public key>,
	"comment": <Explanatory comment; ignored by Fort for now>
}
```

Will force Fort into believing that the [`asn`, `SKI`, `routerPublicKey`] Router Key validated successfully.

Only `comment` isn't mandatory, the rest [`asn`, `SKI`, `routerPublicKey`] are mandatory.

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
		"bgpsecFilters": [
			{
				"asn": 64496,
				"comment": "All keys for ASN"
			}, {
				"SKI": "Q8KMeBsCto1PJ6EuhowleIGNL7A",
				"comment": "Key matching Router SKI"
			}, {
				"asn": 64497,
				"SKI": "g5RQYCnkMpDqEbt9WazTeB19nZs",
				"comment": "Key for ASN 64497 matching Router SKI"
			}
		]
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
		"bgpsecAssertions": [
			{
				"asn": 64496,
				"SKI", "Dulqji-sUM5sX5M-3mqngKaFDjE",
				"routerPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE-rkSLXlPpL_m-L7CfCfKrv1FHrM55FsIc8fMlnjHE6Y5nTuCn3UgWfCV6sYuGUZzPZ0Ey6AvezmfcELUB87eBA",
				"comment": "My known key for my important ASN"
			}
		]
	}
}
```
