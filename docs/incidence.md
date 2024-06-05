---
title: Incidence
description: The incidence section of Fort's configuration file is a means to modify its behavior upon encountering profile violations that, from experience, are often overlooked.
---
 
# {{ page.title }} 

## Index

1. [Introduction](#introduction)
2. [`incidences` definition](#incidences-definition)
3. [Incidence types](#incidence-types)
	1. [Signed Object's hash algorithm has NULL object as parameters](#signed-objects-hash-algorithm-has-null-object-as-parameters)
	2. [Object isn't DER encoded](#object-isnt-der-encoded)
	3. [File listed at manifest doesn't exist](#file-listed-at-manifest-doesnt-exist)
	4. [File hash listed at manifest doesn't match the actual file hash](#file-hash-listed-at-manifest-doesnt-match-the-actual-file-hash)
	5. [Manifest is stale](#manifest-is-stale)
	6. [CRL is stale](#crl-is-stale)

## Introduction

The RPKI RFCs define fairly strict profiles for RPKI objects, and are unequivocal in stating that incorrectly-formed objects are supposed to be rejected by Relying Party validation. In practice, however, this does not prevent a significant amount of legitimate Certificate Authorities from issuing incorrect objects.

The `incidence` section of FORT's configuration file is a means to modify its behavior upon encountering profile violations that, from experience, are often overlooked.

## `incidences` definition

`incidences` is a JSON array that contains (anonymous) incidence elements. Here's an example:

```
"incidences": [
	{
		"name": "incid-hashalg-has-params",
		"action": "warn"
	}
]
```

`name` is the identifier of an incidence. It is case-sensitive and developer-defined. It states the ID of the particular error condition that will be handled by the remaining field.

`action` is an enumeration that states the outcome of a violation of the corresponding incidence. It can take one of three values:

1. `error`: Print error message in `error` log level, fail validation of the offending object (and all of its children).
2. `warn`: Print error message in `warning` log level, continue validation as if nothing happened.
3. `ignore`: Do not print error message, continue validation as if nothing happened.

Some incidences are `ignore`d by default, because they stem from bad practices (which are nonetheless likely harmless) in the global RPKI repositories. If a strict behavior is desired, then the corresponding incidence `action` should be upgraded.

## Incidence types

Presently, there are a few incidences defined. This list might evolve further over time, depending on the state of the global RPKI and user demand.

### Signed Object's hash algorithm has NULL object as parameters

- **Name:** `incid-hashalg-has-params`
- **Default action:** `ignore`

[RFC 6488](https://tools.ietf.org/html/rfc6488) (RPKI Signed Objects) defers digest algorithm specification to RFC 6485:

```
   The digestAlgorithms set contains the OIDs of the digest algorithm(s)
   used in signing the encapsulated content.  This set MUST contain
   exactly one digest algorithm OID, and the OID MUST be selected from
   those specified in [RFC6485].
```

[6485](https://tools.ietf.org/html/rfc6485) has been obsoleted by [7935](https://tools.ietf.org/html/rfc7935), which states the following:

```
   The object identifier and
   parameters for SHA-256 (as defined in [RFC5754]) MUST be used for the
   SignedData digestAlgorithms field and the SignerInfo digestAlgorithm
   field.
```

[RFC 5754](https://tools.ietf.org/html/rfc5754):

```
   There are two possible encodings for the AlgorithmIdentifier
   parameters field associated with these object identifiers. (...)
   some implementations encode parameters as a NULL element
   while others omit them entirely.  The correct encoding is to omit the
   parameters field;
```

As of 2020-07-14, many signed objects in the global RPKI break this rule.

If not `ignore`d, FORT will report this incidence with the following error message at the validation log:

```
<log level>: <offending file name>: The hash algorithm of the '<object>' has a NULL object as parameters
```

This only applies to digest parameters that have been defined as NULL objects; any other type of non-absent digest parameters will yield a different error message, and will therefore not be silenced.

### Object isn't DER encoded

- **Name:** `incid-obj-not-der-encoded`
- **Default action:** `ignore`

Deprecated. `incid-obj-not-der-encoded` does nothing as of Fort 1.6.2.

### File listed at manifest doesn't exist

- **Name:** `incid-file-at-mft-not-found`
- **Default action:** `error`

[RFC 6486 section 6.1](https://tools.ietf.org/html/rfc6486#section-6.1) considers this scenario:

```
   2. {..} If there exist files at the publication point that do not appear
      on any manifest, or files listed in a manifest that do not appear
      at the publication point, then see Section 6.5, but still continue
      with the following test.
```

If there's a missing file, it could be a publisher error or even an attack against the publication point (see [section 6.5](https://tools.ietf.org/html/rfc6486#section-6.5)).

By default, FORT validator will handle this as an error, thus discarding the manifest file.

When the incidence is not `ignore`d, FORT will report it with the following message at the validation log:

```
<log level>: <manifest file name>: File '<file name>' listed at manifest doesn't exist.
```

### File hash listed at manifest doesn't match the actual file hash

- **Name:** `incid-file-at-mft-hash-not-match`
- **Default action:** `error`

[RFC 6486 section 6.1](https://tools.ietf.org/html/rfc6486#section-6.1) considers this scenario:

```
   4. {..} If the computed hash value of a file listed on the manifest does
      not match the hash value contained in the manifest, then see
      Section 6.6.
```

It's up to a local policy to discard these files (and the rest of the manifest files) or trust in them (see [section 6.6](https://tools.ietf.org/html/rfc6486#section-6.6)).

By default, FORT validator will discard such files and the manifest as well.

When the incidence is not `ignore`d, FORT will report it with the following message at the validation log:

```
<log level>: <manifest file name>: File '<file name>' does not match its manifest hash.
```

### Manifest is stale

- **Name:** `incid-mft-stale`
- **Default action:** `error`

[RFC 6486 section 6.1](https://tools.ietf.org/html/rfc6486#section-6.1) considers this scenario:

```
   3. Check that the current time (translated to UTC) is between
      thisUpdate and nextUpdate.
      
      If the current time does not lie within this interval, then see
      Section 6.4 {..}
```

And citing [section 6.4](https://tools.ietf.org/html/rfc6486#section-6.4):

```
   A manifest is considered stale if the current time is after the
   nextUpdate time for the manifest. {..}
   
   All signed objects at the publication point issued by the entity that
   has published the stale manifest, and all descendant signed objects
   that are validated using a certificate issued by the entity that has
   published the stale manifest at this publication point, SHOULD be
   viewed as somewhat suspect, but MAY be used by the RP as per local
   policy.
```

This 'local policy' is the equivalent to the incidence `incid-mft-stale`.

By default, FORT validator will discard a stale manifest and all of its listed elements.

When the incidence is not `ignore`d, FORT will report it with the following message at the validation log:

```
<log level>: <manifest file name>: Manifest is stale. (nextUpdate: <human readable date> )
```

### CRL is stale

- **Name:** `incid-crl-stale`
- **Default action:** `error`

The RFC's aren't clear about stale CRLs; but as strict (or pedantic) as FORT is, a stale CRL isn't trusted by default. A stale CRL is the one where its 'nextUpdate' is in the past.

The "cost" of stop using a stale CRL, is that all of the related CA childs will be discarded as well.

There's a whole discussion on this subject at SIDROPS WG (see the mail archive for ["[Sidrops] what to do when the CRL is hosed?"](https://mailarchive.ietf.org/arch/msg/sidrops/tCybZO7YvXbdVm5pA7DbHEnuKEc/); so, until a concensus is reached on the matter, the RP operator can configure the incidence `incid-crl-stale` to decide how to treat this CRLs.

When the incidence is not `ignore`d, FORT will report it with the following message at the validation log (note that the CRL is validated as part of the manifest validation):

```
<log level>: <manifest file name>: CRL is stale/expired
```
