---
title: mode=print
---

# mode=print

Syntax:

```bash
fort --mode=print [--file-type=TYPE] [FILE]
```

Assuming `FILE` is a path to an RPKI object file (Certificate, CRL, ROA, Manifest or Ghostbusters), the command will convert it to JSON and print it in standard output:

```bash
$ curl -O https://rrdp.lacnic.net/ta/rta-lacnic-rpki.cer
$ fort --mode=print rta-lacnic-rpki.cer
{
    "tbsCertificate": {
        "version": 2,
        "serialNumber": "119535412AFEDFAEB97837B2E1E2EFF1E77B9AAB",
        "signature": "RSA-SHA256",
        "issuer": {
            "rdnSequence": [
                {
                    "type": "commonName",
                    "value": "FC8A9CB3ED184E17D30EEA1E0FA7615CE4B1AF47"
                }
            ]
        },
        "validity": {
            "notBefore": "Mar  5 14:14:56 2024 GMT",
            "notAfter": "Mar  5 14:19:56 2124 GMT"
        },
        "subject": {
            "rdnSequence": [
                {
                    "type": "commonName",
                    "value": "FC8A9CB3ED184E17D30EEA1E0FA7615CE4B1AF47"
                }
            ]
        },
        "subjectPublicKeyInfo": {
            "algorithm": "rsaEncryption",
            "subjectPublicKey": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqZEzhYK0+PtDOPfub/KR\nc3MeWx3neXx4/wbnJWGbNAtbYqXg3uU5J4HFzPgk/VIppgSKAhlO0H60DRP48by9\ngr5/yDHu2KXhOmnMg46sYsUIpfgtBS9+VtrqWziJfb+pkGtuOWeTnj6zBmBNZKK+\n5AlMCW1WPhrylIcB+XSZx8tk9GS/3SMQ+YfMVwwAyYjsex14Uzto4GjONALE5oh1\nM3+glRQduD6vzSwOD+WahMbc9vCOTED+2McLHRKgNaQf0YJ9a1jG9oJIvDkKXEqd\nfqDRktwyoD74cV57bW3tBAexB7GglITbInyQAsmdngtfg2LUMrcROHHP86QPZINj\nDQIDAQAB\n-----END PUBLIC KEY-----\n"
        },
        "issuerUniqueID": null,
        "subjectUniqueID": null,
        "extensions": [
            {
                "extnID": "X509v3 Basic Constraints",
                "critical": true,
                "extnValue": {
                    "cA": true,
                    "pathLenConstraint": null
                }
            },
            {
                "extnID": "X509v3 Subject Key Identifier",
                "critical": false,
                "extnValue": "fc8a9cb3ed184e17d30eea1e0fa7615ce4b1af47"
            },
            {
                "extnID": "X509v3 Key Usage",
                "critical": true,
                "extnValue": {
                    "digitalSignature": false,
                    "contentCommitment": false,
                    "keyEncipherment": false,
                    "dataEncipherment": false,
                    "keyAgreement": false,
                    "keyCertSign": true,
                    "cRLSign": true,
                    "encipherOnly": false,
                    "decipherOnly": false
                }
            },
            {
                "extnID": "Subject Information Access",
                "critical": false,
                "extnValue": [
                    {
                        "accessMethod": "CA Repository",
                        "accessLocation": "rsync://repository.lacnic.net/rpki/lacnic/"
                    },
                    {
                        "accessMethod": "RPKI Manifest (RFC 6487)",
                        "accessLocation": "rsync://repository.lacnic.net/rpki/lacnic/FC8A9CB3ED184E17D30EEA1E0FA7615CE4B1AF47.mft"
                    },
                    {
                        "accessMethod": "RPKI Update Notification File (RFC 8182)",
                        "accessLocation": "https://rrdp.lacnic.net/rrdp/notification.xml"
                    }
                ]
            },
            {
                "extnID": "X509v3 Certificate Policies",
                "critical": true,
                "extnValue": [
                    {
                        "policyIdentifier": "Certificate Policy (CP) for the Resource PKI (RPKI)",
                        "policyQualifiers": null
                    }
                ]
            },
            {
                "extnID": "sbgp-ipAddrBlock",
                "critical": true,
                "extnValue": [
                    {
                        "addressFamily": "IPv4",
                        "ipAddressChoice": [
                            "0.0.0.0/0"
                        ]
                    },
                    {
                        "addressFamily": "IPv6",
                        "ipAddressChoice": [
                            "::/0"
                        ]
                    }
                ]
            },
            {
                "extnID": "sbgp-autonomousSysNum",
                "critical": true,
                "extnValue": {
                    "asnum": [
                        {
                            "min": "0",
                            "max": "FFFFFFFF"
                        }
                    ],
                    "rdi": null
                }
            }
        ]
    },
    "signatureAlgorithm": "sha256WithRSAEncryption",
    "signatureValue": "919f68ef2cc37b0cafff186346bb05f888c47b202f86fb9fa14d6e42f7310aa03cbe7766cf446e6441ddae0088b8fc66273b9602d919985efc7a3786bf7de147a10f19e2a0a13f2f5ad9c0713ddc38fff43254d152f4687e7b23b0ed9247a21701e88d16ebd9f44162bba1056fd48e3d9e12b1696751d41e3057d7139aae0d0ff2c38b3e0af3bd3c566ca73e01f5baa985b343d805a3887fba76486c3049fcd600e3901938acee68acc7ef8258f2f0f9b03f68437b1d7d5660ac797b3af7eae6d981791e319deec9c326bb2537127d737531132bc0c9a8e75954203f7e98454516f527575e7ebeb7313810e8ed8524b358050adb8e40772e6b24865655b0059c"
}
```

If `FILE` is omitted or "`-`", `fort` will receive the file through standard input. The command above is equivalent to

```bash
curl https://rrdp.lacnic.net/ta/rta-lacnic-rpki.cer | fort --mode=print
```

RPKI files do not contain magic headers, so Fort infers their type by analyzing their internal ASN.1 structures. If you need to override this behavior, use `--file-type`:

```bash
# Skip file type guesser; assume the file is a ROA.
fort --mode=print --file-type=roa unknown.bin
```

`--file-type` can be either `roa`, `mft` (Manifest), `gbr` (Ghostbusters), `cer` (Certificate) or `crl`.

If the object you want to print is contained in an RRDP Snapshot or RRDP Delta, extract it by way of an XML querier and a base64 decoder. Say, for example, that you want to Jsonify the object `rsync://repository.lacnic.net/rpki/lacnic/sample2.crl` from [this delta](sample/delta.xml):

```bash
curl https://nicmx.github.io/FORT-validator/sample/delta.xml | # Download the file
	xmlstarlet sel -t -v '//_:publish[@uri="rsync://repository.lacnic.net/rpki/lacnic/sample2.crl"]' | # Extract sample2.crl
	base64 --decode |	# Convert from base64 to raw
	fort --mode=print	# Ask Fort to Jsonify it
```

`rsync` does not appear to be able to pipe to standard output, so Fort will sync it internally if `FILE` is an rsync URL:

```bash
fort --mode=print rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer
```

At the moment, this downloads the file to `/tmp`. Refactors associated with [issue82](https://github.com/NICMx/FORT-validator/issues/82) will (in a future release) allow Fort to download it into the [regular cache](usage.html#--local-repository).
