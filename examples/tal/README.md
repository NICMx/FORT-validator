# TALs

Most of the Trust Anchor Locators of the RIRs are included here for convenience. (But maybe you should get your own, for security.)

**Almost every TAL includes an HTTPS URI to fetch the trust anchor certificates, FORT validator utilizes such URIs by default.**

The only one that's not included is ARIN's, because you need to agree to their [RPA](https://www.arin.net/resources/manage/rpki/tal/).

In order to ease the ARIN TAL download, there's a script that does that for you: [fort_setup.sh](../../fort_setup.sh). Read more about it at web docs section [Compilation and Installation](https://nicmx.github.io/FORT-validator/installation.html).
