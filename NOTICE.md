# Notices

NekoCTI is Copyright (C) 2026 Cameron Gates (GodOfNekos), licensed under the GNU Affero General
Public License v3.0 or later (see [LICENSE](LICENSE)). It uses the third-party work below, each
under its own terms.

## MITRE ATT&CK

The ATT&CK data (`enterprise-attack.json`, downloaded when the Docker image is built from
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data), not stored in
this repository) is used to validate and label ATT&CK techniques.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The
MITRE Corporation.

The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use
ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes
is authorized provided that you reproduce MITRE's copyright designation and this license in any
such copy.

ATT&CK® is a registered trademark of The MITRE Corporation. NekoCTI isn't affiliated with or
endorsed by MITRE.

## Center for Threat-Informed Defense mappings

The CVE-to-ATT&CK mapping of the CISA Known Exploited Vulnerabilities catalogue
(`ctid-kev-attack-mapping.json`, downloaded when the Docker image is built from
[center-for-threat-informed-defense/mappings-explorer](https://github.com/center-for-threat-informed-defense/mappings-explorer),
not stored in this repository) is licensed under the Apache License 2.0.

## Share Tech Mono

`fonts/ShareTechMono-Regular.ttf` is Copyright (c) 2012, Carrois Type Design, Ralph du Carrois,
with Reserved Font Name 'Share', licensed under the SIL Open Font License 1.1. The licence is in
`fonts/OFL-ShareTechMono.txt`.

## Data sources

Articles, advisories and scores (The Hacker News, Krebs on Security, CISA KEV, GitHub Security
Advisories, NVD, FIRST.org EPSS and the curated threat-intel blogs) are fetched at run time into
your own local database. So are CVE Records from the CVE Program's
[cvelistV5](https://github.com/CVEProject/cvelistV5) repository, used under the
[CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse), and the PoC listing from
[nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub). None of that content is
stored in or distributed with this repository. Each source's own terms apply to what you fetch.

## Python dependencies

Installed by `uv` from `uv.lock`, not stored in this repository. Each is under its own licence
(MIT, BSD, Apache-2.0, MPL-2.0 or PSF); see each package's metadata.
