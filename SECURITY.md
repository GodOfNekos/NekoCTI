# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub's **Report a vulnerability** button on
this repository's Security tab (private vulnerability reporting), not in a public issue.

Include what you found, how to reproduce it, and what an attacker could do with it. You'll get an
acknowledgement, and a fix or a decision, as soon as is practical. This is a one-person project
maintained in spare time, so there's no fixed timescale.

## Supported versions

Only the latest commit on `main` is supported.

## How NekoCTI is meant to be deployed

NekoCTI is a single-user tool for a private network. The supported setup is the Docker container
published on the host's loopback (as `docker-compose.yml` does), reached from other devices only
through private access you control (a VPN, or a reverse proxy serving HTTPS), and protected by the
dashboard's own password login. Running it on the public internet is outside what it's designed
for.

Things the design already assumes are hostile, and handles:
- **Feed content.** Titles, links, images and article text come from third parties. They're
  escaped before display, URLs are restricted to http(s), and a strict Content-Security-Policy
  is sent with every page.
- **Article fetching.** Full-text fetches only go to public addresses, never to private,
  loopback, link-local or tailnet ones. Known limit: a redirect isn't re-checked.
- **The dashboard API.** It needs a session, writes need a custom header (which blocks cross-site
  form posts), and configuration writes are validated and size-capped.
