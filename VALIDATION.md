# Validation — October 6, 2026

Built and tested on Windows with Python 3.12.

- **20 tests passed**, including the opt-in real Chromium test, in 9.43 seconds.
- After the final client-output-path restriction and fast-process cleanup adjustment, both affected command/client regression tests passed again (2 passed, 17 deselected).
- Real loopback HTTPS: certificate verification, scoped bearer authentication, actual command execution through the client, rejected browser-origin requests, and revocation verified.
- Browser: real Playwright Chromium submitted a synthetic password into a synthetic HTTPS login form. Requests were fulfilled in-process; the test verified domain blocking and redaction of a reflected fake credential. No real site or account was used.
- Commander adapter: legacy records, typed records, custom fields, ambiguous-field rejection, and session cleanup exercised against the installed SDK with synthetic record objects.
- API calls: HTTP transport fixtures verified secret header injection, redirect rejection, selected JSON output, and redaction.
- Commands: actual subprocess execution verified environment injection, suppression/redaction, parent-environment filtering, timeouts and output limits. TOTP generation/injection was exercised.
- Windows: actual state initialization, restrictive ACL creation, readable protected client-file creation, and client revocation smoke-tested with dummy account metadata.
- Example policy validated; Python source compiled; installed dependency requirements checked successfully.

Tested versions: Keeper Commander 18.1.6, Playwright 1.63.0, Chromium 153.0.8010.12, HTTPX 0.28.1, cryptography 50.0.2, pyotp 2.10.0, psutil 7.2.2, pytest 9.1.1. Exact environment versions are in `constraints-windows-py312.txt`.

## Not verified or activated

- No real Keeper login, device approval, account MFA, vault read, or credential export took place. A live connection requires the owner's private terminal authentication.
- No production API endpoint, real website login, account action, or production credential was used. Individual site selectors, success checks and MFA flows need configuration.
- A separate OS account has not been provisioned. Tests ran under the current account with synthetic secrets; this is not evidence of isolation from another user or an administrator.
- Microsoft Edge launch timed out on this host. The browser test passed using Playwright's Chromium; the example and recommended setup use Chromium.
- No daemon, scheduled task, autostart entry, firewall change, or public listener was installed. No global CLI installation or deployment was performed.
- Process cleanup and browser routing are not OS sandbox/network-isolation guarantees. See the README's trust boundary before connecting real secrets.
- This software has not received an independent security audit. Tests validate the listed cases, not an absolute guarantee against credential disclosure.
