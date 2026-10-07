# Validation — October 6, 2026

## Browser application 0.3 — October 7, 2026

- 47 backend cases passed across the default suite, the opt-in Chromium test, and the final web regression run. Thirteen web tests cover authentication, exact Host/Origin, CSRF, session expiry/logout, request limits, real TLS/Secure cookies, persisted actions/grants, explicit client downloads, typed Keeper challenge callbacks with synthetic credentials, and safe cleanup of finished workers.
- Three authenticated-browser Playwright tests passed: real backend persistence and action execution through pinned local TLS; client download/revocation; mobile layout; and typed password/device/MFA interface challenges. Only Keeper challenge responses are simulated in that test; no live vault is used.
- Five existing preview interface tests passed. Svelte/TypeScript diagnostics: zero errors and warnings. Production assets: 92.85 kB JavaScript (33.89 kB gzip), 27.23 kB CSS (6.24 kB gzip), plus a small dynamic import. These asset sizes are not a RAM benchmark.
- The Windows 0.3 frozen web host passed startup, bundled assets, authenticated session, logout, and isolated login-worker import/sanitized-failure smoke tests without contacting Keeper or using an installed Python runtime.
- No live Keeper authentication or independent security audit was performed. Hardware-key-only, biometric, enterprise SSO, and account recovery flows require existing Keeper tools. Browser workflows run on the broker host; interactive site MFA still needs access to that host's desktop.
- Web deployment, session protections, and authentication limitations are documented in [WEB.md](docs/WEB.md). Desktop validation from version 0.2 below remains historical; version 0.3 packaging results will be recorded separately.

## Desktop update — October 7, 2026

- 34 backend tests passed, including real Chromium with synthetic credentials and the desktop's full action-run path through pinned local TLS. Temporary client cleanup, interruption-safe expiry, metadata filtering, CRUD, and grants/revocation were covered.
- Five Playwright interface tests passed: empty setup, search and run confirmation/results, action creation and scoped grants/revocation, keyboard/theme/minimum-width behavior, and screenshot generation. These use browser preview fixtures, not the native bridge.
- Svelte/TypeScript diagnostics: zero errors and warnings. Production frontend: 85.83 kB JavaScript (31.54 kB gzip), 24.77 kB CSS (5.73 kB gzip), plus a small dynamic import.
- Frozen Python helper passed synthetic initialization, action editing, client creation/revocation, metadata non-disclosure, and CLI help. No installed Python is needed by that helper.
- The final helper smoke test measured 1.043 seconds for its initial empty snapshot and 1.103 seconds for a subsequent initialized snapshot. These are individual subprocess measurements on this host during build activity, not cross-platform performance benchmarks.
- The Windows native process launched, remained responsive, and closed cleanly in a smoke test. Full native interaction still needs manual validation.
- The UI does not poll while idle. Its 3.2 MiB native executable uses the platform webview. The Python helper/resources occupy about 204 MiB before installer compression; browser binaries are an optional separate download. Frontend size is not total installed size or a RAM benchmark.
- Windows x64: release compilation and NSIS packaging succeeded locally. The 67.36 MiB installer passed a 7-Zip integrity test, and the embedded helper matched the smoke-tested helper's SHA-256. Installer SHA-256: `F8F6DCC02CF2E25F345F81AE34841FF89A2301D6B1708FE7DB22640F6932A6A6`.
- macOS ARM64: [CI run 37630393709](https://github.com/nuroctane/keeper-agent/actions/runs/37630393709) passed backend tests, interface tests, frozen-helper smoke tests, release compilation, and DMG packaging. The resulting Apple Silicon DMG is 98.11 MiB. Intel macOS has build instructions but was not built in this run.
- Both platform packages are unsigned development builds; macOS notarization is not configured. Native UI interactions, real Keeper authentication, and target-site workflows have not been end-to-end automated. Platform build/runtime observations should not be interpreted as an independent security audit.

The original CLI validation follows.

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

- No real Keeper login, device approval, account MFA, vault read, or credential export took place. A live connection requires the owner's private authentication through a supported browser login flow or terminal.
- No production API endpoint, real website login, account action, or production credential was used. Individual site selectors, success checks and MFA flows need configuration.
- A separate OS account has not been provisioned. Tests ran under the current account with synthetic secrets; this is not evidence of isolation from another user or an administrator.
- Microsoft Edge launch timed out on this host. The browser test passed using Playwright's Chromium; the example and recommended setup use Chromium.
- No daemon, scheduled task, autostart entry, firewall change, or public listener was installed. No global CLI installation or deployment was performed.
- Process cleanup and browser routing are not OS sandbox/network-isolation guarantees. See the README's trust boundary before connecting real secrets.
- This software has not received an independent security audit. Tests validate the listed cases, not an absolute guarantee against credential disclosure.
