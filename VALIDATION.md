# Validation

## Skill review and hardening 0.3.2 — October 29, 2026

- **100 backend tests passed** with the updated dependencies and opt-in real Chromium test, in 77.29 seconds. New regressions cover client-file ownership during revocation, bounded execution-slot waiting and activity history across rotated logs; the real TLS test checks HTTP 503 and `queue_timeout`.
- Six desktop-preview UI tests passed in 16.6 seconds, including accessible dialog names and initial/return keyboard focus. Three authenticated web UI tests passed in 13.0 seconds. Formatting and the production build pass with zero Svelte/TypeScript errors or warnings.
- Updated certifi to 2026.10.19, Pillow to 13.0.0 and setuptools to 84.1.0, checking compatibility after each update. The final 87-package Python environment passes `uv pip check` and `pip-audit` reports no known vulnerabilities. The npm audit retains three low entries in one unpatched build-tool dependency chain; no high, moderate or critical entries. See [the review](docs/SKILL-REVIEW.md) for the advisory and triage limits. No Rust advisory audit was completed.
- Automatic PR/main source-check workflows are prepared, with read-only permissions, dependency audits and synthetic backend/UI tests. Local equivalent commands pass; hosted CI execution has not been performed.
- The [skill review](docs/SKILL-REVIEW.md) distinguishes the complete inventory/screening from close reading of relevant guidance. Attempted independent reviews stopped on usage limits and are not counted as verification.
- Windows frozen-helper and web-host smoke tests pass. The ZIP passes its CRC test and includes the updated agent guide; the NSIS installer passes its 7-Zip integrity test. The extracted helper and four bundled web assets match the verified runtime and production build. The bundled CA store matches patched certifi, and the archive contains Pillow 13.0.0 and the client-file ownership fix. Exact filenames and hashes are in [the 0.3.2 manifest](docs/RELEASE-0.3.2.md).
- Older manifests below describe their historical artifacts. No real credentials or production actions were used. No installer was run; macOS 0.3.2 and full native interaction remain unverified.

## Agent setup and access 0.3.1 — October 29, 2026

- **97 backend tests passed**, including opt-in real Chromium tests, in 67.05 seconds on this Windows host. Thirteen new cases cover concurrent workspace saves, cross-process revocation, lock cleanup/nesting, grant expiry and compatibility, invalid durations, metadata-only status, safe structured errors, temporary grants, and replacement-token checks before execution.
- Six desktop-preview UI tests passed in 14.1 seconds. Three authenticated web UI tests passed in 12.5 seconds. The new guided flow tests cover preselecting the tested action, changing access duration, creating access, and copying working connection-command text without exposing the token.
- Production frontend build: zero Svelte/TypeScript errors or warnings. Result details are collapsed by default. The agent-access completion dialog was visually inspected.
- Existing JSON workspaces and grants without expiry remain compatible. New grants default to seven days. Built-in edits serialize through an OS file lock across processes and atomic JSON replacement; this is not a database migration or a multi-file crash-recovery transaction. Manual file editing does not acquire that lock.
- Windows frozen desktop-helper and web-host smoke checks passed, including grant expiry metadata, agent CLI routing and structured JSON failures. The standalone ZIP passed a CRC integrity test; the NSIS installer passed a 7-Zip integrity test. The installer's extracted helper and frontend match the verified runtime and UI build. Filenames and SHA-256 checksums are in [the 0.3.1 manifest](docs/RELEASE-0.3.1.md).
- Tests use synthetic state and credentials. No installer was run. Real Keeper authentication, separate-account isolation, and macOS execution were not tested in this continuation.

## Source continuation — October 29, 2026

- Started from Claude's completed source at `0947732`. Reviewed the recent Claude transcript for this repository before making changes.
- **84 backend tests passed**, including the opt-in real Chromium tests, in 57.42 seconds on Windows with the repository's Python environment. Tests use synthetic credentials; no live Keeper authentication or production action was performed.
- Four new regression cases failed before the fixes: duplicate legacy custom-field labels, multiple values in a typed standard field, multiple values in a typed custom field, and audit rotation after a clock rollback. They now pass. The rotation test also covers repeated timestamps and recovery across process restarts, including a missing current file after rotation.
- Five desktop-preview UI tests passed in 11.1 seconds. Three authenticated web UI tests passed in 11.8 seconds. The production frontend build passed with zero Svelte/TypeScript errors or warnings.
- Ambiguous secret references now fail rather than selecting the first credential. Rotated audit filenames retain write order if the system clock repeats or moves backward; entry timestamps still use the actual system clock.
- This validates source changes only. No frozen runtime, installer or replacement release package was built during this continuation. The October 8 packages below predate the October 25–29 changes.

## Browser application 0.3 — verified October 8, 2026

- [CI run 37671696574](https://github.com/nuroctane/keeper-agent/actions/runs/37671696574), source commit `c16e052`, passed on Windows x64 and macOS ARM64. Each platform passed 48 backend tests, including real Chromium with synthetic credentials. Fourteen web tests cover authentication, exact Host/Origin, CSRF, session expiry/logout, request limits, real TLS/Secure cookies, persisted actions/grants, explicit client downloads, typed Keeper challenge callbacks with synthetic credentials, safe cleanup of finished workers, and rejection of cookie-only access from another localhost service.
- Three authenticated-browser Playwright tests passed: real backend persistence and action execution through pinned local TLS; client download/revocation; mobile layout; and typed password/device/MFA interface challenges. Only Keeper challenge responses are simulated in that test; no live vault is used.
- Five existing preview interface tests passed. Svelte/TypeScript diagnostics: zero errors and warnings. Production assets: 93.11 kB JavaScript (33.95 kB gzip), 27.23 kB CSS (6.24 kB gzip), plus a small dynamic import. These asset sizes are not a RAM benchmark.
- Both frozen web hosts passed startup, bundled assets, authenticated session, cookie-only access rejection, logout, and isolated login-worker import/sanitized-failure smoke tests without contacting Keeper or using an installed Python runtime. Both frozen desktop helpers also passed synthetic CRUD/grant smoke tests. The local Windows packaged Chromium installation worker completed successfully.
- Windows NSIS and Apple Silicon DMG packaging succeeded. Both standalone web ZIPs and both native packages passed local 7-Zip integrity tests. Sizes and SHA-256 checksums are recorded in [the 0.3 build manifest](docs/RELEASE-0.3.0.md).
- No live Keeper authentication or independent security audit was performed. Hardware-key-only, biometric, enterprise SSO, and account recovery flows require existing Keeper tools. Browser workflows run on the broker host; interactive site MFA still needs access to that host's desktop.
- Web deployment, session protections, and authentication limitations are documented in [WEB.md](docs/WEB.md). Packages remain unsigned development builds; macOS notarization, Intel Mac packaging, native UI interaction, and live account/site authentication are not verified. Desktop validation from version 0.2 below remains historical.

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
