# Development build 0.3.2

These historical artifacts predate the subsequent bug-review fixes in the current working tree. Rebuild before using those fixes in a packaged application.

Verified locally on Windows x64, October 29, 2026. Source is `0947732` plus the uncommitted continuation in this checkout. These are unsigned development packages; no installation or publication was performed.

## Changes

- Preserve another grant's client file during revocation by checking token ownership before deletion.
- Bound execution-slot waiting to ten seconds, with HTTP 503 and `queue_timeout` when no action started.
- Keep recent Activity history across audit rotation, within bounded reads and metadata-only output.
- Normalize workspace paths before mutation locking and improve native dialog names and keyboard focus.
- Update certifi to 2026.10.19, Pillow to 13.0.0 and setuptools to 84.1.0. Add automatic source checks and dependency audits; disable npm install scripts except the explicitly rebuilt esbuild binary.
- Preserve the 0.3.1 guided test-to-access flow, expiring grants, metadata-only status, structured agent errors and serialized workspace edits.

The [skill and product review](SKILL-REVIEW.md) explains the full library inventory, applied guidance, reproduced findings and remaining priorities.

## Verification

100 backend tests, six desktop-preview UI tests and three authenticated web UI tests pass. Formatting and the production frontend build pass with zero Svelte/TypeScript errors or warnings. The updated Python environment passes compatibility checks and its third-party dependency audit reports no known vulnerabilities. The npm audit retains three low entries in one unpatched build-tool chain; see the review for triage and scope.

The clean-frozen helper and web host pass their synthetic smoke tests, including CLI routing, grant expiry, bundled assets, authenticated sessions and sanitized login-worker failure. The embedded revoke implementation contains the ownership check; the bundled CA store matches patched certifi, and the frozen Pillow version is 13.0.0. Snapshot smoke timings were 1.049 seconds initially and 1.424 seconds on a subsequent subprocess; these single observations are not performance benchmarks.

The standalone ZIP passed its CRC integrity test and includes the agent guide with `queue_timeout` recovery instructions. The NSIS installer passed a 7-Zip integrity test. Its extracted helper matches the smoke-tested runtime's SHA-256, and all four extracted web asset files match the production build. Native packaging compiled against that same frontend build.

## Windows artifacts

Files are in the ignored `work/releases/0.3.2` folder. `verification.json` records exact sizes, hashes and embedded-file comparisons.

| File | Bytes | Size |
| --- | ---: | ---: |
| `Keeper-Agent-Web-Windows-x64-0.3.2.zip` | 93,758,412 | 89.41 MiB |
| `Keeper-Agent-Windows-x64-0.3.2-setup.exe` | 70,744,741 | 67.47 MiB |

SHA-256:

```text
732ebb57296a0e8ef69cddaad911d9162121a689007141702e23b15f56783e99  Keeper-Agent-Web-Windows-x64-0.3.2.zip
abefb05ab71eafdc424d86e1f799a12093314450b45248d9302d953f0b486664  Keeper-Agent-Windows-x64-0.3.2-setup.exe
b9ad7a18a578f6b0b7c69bdc15b6d532091e314532b70ade373936a11dfb43c8  keeper-agent-core.exe
```

## Limits

macOS 0.3.2 has not been rebuilt or executed; older manifests identify historical packages. Hosted CI has not run on these local changes. No real Keeper account, production target, separate-account isolation or full native interaction was tested. No Rust advisory audit or independent security audit was completed. The existing trust boundary remains: approved commands receive plaintext credentials, and the broker requires its own OS account for meaningful separation from agents. See [VALIDATION.md](../VALIDATION.md).
