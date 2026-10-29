# Development build 0.3.1

Historical local build. Source 0.3.2 adds dependency security updates and the findings in [SKILL-REVIEW.md](SKILL-REVIEW.md); the checksums below continue to identify the unchanged 0.3.1 artifacts.

Local Windows builds prepared October 29, 2026, from the working tree based on `0947732`. These changes have not been committed or published. The [0.3.0 manifest](RELEASE-0.3.0.md) remains the record for the older Windows and macOS artifacts.

## Changes

- Connect Keeper, create and test an action, then grant it to an agent. Successful tests offer **Give agent access** with that action selected. The completion screen provides the client file and commands to copy.
- Access expires after seven days by default, with one-hour, 24-hour and until-revoked options. Existing grants without expiry retain their previous lifetime.
- Built-in workspace edits serialize across administrator processes. Revoking and reissuing an agent name cannot authorize a queued request from its old token.
- Agent `status` checks broker reachability and policy validity without accessing the vault. CLI errors support stable codes and safe next steps. Interrupted responses warn against blindly repeating actions.
- Result details are collapsed by default. The bundled helper supports agent CLI commands.
- Includes the October 25–29 broker hardening, hot-reload, concurrent execution, shared vault refreshes, clean shutdown and audit chaining/rotation, plus rejection of ambiguous Keeper fields and ordered rotation after clock rollback.

## Validation

97 backend tests, six desktop-preview UI tests and three authenticated web UI tests pass. The frontend builds with zero Svelte/TypeScript errors or warnings. The access-completion dialog was visually inspected. See [VALIDATION.md](../VALIDATION.md).

Frozen-runtime smoke tests passed for initialization, action editing, expiring grants, metadata filtering, revocation, CLI routing and structured JSON errors. Frozen web checks passed for bundled assets, authenticated sessions and sanitized login-worker failures. No Keeper account was contacted.

The standalone ZIP passed its CRC integrity test and includes `AGENT-USAGE.md`. The Windows installer passed a 7-Zip integrity test. Its extracted helper matches the smoke-tested runtime's SHA-256, and its extracted frontend matches the final UI build. Frozen builds now use a clean PyInstaller cache to avoid retaining an older module archive.

Local artifacts live in the ignored `work/releases/0.3.1` folder:

| Package | Size | Purpose |
| --- | ---: | --- |
| `Keeper-Agent-Web-Windows-x64-0.3.1.zip` | 89.38 MiB | Standalone web administrator and agent CLI helper |
| `Keeper-Agent-Windows-x64-0.3.1-setup.exe` | 67.44 MiB | Native Windows desktop installer |

## SHA-256

```text
3916c8cb9865c8c09841edee3c5acdae0fbe478ffd2fc02a5b2ffede1501454f  Keeper-Agent-Web-Windows-x64-0.3.1.zip
74b67b9db871aeecf203f18e6d52430c7a710597898d59cedc9e50f6bcc269cb  Keeper-Agent-Windows-x64-0.3.1-setup.exe
```

These are unsigned development builds. No installer was run, no real Keeper authentication was performed, and no separate-account or macOS validation was performed in this continuation.
