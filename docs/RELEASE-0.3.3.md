# Development build 0.3.3

Verified locally on Windows x64, October 30, 2026. This is an unsigned development build from the current uncommitted working tree; it has not been installed, pushed or published.

## What changed

The native desktop keeps one bounded stdio helper alive for the application session instead of starting a new Python process for each request. Requests remain serialized and use the same policy, grant and broker checks. If a request is canceled, times out or loses its transport, the worker is discarded; an action is never automatically retried. The next request can start a fresh helper. The single-request CLI and web-host entry points remain supported.

## Measurement and verification

On this Windows host with a two-core, BelowNormal CPU cap, an offline synthetic workspace with 20 actions, 10 clients and 200 audit events measured:

| Path | Samples | Median |
| --- | ---: | ---: |
| Previous source helper, new process for each snapshot | 8 | 885.55 ms |
| Current source worker, warmed snapshots | 12 | 5.19 ms |
| Current frozen worker, warmed snapshots | 12 | 5.31 ms |

The frozen worker's first request took 551.85 ms; its process RSS was 39.03 MiB in one idle observation. These small, separate samples are helper-level observations on one machine—not end-to-end native UI, live Keeper, cross-platform or peak-memory measurements.

106 backend tests passed with synthetic Chromium; two Rust tests passed, including worker reuse, cancellation and crash handling. The frontend build reported zero Svelte/TypeScript errors or warnings. Frozen helper and web-host smoke tests passed, including multiple requests through the packaged worker. The ZIP passed CRC verification; the NSIS installer passed a 7-Zip integrity check. Its extracted helper matches the smoke-tested helper, and its four extracted web assets match the final frontend build. No installer or native UI interaction was run.

## Windows artifacts

Files are in the ignored `work/releases/0.3.3` folder:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `Keeper-Agent-Web-Windows-x64-0.3.3.zip` | 93,760,942 | `3e42728c7dbaeb88a7ae7d14cbcd6a7ed28534f951b6a1eb6059360bcd5c0d3a` |
| `Keeper-Agent-Windows-x64-0.3.3-setup.exe` | 70,739,886 | `2a7cded567a5000da3ffa470593b6f3ae60041c137a68f53284707cf465399d2` |

The smoke-tested and installer-embedded `keeper-agent-core.exe` SHA-256 is `d7c227d422b8faf1c140745a2f6ad610959ed8a5fe89b079fcba016bd28bbfff`. `verification.json` records the local archive hashes.

The application remains a development build. Current macOS packaging, real Keeper login, live target workflows, separate-account isolation and full native interaction were not verified. Approved commands remain trusted code that receives plaintext credentials. See [VALIDATION.md](../VALIDATION.md) and the root README for the trust boundary.
