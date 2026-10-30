# Resume Keeper Agent

Updated October 30, 2026. Codex reviewed the recent Claude transcript for this repository before continuing development, as the owner requested. Use this file for the current handoff; earlier package results remain historical.

**Current local source: 0.3.3.** A persistent native helper removes repeated process startup from desktop requests. The Windows helper, web host and installer were built and verified locally; these changes remain uncommitted and unpublished. Start with [the skill/product review](SKILL-REVIEW.md), root [AGENTS.md](../AGENTS.md), [validation](../VALIDATION.md) and [the 0.3.3 artifact manifest](RELEASE-0.3.3.md).

## Source and completed work

The Laboratory checkout is `C:\Users\david\Laboratory\keeper-agent`. At handoff, `main` and the local `origin/main` tracking ref both pointed to `0947732`, with a clean working tree.

Claude completed these changes before the handoff:

- Web admin and broker availability fixes, tighter policy validation, and corrected security claims (`c135b2d`, `03dfe19`).
- Policy hot-reload that refuses actions while the policy is invalid or missing (`151040e`).
- Up to four simultaneous actions, serialized vault access, and rechecking queued grants (`5ef75dd`).
- Shared vault refreshes for waiting requests without added staleness (`36c33c0`).
- Keeper session cleanup when the web admin exits, plus hash-chained audit logs with 8 MiB rotation and `audit-verify` (`0947732`).

Claude's transcript reports that `0947732` was pushed and backed up. It also records that Factory Droid restarted the admin but made no project code changes. The temporary transcript extracts and Droid logs were subsequently moved to the Recycle Bin.

## Current continuation

Codex added regression tests and fixes for two further gaps:

- Refuse duplicate legacy custom-field labels and typed fields containing multiple values. Commander's convenience getters otherwise select the first value.
- Keep rotated audit filenames ordered when the system clock repeats or moves backward, including after a restart. Entry timestamps still record the actual clock time; filenames preserve chain order.

Those earlier changes were committed and shipped. See [VALIDATION.md](../VALIDATION.md) for the current checks.

The owner then approved the next improvement batch, emphasizing UX simplicity. Version 0.3.1 introduced:

- A short Actions-page setup guide and a **Give agent access** shortcut after a successful test, with the tested action selected. Completion offers a client download or file path and commands to copy. Result JSON is collapsed under details.
- New grants expire after seven days by default, with one-hour, 24-hour and until-revoked choices. CLI equivalents are `--expires-in-hours` and `--no-expiry`. Existing grants are unchanged.
- Cross-process serialization of built-in workspace edits, preserving the JSON format. Temporary grants include their expiry in the initial write. Reissuing an agent name cannot authorize a queued request from its old token.
- Authenticated, metadata-only `status` and safe structured errors (`--json`) for agents. The bundled helper now routes agent CLI commands as well as administrator operations.

Source validation: 97 backend tests, six desktop-preview UI tests and three authenticated web UI tests pass. Windows frozen-helper and web-host smoke tests, ZIP and installer integrity checks, and comparisons of the installer's embedded runtime/frontend also pass. Verified Windows artifacts and checksums are in [the 0.3.1 manifest](RELEASE-0.3.1.md), with local files under `work/releases/0.3.1`. No installation or publication was performed. See [VALIDATION.md](../VALIDATION.md).

## Start again

The owner requested a deep review of the skill libraries with `.nur` preferred over mirrors. See [SKILL-REVIEW.md](SKILL-REVIEW.md) and root [AGENTS.md](../AGENTS.md) for routing, findings, fixes and the ordered roadmap. Validation with patched dependencies is now 100 backend tests plus six desktop and three web UI tests, frozen-helper/web-host smoke checks and verified Windows packaging. The Python dependency audit is clean; one unpatched low-severity npm build-tool advisory remains. See [the 0.3.2 manifest](RELEASE-0.3.2.md) for exact files and checksums.

Use [WEB.md](WEB.md) for web-host startup and authentication, or [DESKTOP.md](DESKTOP.md) for the native app. The [0.3.3 Windows builds](RELEASE-0.3.3.md) include the current local changes. Earlier manifests describe historical packages that lack the latest fixes. Their local files and checksums remain unchanged.

Claude last reported no running admin or broker and an initialized workspace without actions or agent grants at `%LOCALAPPDATA%\dev.nuroctane.keeper-agent\broker`. That is a historical observation, not a live health check. Check current listeners before starting or restarting a service.

The previous Codex-hosted launch redirected its private administration folder to:

```text
C:\Users\david\AppData\Local\Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local\dev.nuroctane.keeper-agent\web-admin
```

That folder contains `admin-access.key`. Its contents must remain private and outside source control. To reuse it, pass that directory explicitly as `--web-state` and a separate sibling `broker` directory as `--state`. Launching from a normal terminal can otherwise use a different Local AppData location. The default browser address is `http://127.0.0.1:19464/`.

## Remaining work

1. Build and verify macOS 0.3.3 packages on a Mac/CI before describing them as current. Keep historical release checksums intact. The 0.3.3 changes are still uncommitted and unpublished.
2. Follow the prioritized roadmap in [SKILL-REVIEW.md](SKILL-REVIEW.md): approved action revisions, a local MCP adapter, durable execution receipts and measured scheduling improvements. A ten-second execution-slot queue bound is already implemented; fairness and receipts are not. Preserve policy fail-closed behavior, queued revocation checks, vault-refresh freshness, bounded outputs and metadata-only auditing.
3. Verify the real Keeper login and one narrowly scoped target action with the owner. Tests use synthetic secrets; they do not establish real-account or real-site behavior. Never send master passwords, MFA codes or administrator keys into chat.
4. Provision and validate separate broker and agent OS accounts before relying on the README's isolation boundary.

The audit chain cannot detect removal of the newest entries or a complete rewrite by the broker account. Approved commands receive plaintext credentials and remain trusted code. Hardware-key-only, biometric, enterprise SSO and account recovery flows require existing Keeper tools.

Packages are unsigned development builds. Mac packaging currently targets Apple Silicon; signing/notarization, Intel packaging, and manual native UI validation remain future work. The software has not received an independent security audit.
