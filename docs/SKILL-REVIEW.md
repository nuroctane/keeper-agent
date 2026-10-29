# Skill and product review

October 29, 2026. This review continues Claude's work at `0947732` and the local 0.3.1 improvements. The product requirement is simple: an owner approves an action once, tests it, then gives an agent limited access without sharing the credential.

## Coverage and provenance

The inventory covered 6,579 `SKILL.md` files: 2,548 under `.nur/skills`, 2,535 under `.agents/skills`, 994 under `.codex/skills`, 468 under `.nur/plugins`, and 34 under `.codex/plugins`. These contain 2,463 distinct byte-level bodies. Fifty-three paths were archival or evaluation material. A name-based comparison preferred `.nur`, then `.agents`, then `.codex`, then plugin copies, producing 1,761 named entries; 646 have differing mirrors.

All files were read programmatically for inventory and comparison, and canonical bodies were screened for applicability. This is not a claim that a human or model deeply read 2.3 million words. The initial screen identified 44 direct candidates, 484 adjacent skills and 1,233 skills for other stacks or domains. Those are heuristic routing groups, not quality grades or proof that every candidate applies. Relevant guidance and its supporting references received the close review described below.

The owner's preference for `.nur` matters. For example, its API/interface skill adds 73 lines to the Codex mirror. Its security/hardening and performance skills differ substantially from their native copies, including removed material. The review used the preferred bodies, rather than combining contradictory versions or assuming that the longest copy is newest. It did not rewrite, synchronize or delete the owner's skill libraries.

Local reproducibility files are under `work/skill-review/`: `inventory.py`, `select.py`, `inventory.json`, `canonical.json`, `applicability.json`, dependency audit results and test logs. These are ignored working files, not a public export of private skills. Project `AGENTS.md` preserves routing and technical boundaries for future sessions.

## Guidance applied to the product

| Skill or review area | Application here |
| --- | --- |
| `code-review-and-quality` | Check correctness, security, efficiency, maintainability and tests. Reproduce concrete failures before fixing them; avoid speculative framework changes. |
| `security-and-hardening` and hardening patterns | Treat tokens as capabilities, verify filesystem identity, preserve deterministic authorization, triage dependency advisories and update packages separately. |
| `securing-agentic-ai-tool-invocation` | Keep permission enforcement in the broker. Do not add an LLM security decision or expose vault records to agents. |
| `api-and-interface-design` | Preserve additive status/error contracts; distinguish a queued action that never started from an action with an uncertain result. No pretend exactly-once semantics. |
| `ui-craft`, `fixing-accessibility`, `harden`, `distill`, `clarify` | Keep the existing visual identity and short setup flow. Use named native dialogs, keyboard focus and useful recovery text; avoid additional settings pages. |
| Writing guidance and `ce-noslop` | Keep setup, agent instructions and validation direct, with claims tied to actual evidence. |
| `performance-optimization` | Preserve measured behavior and bounded work. Do not claim memory or cross-platform speed improvements from asset size or one subprocess timing. |
| `observability-and-instrumentation` | Keep recent activity useful across rotated files, bounded in size and limited to metadata. No added external telemetry service. |
| `systematic-debugging` | Investigate a transient TLS test failure through isolated and full reruns; do not weaken assertions or invent a production diagnosis. |
| `codebase-design` | Preserve existing execution seams and JSON compatibility. Extract modules when that reduces a real maintenance burden, without a broad rewrite. |
| `mcp-builder` | Review the future adapter boundary: local status/list/run through the existing broker. No new vault authority or protocol implementation in this batch. |

Native-only skills and plugin copies were included in discovery. Review orchestration, deployment and artifact skills were screened for fit; discovering one did not invoke its entire workflow. Solidity reviews, security exploitation labs, visual presets, game/3D work and cloud-specific runtimes were excluded where their assumptions do not fit this application. In particular, the `agentic` skill is a visual preset, not a requirement to redesign an agent product.

Two independent review agents were attempted under the review skill's review pattern, but both stopped on model/account usage limits without delivering a review. Their work is not counted as verification. The completed review and changes below are the primary agent's work, not an independent security audit.

## Concrete findings fixed in 0.3.2

| Finding | Behavior after the change | Evidence |
| --- | --- | --- |
| Revoking a grant could delete a conventional client file containing another grant's token. | Persist revocation, then delete only a non-symlink file whose token matches the revoked hash. Remove the desktop's second unconditional deletion. | Filesystem ownership regression failed before the fix and passes after it. |
| A request could wait indefinitely behind the four execution slots and run later after its caller had given up. | Wait at most ten seconds for a slot. Return HTTP 503 with `queue_timeout` if capacity is unavailable; no action starts. Continue rechecking authorization after acquiring capacity. | Queue regression failed before the fix; real TLS test verifies the 503 contract and execution remains usable afterward. |
| Activity lost recent visible history whenever the current audit file rotated. | Read recent rotated files within one 256 KiB budget and 200-event cap, returning only approved metadata fields. | Rotation-history regression failed before the fix and now retains the expected 25 events. |
| Workspace `~` paths were normalized differently before mutation locking and before dispatch. | Expand the path before both validation and dispatch so they lock the same workspace. | Full workspace and desktop regression suites. |
| Dialogs lacked reliable accessible names and initial/return focus. | Use the native modal, label it with its heading, focus the first field or heading, and close it through the native dialog API. | Keyboard/UI test now checks the named dialog, focused action-name field and restored trigger focus. The old dialog failed this test. |
| Known Python dependency advisories remained in the build environment. | Update certifi to 2026.10.19, Pillow to 13.0.0 and setuptools to 84.1.0, one package at a time. Set secure minimums where these enter the runtime/build. Rebuild the frozen packages. | Targeted compatibility checks between updates, `uv pip check`, then a clean audit and full backend suite. |
| Source checks depended on a manually started packaging workflow. | Add automatic PR/main checks for backend tests, frontend build/UI checks and dependency audits. Keep read-only workflow permissions. Install npm dependencies with scripts disabled and explicitly rebuild esbuild. | Local equivalent commands pass; workflow YAML parses. Hosted execution has not been performed. |

The queue deadline bounds waiting for execution capacity, not the entire action. HTTP operations and trusted commands retain their documented execution limits; no hard whole-process deadline is claimed. A run already executing may finish after revocation. JSON locking prevents concurrent edit loss but is not a multi-file crash recovery transaction.

## Dependency review

The initial Python audit reported 42 advisory records across three installed packages; this count includes repeated advisory records and is not a claim of 42 distinct reachable exploits. The updated 87-package environment passes compatibility checks, and the final Python audit reports **no known vulnerabilities** in installed third-party packages. The audit used `--skip-editable`; application code received the review and regression checks above. The result is limited to the audit database and installed Python packages.

- **certifi:** the security update removes trust in the emSign root affected by compromised intermediate CA keys. Version 2026.10.19 retains the unaffected roots. [Upstream advisory](https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2).
- **Pillow:** 13.0.0 fixes multiple image-decoding vulnerabilities. Its removed APIs are not used by the broker; a basic PNG round trip passes. This does not assert that every image vulnerability was reachable through this application. [Upstream release notes](https://pillow.readthedocs.io/en/stable/releasenotes/13.0.0.html).
- **setuptools:** 84.1.0 fixes the Windows legacy wheel installation path traversal. [Upstream advisory](https://github.com/pypa/setuptools/security/advisories/GHSA-xmj3-9gf7-h52w).
- **npm:** the lockfile audit reports three low-severity entries in one chain: `deepmerge` → Svelte inspector → Svelte Vite plugin. The upstream advisory has no patched version at review time. These are build-tool dependencies; this is not a proven exploit-reachability assessment. Keep the reviewed exception visible and recheck before the next package build, or by November 5, 2026. Do not force an unsupported Svelte/Vite downgrade just to suppress the report. [Reviewed advisory](https://github.com/advisories/GHSA-gcqx-w48m-w2h4).

No Rust advisory audit was completed. Python/npm results do not cover Rust, browser binaries, OS libraries or all possible supply-chain threats. CI now rejects known Python vulnerabilities and high-or-higher npm advisories; it does not certify dependencies as safe.

## Remaining work, in useful order

1. **Approve action changes without adding setup friction.** Currently a grant trusts the named action as the owner edits its policy. Design a clear approved-revision rule for material authority changes: target, credential, executable, browser origin and outputs. Reuse the existing test/review step and show which grants need renewed approval. Avoid asking for approval on harmless labels.
2. **Offer a small local MCP adapter.** Expose status, the granted action list and named run through existing client credentials. Preserve the same authorization, audit and unknown-outcome behavior. Do not add vault search, secret inspection, arbitrary headers or agent-supplied executable arguments.
3. **Make uncertain outcomes recoverable.** Introduce durable execution receipts before promising idempotency. Define atomic reservation, expiry, caller identity and crash behavior; provide a receipt lookup so agents can check a timed-out write. A random request ID alone does not prevent duplicate side effects.
4. **Verify the real deployment boundary.** Test a narrow real Keeper login/action privately with the owner and provision separate broker/agent OS accounts. Keep `doctor` read-only and useful for permissions/configuration; do not describe it as proof of isolation. Preserve Keeper Personal as the default rather than requiring an enterprise vault migration.
5. **Improve scheduling only when needed.** The ten-second queue bound is implemented. Per-client fairness, quotas and cancellation need a small explicit model and tests before adding settings; four concurrent actions are appropriate for a small local broker, not internet multitenancy.
6. **Add useful local diagnostics.** Record safe administrator mutation events and aggregate denial/queue counters without logging tokens, action payloads or credentials. Use the existing Activity view before introducing dashboards or remote telemetry.
7. **Complete platform evidence.** Build/test macOS 0.3.2 on a Mac or hosted runner, exercise the native bridge, and decide on signing/notarization. Add a Rust advisory check with an explicit triage policy. The owner must choose any project license; this review does not assign one.
8. **Keep maintenance changes proportionate.** Extract the large Svelte component's dialog/access workflow when another feature makes that seam useful. Preserve the established UI, protocol and Python/Svelte/Tauri stack. Revisit a database only when durable receipts or measured contention justify it.

## Validation and limits

With the updated dependencies: **100 backend tests pass**, including real Chromium with synthetic credentials (77.29 seconds); **six desktop-preview** and **three authenticated web UI tests pass** (16.6 and 13.0 seconds). Formatting and the production frontend build pass with zero Svelte/TypeScript errors or warnings. Tests cover real local TLS, persisted policy/grants, revocation, expiry, output redaction, queue rejection and dialog keyboard behavior.

One earlier full run had a transient HTTPX remote-protocol failure on an existing rejected-Origin TLS request. The isolated test and two subsequent complete backend runs passed. No speculative transport change was made; retain the observation as a follow-up if it repeats.

See [VALIDATION.md](../VALIDATION.md) for current packaging results and historical evidence. Synthetic tests do not establish real Keeper authentication, live site MFA, separate-account isolation or native OS interaction. Audit chaining cannot detect deletion of the newest entries or a complete rewrite by the broker account. Trusted approved commands receive plaintext credentials. Packages remain unsigned development builds, and local changes remain uncommitted and unpublished until shipped through the owner's workflow.
