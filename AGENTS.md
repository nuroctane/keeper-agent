# Keeper Agent

Read `docs/RESUME.md` for the handoff and `docs/SKILL-REVIEW.md` for the current review. Preserve the work already in this checkout.

## Skills and scope

Prefer the owner's matching skill in `C:\Users\david\.nur\skills`; that is the primary source for current guidance. Matching names do not establish matching content. Fall back to `.agents\skills` and `.codex\skills` for native-only skills, comparing instructions if a conflict matters. Load only skills relevant to the task. Apply guidance to this Python/Svelte/Tauri application; the library also contains unrelated frameworks, visual presets and security lab exercises. Do not mirror or rewrite the owner's skill library as a side effect of product work.

UX simplicity is a product requirement. Preserve the short path: create an action, test it, give an agent scoped access. Keep detailed results and advanced choices behind disclosure. Keep agent commands to status, list and named run unless a task explicitly requires a broader interface.

## Boundaries to preserve

- Agents receive named capabilities, never vault search, record selection, raw credentials or arbitrary execution parameters.
- Check authorization in deterministic broker code. Fail closed on invalid policy; recheck grants and policy after waiting for execution capacity. Do not authorize a replacement client token with a queued request from the old token.
- Keep vault access serialized and freshness checks intact. Four concurrent actions do not imply four independent vault sessions.
- Serialize built-in workspace mutations across processes. Before deleting a credential file, verify it belongs to the revoked token; a conventional filename is insufficient.
- Keep diagnostics and audit records limited to safe metadata. An uncertain execution result must not trigger an automatic retry of an action with side effects.
- Approved commands receive plaintext credentials and are trusted code. Do not describe process cleanup or a shared OS account as a sandbox.

## Validation and packaging

Run meaningful regressions for authorization, lifecycle, filesystem and execution changes. The full backend suite is `python -m pytest -q`; set `KEEPER_AGENT_BROWSER_TEST=1` to include the real Chromium synthetic test. Use the repository's Python environment.

In `desktop`, install the lockfile with `npm ci --ignore-scripts`, then explicitly build the known binary with `npm rebuild esbuild --ignore-scripts=false`. Run `npm run format:check`, `npm run build`, `npm test` and `npm run test:web` as appropriate. Interface tests use synthetic state; native interaction and real Keeper login need separate evidence.

Finalize source and frontend assets before running `desktop/scripts/package_core.py`; its clean freeze avoids stale cached code. Smoke-test the frozen helper and web host, then build the native package against that exact runtime. Check archive integrity and compare the installer's embedded runtime and frontend with the verified files. Record platform, version and checksums without replacing historical manifests.

For ship, push, deploy, publish or landing work on main, follow `C:\Users\david\.agents\SHIP.md`: commit, push `origin main`, then create and report the required backup. A local build is not publication.
