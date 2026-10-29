# Keeper Agent

A local CLI, desktop and browser administrator, and HTTPS broker for using a **Keeper Personal vault** in agent workflows. Built on Keeper Commander; no Secrets Manager subscription is required for the Commander approach. The Keeper vault stays in Keeper's cloud.

Agents invoke **named, preconfigured actions**. They cannot supply record IDs, retrieve raw secrets, change command arguments, choose URLs, or control a browser session through the broker API.

```text
Agent CLI → local HTTPS + scoped client token → private broker → Keeper Commander
                                                   ├─ HTTPS API request
                                                   ├─ trusted command + secret environment
                                                   └─ isolated browser login and workflow
```

## What is implemented

- Authenticated browser administrator with the same charcoal/gold interface: real action editing/execution, grants and client downloads, activity, workspace setup, Keeper login challenges, and browser installation. Responsive phone layout; localhost by default, explicit HTTPS for remote access. See [web setup and authentication limits](docs/WEB.md).

- Native desktop administrator for Windows and macOS: dark charcoal/gold interface, action editing, agent grants, activity, private login terminal, and browser setup. See [desktop setup and architecture](docs/DESKTOP.md). Windows validation and macOS limitations are in [VALIDATION.md](VALIDATION.md).

- API requests: fixed HTTPS destination/method/headers/body; redirects refused; select specific JSON fields to return. Status only by default.
- Commands: fixed executable, arguments, working directory, and environment; no shell interpolation; output suppressed by default. Optional bounded, redacted text output.
- Browser workflows: navigate, fill, click, wait, and extract selected visible text; exact origin allowlist; service workers and WebSockets disabled; isolated context closed after each action. No cookie exports, screenshots, downloads, CDP endpoints, or arbitrary agent JavaScript.
- Passwords, usernames, custom text fields/API keys, and TOTP codes from legacy and typed Keeper records.
- Separate per-client action grants; token hashes stored by broker; immediate revocation for subsequent requests; TLS certificate pinned by client; loopback-only listener.
- Metadata audit log for started/completed/failed permitted actions; no credentials, request payloads, or operation output in audit logs. Entries are hash-chained and the log rotates at 8 MiB; `keeper-agent audit-verify --state <dir>` reports the first edited, inserted or missing entry. The chain cannot detect removal of the newest entries, or a rewrite of the whole log by the broker account.

This is a working first version, not an independently audited password-management product. Automated tests use synthetic secrets. Your Keeper authentication and your real sites still need local setup and verification.

## The security boundary

**Run the broker under a different standard OS account from the agent.** The broker code, Python environment, policy, state directory, command executables, scripts, and working directories must not be writable by the agent account. Do not run the agent as administrator. `init` restricts its new state directory to the current account and SYSTEM on Windows, or mode 0700 on Unix. It does not create or verify OS account separation.

If the agent runs as your normal Windows user, it can potentially access your existing Keeper application/session as that user. This broker does not secure other Keeper installations or sessions. For stronger separation, run the agent in a dedicated unprivileged account or VM, with only the broker client granted to it. An administrator or an agent with unrestricted access to the broker account can bypass this architecture.

Commander authenticates as the vault owner and can synchronize the whole vault into broker memory. A policy limits the broker interface, not Commander's underlying Keeper permissions. A folder in a Personal vault is not a scoped machine credential.

An approved command runs as the broker user and receives plaintext secrets in its own environment. It is trusted code, not a sandbox. Do not approve a general shell, interpreter with agent-controlled scripts, arbitrary URLs, plugins, or commands that load code/configuration from agent-writable locations. A browser destination necessarily receives the credentials used to log in. Browser routing is an application restriction, not an OS network firewall.

Redaction replaces only exact matches of the secrets used in that action, in four forms: literal, URL-encoded, base64, and JSON-escaped. Any other transformation passes through unredacted; for example, a command that prints a secret as hex returns it readable. Redaction also misses other secrets returned by a service and cannot stop deliberate exfiltration. Only enable text/JSON extraction for trusted operations and carefully chosen fields. The strongest default is status-only output.

## Install on Windows

Use a private terminal signed into the chosen broker account. Copy this project to a location controlled by that account before using real secrets. Python 3.12 is the tested version.

```powershell
cd C:\path\to\keeper-agent
.\Setup.ps1 -InstallChromium
$ka = Join-Path $PWD '.venv\Scripts\keeper-agent.exe'
```

`Setup.ps1` creates a local virtual environment; it does not alter PATH or start a background service. It defaults to `py -3.12`; pass `-Python 'C:\path\to\python.exe'` to select another interpreter. `-InstallChromium` installs Playwright's browser; the sample policy uses it. Installed Microsoft Edge (`"channel": "msedge"`) or Chrome (`"channel": "chrome"`) are optional alternatives. Edge timed out in this environment during testing.

For reproducible dependency versions from the verified Windows/Python 3.12 environment, use the supplied constraints file with pip (when present):

```powershell
.venv\Scripts\python.exe -m pip install -c constraints-windows-py312.txt '.[keeper,browser]'
```

On another platform: `python3 -m venv .venv`, activate it, then `python -m pip install '.[keeper,browser]'` and `python -m playwright install chromium`.

## Connect your vault

Choose a **new** private state directory outside source control. Run these yourself in the broker account's terminal:

```powershell
& $ka init --state C:\KeeperBrokerState --email your-email@example.com
```

`init` creates an empty policy and a self-signed local TLS certificate. For non-US vaults, change `server` in `keeper.json` to your official Keeper region hostname. There is no plaintext master password field to fill in.

1. Copy the actions you need from `examples/policy.windows.json` into the state's `policy.json`.
2. Replace record UID placeholders with UIDs from your Keeper vault. UIDs identify records; they are not passwords. Use `password`, `login`, `oneTimeCode`, or `custom:Your field label` as the field selector. Ambiguous/missing fields fail closed.
3. Customize fixed repository names, executable paths, URLs, browser selectors, and expected result fields. The sample `app.example.com` login is a template, not a working website integration. Its final `wait` is the success assertion; a click alone does not prove a login succeeded.
4. Validate, issue a scoped client into private state, and start the broker:

```powershell
& $ka validate --policy C:\KeeperBrokerState\policy.json
& $ka client-add --state C:\KeeperBrokerState --name codex `
    --allow github-me --allow website-account `
    --out C:\KeeperBrokerState\codex-client.json
& $ka serve --state C:\KeeperBrokerState
```

Complete the normal Keeper login, MFA and device approval **in that terminal**. No credentials belong in chat or command arguments. The server starts only after login and vault sync succeed. It refreshes the vault before actions that use secrets. Requests waiting together share one refresh, but only one that began after they arrived, so no action reads an older vault than one refreshed for it alone. If authentication expires, restart `serve` and authenticate again.

Login uses Commander's supported SDK/configuration flow. Device/session material may be persisted by Commander in its protected configuration or OS credential storage; this application does not promise memory-only authentication. It rejects a plaintext `password` in `keeper.json`. It does not automatically enable indefinite persistent login.

Keep the terminal open. Ctrl+C stops the broker and clears its in-process Keeper session; it does not revoke Keeper device approval or erase Commander-persisted authentication. Use Keeper's device/session controls for that. No autostart or persistent Windows service is installed.

## Give an agent access

Transfer **only** `codex-client.json` to a private location readable by the agent account, using Windows file permissions to grant that account access. It contains a capability token plus the public TLS certificate. Never transfer `keeper.json`, `server.key`, or the broker state directory. The agent needs only the client package (`Setup.ps1 -ClientOnly`).

```powershell
keeper-agent list --client C:\AgentAccess\codex-client.json
keeper-agent run github-me --client C:\AgentAccess\codex-client.json
keeper-agent run website-account --client C:\AgentAccess\codex-client.json
```

If PATH is unchanged, invoke `.venv\Scripts\keeper-agent.exe` by its full path. `AGENT-USAGE.md` contains instructions suitable for the agent's own workspace.

The agent listener is always `127.0.0.1`, with verified HTTPS; no HTTP or public network mode is provided for agents. The current version supports agents on this machine. Remote administrator access is available through the separate [web app](docs/WEB.md); it does not expose the agent listener.

## Browser MFA and forms

For an interactive challenge, set `headless` to `false`, use a suitable timeout (maximum 300 seconds), and configure a `wait` for the page element that appears after you finish MFA. The browser appears in the **broker account's desktop session**, not the agent's. It closes after the workflow, including on failure. Each action starts a new browser session.

For a TOTP secret stored in Keeper, add a secret reference with `"field": "oneTimeCode", "transform": "totp"` (or a custom field containing a base32 seed/otpauth URI), then use `{{otp}}` in a fill step. TOTP values are generated at action start; long manual steps can make them expire. Passkeys, push approvals, CAPTCHA solving, iframe-specific selectors, popup/SSO flows, and automatic site discovery are not universal features of this version; configure a suitable flow or complete the human step. Every redirect/resource origin required by a site must be explicitly permitted.

## Policy and operations

- The broker applies `policy.json` edits without a restart: it checks the file before each request and about once a second. Each action runs against the policy it was authorized with. If the file becomes invalid or missing, the broker refuses every action until it is valid again, so a broken edit cannot leave a removed action live. Client grants are reloaded on every request.
- Each client gets an explicit list of named actions. There are no wildcard grants. A token is a capability to repeat those actions; use read-only, narrowly scoped upstream credentials where possible.
- The broker accepts connections concurrently and runs up to four actions at once; further requests wait for a free slot. Keeper vault sync and secret reads go through one Commander session one at a time, and each action holds it only while fetching its secrets. A request that waits for a slot rechecks its grant and the current policy before it starts, so revoking a client also stops its queued runs. This is a local tool for a small number of agents, not a multi-tenant internet service.
- HTTP and browser output is capped at 256 KiB. Commands have a bounded runtime and output size. Tracked command descendants are terminated on completion/timeout, but process cleanup is not a containment boundary for malicious executables.
- HTTP timeouts bound network operations; the response loop also checks elapsed time. They are not a hard process-level wall-clock deadline.
- `http.outputs` maps friendly names to dot-separated JSON paths, including numeric array indices. Missing fields fail the action. HTTP 4xx/5xx statuses are returned as statuses; consumers must inspect them. Commands return `exit_code`; consumers must inspect it. Browser completion means configured steps finished.
- `doctor --state ...` validates policy and reports setup requirements; it does not certify account isolation or authenticate to Keeper.
- Audit logging must succeed before an allowed action starts. A failed request after execution (for example a disk failure during audit completion) may have already caused side effects. Requests are not automatically retried and are not idempotent.
- Certificate lifetime is one year. To replace it, stop the broker, create a new state directory with `init`, transfer the policy/appropriate Keeper configuration privately, and issue new clients. Old client files must not be reused with a new certificate.

Revoke a client without restarting (an already-running action may finish):

```powershell
& $ka client-revoke --state C:\KeeperBrokerState --name codex
```

## Tests

```powershell
.venv\Scripts\python.exe -m pip install '.[keeper,browser,test]'
.venv\Scripts\python.exe -m pytest -q
$env:KEEPER_AGENT_BROWSER_TEST = '1'
.venv\Scripts\python.exe -m pytest tests/test_browser.py -q
```

The browser test uses real Playwright Chromium with synthetic HTTPS pages fulfilled in-process. It submits a fake password, verifies unauthorized origin blocking, and checks output redaction. No real credentials or Keeper account are needed for tests. Set `KEEPER_AGENT_BROWSER_CHANNEL=msedge` to test Edge instead. See `VALIDATION.md` for the actual results from this build.

## Upstream references

- [Keeper Commander source and authentication](https://github.com/Keeper-Security/Commander)
- [Official Commander SDK login example](https://github.com/Keeper-Security/Commander/blob/master/examples/add_record_to_shared_folder.py)
- [Keeper's extension supporting consumer accounts with Commander](https://github.com/Keeper-Security/keeper-vscode-extension)
- [Playwright browser contexts](https://playwright.dev/python/docs/browser-contexts)
