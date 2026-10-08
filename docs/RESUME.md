# Resume Keeper Agent

Saved October 8, 2026, after the owner requested shutdown and shipment.

## Current state

- Version 0.3 includes the CLI/broker, native Windows/macOS administrator, and authenticated browser administrator. The interface uses charcoal and gold, with optional light/system appearance.
- Tested application source: `c16e052`. The [build manifest](RELEASE-0.3.0.md) contains package names, checksums, and the successful private CI run. Each platform passed 48 backend tests, eight UI tests, and packaged-runtime checks.
- The local web process was stopped. No listener remained on ports 19463, 19464, or 19465. No autostart or scheduled service was installed.
- The browser host's administrator key was created privately. No broker workspace was initialized at shutdown, and this chat has not authenticated to a real Keeper vault.
- The Laboratory checkout is `C:\Users\david\Laboratory\keeper-agent`; its remote is private `nuroctane/keeper-agent`.

## Start again

Use [WEB.md](WEB.md) for web-host startup and authentication, or [DESKTOP.md](DESKTOP.md) for the native app. Verified downloads are in this chat's `outputs` folder; copies are retained under the lab's ignored `work/releases/0.3.0` directory.

The previous Codex-hosted launch redirected its private administration folder to:

```text
C:\Users\david\AppData\Local\Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local\dev.nuroctane.keeper-agent\web-admin
```

That folder contains `admin-access.key`. Its contents must remain private and outside source control. To reuse it, pass that directory explicitly as `--web-state` and a separate sibling `broker` directory as `--state`. Launching from a normal terminal can otherwise use a different Local AppData location. The default browser address is `http://127.0.0.1:19464/`.

The attempted automatic default-browser opening was blocked by the tool's approval policy. The server itself worked and returned HTTP 200; the URL can be opened manually after starting it.

## Remaining setup and validation

1. Choose the private broker OS account and keep agent access under a separate unprivileged account, following the README's trust boundary.
2. Initialize the workspace with the owner's Keeper email and region, then authenticate privately. Never send the master password, MFA codes, or administrator key into chat.
3. Configure a narrowly scoped action with real record references; verify the intended result before granting it to an agent.
4. Validate account-specific Keeper login and target-site behavior. Hardware-key-only, biometric, enterprise SSO, and recovery flows use existing Keeper tools. Site workflows execute on the broker host.

Packages are unsigned development builds. Mac packaging currently targets Apple Silicon; signing/notarization, Intel packaging, and manual native UI validation remain future work. The software has not received an independent security audit.
