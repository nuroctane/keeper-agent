# Development build 0.3.0

Artifacts verified October 8, 2026. All four packages were built from source commit `c16e052` in the private [Windows/macOS CI run](https://github.com/nuroctane/keeper-agent/actions/runs/37671696574). CI artifacts may expire; verified local copies are in this chat's `outputs` folder, with build copies under the lab's ignored `work/releases/0.3.0` directory.

| Package | Size | Purpose |
| --- | ---: | --- |
| `Keeper-Agent-Web-Windows-x64-0.3.0.zip` | 89.43 MiB | Standalone browser host, bundled Python and frontend |
| `Keeper-Agent-Web-macOS-Apple-Silicon-0.3.0.zip` | 96.95 MiB | Standalone browser host for ARM64 Macs |
| `Keeper-Agent-Windows-x64-0.3.0-setup.exe` | 67.50 MiB | Native Tauri desktop installer |
| `Keeper-Agent-macOS-Apple-Silicon-0.3.0.dmg` | 98.21 MiB | Native Tauri desktop application for ARM64 Macs |

The browser app supports persistent actions and policies, confirmed execution, scoped grants, explicit client downloads, revocation, activity, workspace setup, supported Keeper login challenges, and Chromium installation. It shares the native charcoal/gold interface, with responsive layouts and optional light/system appearance. Production mode never falls back to demo data.

Follow [WEB.md](WEB.md) to start the web host and sign in with its separate administrator key. Extract the entire ZIP and keep the runtime folder intact. Localhost is the default; remote administration requires explicitly configured HTTPS. The archive includes `START-HERE.md`. Native setup is described in [DESKTOP.md](DESKTOP.md).

Each platform passed 48 backend tests, five desktop-preview UI tests, three authenticated-browser UI tests, and frozen-runtime smoke tests. All downloaded packages passed archive integrity checks. No real Keeper account or production secrets were used. Hardware-key-only/biometric/SSO/recovery login needs existing Keeper tools; site workflows execute on the broker host. These are unsigned development packages, and macOS notarization is not configured. See [validation limits](../VALIDATION.md).

## SHA-256

```text
9d6ad391754535a4f07cbafbeecea70d33f694301c34b19c1b1323643d0b4be0  Keeper-Agent-macOS-Apple-Silicon-0.3.0.dmg
15d748ba8ab9238f0fa4f79b0a0c88d6d818cbdaca21c2c2ca3daf0a778ead2b  Keeper-Agent-Web-macOS-Apple-Silicon-0.3.0.zip
63322aa7cb389724c57992ba8c232738c78b13b69e85824067fde6bc262574db  Keeper-Agent-Web-Windows-x64-0.3.0.zip
b60e752a24c78428f564f5279faf5517a1abca9d0c5abbfb7f2ed1c343a764c7  Keeper-Agent-Windows-x64-0.3.0-setup.exe
```

Old 0.2 installers were moved out of the download folder into `work/releases/0.2.0`. Development scratch, caches, and downloaded binaries remain ignored inside the lab. No web server, Keeper session, scheduled task, autostart entry, or public listener was left running by this build process.
