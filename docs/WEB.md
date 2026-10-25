# Browser administrator

Keeper Agent 0.3 adds a real, authenticated browser application using the same charcoal-and-gold interface and broker as the desktop app. It supports desktop and phone browser layouts. Production web mode never substitutes demo data when a connection fails.

## Start on your computer

Extract the standalone web-host archive, keeping its `keeper-agent-core` folder intact. On Windows:

```powershell
./keeper-agent-core/keeper-agent-core.exe web `
  --state "$env:LOCALAPPDATA/dev.nuroctane.keeper-agent/broker" `
  --web-state "$env:LOCALAPPDATA/dev.nuroctane.keeper-agent/web-admin"
```

On macOS, use `./keeper-agent-core/keeper-agent-core` and private state folders such as `"$HOME/Library/Application Support/dev.nuroctane.keeper-agent/broker"` and its sibling `web-admin`. The bundled helper also lives inside a complete desktop installation's `core` resources. macOS development builds are not notarized.

Open **http://127.0.0.1:19464**. The server prints the location of `admin-access.key`, a file readable by the broker account. Open that file privately and paste its contents into **Administrator access key**. This is a separate random administrator credential, not your Keeper password. It authorizes full control of this broker, including trusted executable policies and client downloads; never give it to an agent.

The server creates the web-administration folder at startup. The broker folder is created only when you choose **Create workspace**. Existing broker state is supported. The two folders must be separate and not nested. Launch the server as a standard private broker account, with your agents under a different unprivileged OS account.

### From the source checkout

Install the Python dependencies from the root README, then:

```powershell
cd desktop
npm ci
npm run build
cd ..
.venv/Scripts/python.exe -m keeper_agent.cli web `
  --state "$env:LOCALAPPDATA/dev.nuroctane.keeper-agent/broker" `
  --web-state "$env:LOCALAPPDATA/dev.nuroctane.keeper-agent/web-admin"
```

On macOS/Linux, use `.venv/bin/python` and private paths appropriate to your account. `--assets /absolute/path/to/dist` selects a separately built frontend. Serving `dist` with an arbitrary static-file server does not provide the authenticated API. Vite's developer preview is still a labelled, in-memory preview.

## Use the web app

- **Vault connection:** create a workspace or select an existing broker-host path. Connect Keeper, enter your master password, complete device approval and MFA, or disconnect. Credentials are submitted only through this authenticated session to the broker; the isolated login process passes them to Keeper and never sends them back as UI output.
- **Actions:** search/filter actions; create API requests, fixed commands, and browser workflows; edit the full policy; confirm and run actions; inspect bounded results; delete ungranted actions. Changes persist on disk, and a connected broker applies them within a few seconds without reconnecting.
- **Agent access:** create scoped grants, download the generated client file explicitly, and revoke access. Downloads contain a capability token and pinned certificate; transfer them privately to the intended agent account. The agent API remains loopback-only. A remote web administrator does not turn it into a public agent endpoint.
- **Activity:** view and filter recent action metadata. Secret values and action output are not written to the audit log.
- **Settings:** light/dark/system appearance, broker-host folder selection, and background Chromium installation with status. Folder selection lasts for this server process; use the desired `--state` on later launches.
- **Sign out:** revoke this administrator session. A connected broker keeps serving agent requests. **Disconnect Keeper** ends a broker started by the web app; a broker started independently in a terminal must be stopped there. Ctrl+C in the web-server terminal stops the server and the child processes it owns.

The browser uses Keeper's password, email/device-approval, authenticator/backup-code, SMS, and supported push flows. Live account flows still need verification with your own account. Hardware-key-only authentication, biometric prompts, account recovery/password changes, and enterprise SSO are not implemented by the web login adapter. These must be completed with a private terminal/official Keeper client; the web app can administer a broker connected separately. Keeper's WebAuthn relying-party identity cannot be impersonated by a self-hosted origin.

Browser workflow tasks execute on the **broker host**, not inside the administrator tab. Web-created workflows default to headless mode. Visible workflows and human interaction with a site's MFA require access to that host's desktop; the web app does not expose remote browser cookies or interactive sessions. Configure TOTP and unattended steps through policy where appropriate.

## Access from another device

Loopback HTTP is the default. Binding another interface requires HTTPS and an explicit, exact origin:

```text
keeper-agent-core web --state /private/broker --web-state /private/web-admin \
  --host 0.0.0.0 --port 19464 --origin https://keeper.example.com:19464 \
  --cert /private/tls/fullchain.pem --key /private/tls/key.pem
```

Use a certificate your browser already trusts and a hostname you control. Remote HTTP is refused. The application does not configure DNS, issue certificates, open firewall ports, trust forwarding headers, or change your network. A reverse proxy must preserve the configured Host/Origin and use the server's HTTPS connection; placing unrelated apps on the same origin is inappropriate for this administrator interface.

## Session and request protection

Administrator sessions are random, stored in server memory, and carried in HttpOnly, host-only, SameSite=Strict cookies. HTTPS adds Secure. Sessions expire after 30 minutes of inactivity or eight hours total and disappear on restart/sign-out. Tokens are not placed in URLs or localStorage. The only localStorage setting is appearance. The separate request proof is kept in the tab's sessionStorage and is required even to resume a session after reload. A newly opened tab needs sign-in. This matters on localhost: cookies span ports, while sessionStorage is isolated to the exact origin; a cookie received by another localhost service alone cannot authorize administrator requests or retrieve the proof.

Each API mutation requires an authenticated session, a per-session CSRF header, the exact configured Origin and Host, and a same-origin Fetch Metadata context when provided. Cross-origin preflights are refused. Responses disable caching, framing, cross-origin reading, and referrer disclosure. Request sizes, socket timeouts, simultaneous connections, login attempts, and live sessions are bounded.

Keeper login runs in a separate subprocess. Only fixed typed challenges/status messages cross back to the UI; SDK stdout, stderr, and diagnostics are suppressed. Each answer is bound to a fresh challenge and the administrator session that started it. Pending login/browser installation times out after ten minutes. An interrupted action can finish or be stopped with its broker; revocation prevents subsequent requests.

To rotate a compromised administrator access key, stop the web server, remove its `admin-access.key` privately, and restart. The server creates a fresh random key and all old in-memory sessions are gone. Do not put state, TLS private keys, downloads, or access keys in the repository. Keep the authentication files and approved executables inaccessible to agent accounts.

This is an administrator surface, not a sandbox or a replacement for Keeper's encrypted cloud vault. The full root README threat model still applies. No live credentials were used in development tests, and the application has not had an independent security audit.

Security references: [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [CSRF protection](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), and [Keeper Commander authentication API](https://github.com/Keeper-Security/Commander/blob/master/keepercommander/api.py).
