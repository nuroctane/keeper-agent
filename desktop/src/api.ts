import { invoke } from '@tauri-apps/api/core';
import type { Snapshot, PolicyAction, Kind } from './types';
import { emptySnapshot } from './types';
export const native = '__TAURI_INTERNALS__' in window;
export const web =
  !native &&
  document.querySelector('meta[name="keeper-agent-mode"]')?.getAttribute('content') === 'web';
export const preview = !native && !web && import.meta.env.DEV;
let csrf = '';
const proofKey = 'keeper-agent-session-proof';
export async function webSession(key?: string): Promise<boolean> {
  if (key === undefined) {
    csrf = sessionStorage.getItem(proofKey) || '';
    if (!csrf) return false;
  }
  const response = await fetch(key === undefined ? '/admin/session' : '/admin/login', {
    method: key === undefined ? 'GET' : 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: key === undefined ? { 'X-CSRF-Token': csrf } : { 'Content-Type': 'application/json' },
    body: key === undefined ? undefined : JSON.stringify({ key }),
  });
  if (key === undefined && [401, 403].includes(response.status)) {
    sessionStorage.removeItem(proofKey);
    csrf = '';
    return false;
  }
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || 'Sign-in failed');
  csrf = value.csrf;
  sessionStorage.setItem(proofKey, csrf);
  return true;
}
async function webFetch(path: string, payload: Record<string, unknown>) {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: JSON.stringify(payload),
  });
  if (response.status === 401) {
    csrf = '';
    sessionStorage.removeItem(proofKey);
    window.dispatchEvent(new Event('keeper-agent:locked'));
  }
  if (!response.ok) {
    const value = await response.json();
    throw new Error(value.error || 'Request failed');
  }
  return response;
}
export async function logout() {
  await webFetch('/admin/logout', {});
  csrf = '';
  sessionStorage.removeItem(proofKey);
  window.dispatchEvent(new Event('keeper-agent:locked'));
}
export async function downloadClient(name: string) {
  const response = await webFetch('/admin/request', { operation: 'download_client', name });
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = `${name}-client.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
let demo = emptySnapshot();
const definitions: Record<string, PolicyAction> = {};
if (preview && new URLSearchParams(location.search).get('demo') === '1') {
  demo = {
    initialized: true,
    online: true,
    email: 'alex@example.com',
    region: 'US',
    port: 19463,
    pendingRestart: false,
    statePath: 'Preview / private broker',
    actions: [
      {
        name: 'github-profile',
        kind: 'http',
        description: 'Read your GitHub identity',
        destination: 'api.github.com',
        secrets: 1,
        timeout: 60,
        grants: 2,
      },
      {
        name: 'repository-status',
        kind: 'command',
        description: 'Check the status of your workspace',
        destination: 'gh',
        secrets: 1,
        timeout: 60,
        grants: 1,
      },
      {
        name: 'cloudflare-zones',
        kind: 'http',
        description: 'List the domains in your account',
        destination: 'api.cloudflare.com',
        secrets: 1,
        timeout: 60,
        grants: 1,
      },
      {
        name: 'account-overview',
        kind: 'browser',
        description: 'Sign in and read your account status',
        destination: 'app.example.com',
        secrets: 2,
        timeout: 180,
        grants: 1,
      },
    ],
    clients: [
      { name: 'codex', actions: ['github-profile', 'repository-status', 'cloudflare-zones'] },
      { name: 'local-assistant', actions: ['github-profile', 'account-overview'] },
    ],
    events: [
      {
        id: 'preview-1',
        time: new Date().toISOString(),
        client: 'codex',
        action: 'github-profile',
        status: 'completed',
      },
      {
        id: 'preview-2',
        time: new Date(Date.now() - 180000).toISOString(),
        client: 'codex',
        action: 'repository-status',
        status: 'completed',
      },
      {
        id: 'preview-3',
        time: new Date(Date.now() - 540000).toISOString(),
        client: 'local-assistant',
        action: 'account-overview',
        status: 'failed',
      },
    ],
  };
  for (const a of demo.actions) definitions[a.name] = template(a.kind);
}
export function template(kind: Kind): PolicyAction {
  if (kind === 'http')
    return {
      kind,
      description: '',
      url: 'https://api.github.com/user',
      method: 'GET',
      headers: { Authorization: 'Bearer {{token}}', Accept: 'application/vnd.github+json' },
      secrets: { token: { record: 'RECORD_UID', field: 'password' } },
      outputs: { login: 'login' },
    };
  if (kind === 'command')
    return {
      kind,
      description: '',
      argv: ['/absolute/path/to/executable', '--version'],
      cwd: '/absolute/path/to/trusted-folder',
      env: { API_TOKEN: '{{token}}' },
      secrets: { token: { record: 'RECORD_UID', field: 'password' } },
      output: 'none',
      timeout: 60,
    };
  return {
    kind,
    description: '',
    origins: ['https://app.example.com'],
    headless: false,
    timeout: 180,
    secrets: {
      username: { record: 'RECORD_UID', field: 'login' },
      password: { record: 'RECORD_UID', field: 'password' },
    },
    steps: [
      { op: 'goto', url: 'https://app.example.com/login' },
      { op: 'fill', selector: 'input[name=email]', value: '{{username}}' },
      { op: 'fill', selector: 'input[name=password]', value: '{{password}}' },
      { op: 'click', selector: 'button[type=submit]' },
      { op: 'wait', selector: '[data-testid=account]' },
    ],
  };
}
export async function request<T = Snapshot>(
  operation: string = 'snapshot',
  payload: Record<string, unknown> = {},
): Promise<T> {
  if (native) return invoke<T>('desktop_request', { request: { operation, ...payload } });
  if (web) return (await webFetch('/admin/request', { ...payload, operation })).json();
  if (!preview) throw new Error('Start the Keeper Agent web server to use this application.');
  await new Promise((resolve) => setTimeout(resolve, 150));
  const name = String(payload.name ?? '');
  switch (operation) {
    case 'initialize':
      demo = {
        ...emptySnapshot(),
        initialized: true,
        email: String(payload.email),
        region: String(payload.region),
        statePath: 'Preview / private broker',
      };
      break;
    case 'get_action':
      return (definitions[name] ?? template('http')) as T;
    case 'save_action': {
      if (demo.actions.some((a) => a.name === name) && !payload.replace)
        throw new Error('An action with that name already exists');
      const action = payload.action as PolicyAction;
      definitions[name] = action;
      demo.actions = demo.actions.filter((a) => a.name !== name);
      demo.actions.push({
        name,
        kind: action.kind,
        description: action.description ?? '',
        destination: String(
          action.url ??
            ((action.origins as string[]) ?? [])[0] ??
            ((action.argv as string[]) ?? [])[0] ??
            '',
        ),
        secrets: Object.keys(action.secrets ?? {}).length,
        timeout: action.timeout ?? 60,
        grants: 0,
      });
      break;
    }
    case 'delete_action':
      if (demo.clients.some((c) => c.actions.includes(name)))
        throw new Error('Revoke agent access before deleting this action');
      demo.actions = demo.actions.filter((a) => a.name !== name);
      break;
    case 'create_client':
      if (demo.clients.some((c) => c.name === name)) throw new Error('Agent already exists');
      demo.clients.push({ name, actions: payload.actions as string[] });
      return { path: `Preview / ${name}-client.json`, snapshot: structuredClone(demo) } as T;
    case 'revoke_client':
      demo.clients = demo.clients.filter((c) => c.name !== name);
      break;
    case 'run':
      demo.events.unshift({
        id: crypto.randomUUID(),
        time: new Date().toISOString(),
        client: 'desktop',
        action: name,
        status: 'completed',
      });
      return {
        action: name,
        result: { preview: true, message: 'Sample action completed. No service was contacted.' },
      } as T;
  }
  demo.actions = demo.actions.map((a) => ({
    ...a,
    grants: demo.clients.filter((c) => c.actions.includes(a.name)).length,
  }));
  return structuredClone(demo) as T;
}
export async function chooseState(): Promise<boolean> {
  if (!native) return false;
  const { open } = await import('@tauri-apps/plugin-dialog');
  const selected = await open({
    directory: true,
    multiple: false,
    title: 'Choose existing broker folder',
  });
  if (!selected) return false;
  await invoke('set_state_path', { path: selected });
  return true;
}
export async function loginTerminal() {
  if (!native) {
    demo.online = true;
    return;
  }
  await invoke('login_terminal');
}
export async function browserSetupTerminal() {
  if (!native) return;
  await invoke('browser_setup_terminal');
}
