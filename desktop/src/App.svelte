<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from './Icon.svelte';
  import WebConnection from './WebConnection.svelte';
  import {
    request,
    preview,
    chooseState,
    loginTerminal,
    browserSetupTerminal,
    template,
    web,
    logout,
    downloadClient,
  } from './api';
  import { emptySnapshot, type Snapshot, type Kind, type PolicyAction } from './types';

  type Page = 'actions' | 'agents' | 'activity' | 'vault' | 'settings';
  type Modal = 'action' | 'agent' | 'run' | 'revoke' | 'delete' | 'folder' | null;
  let page = $state<Page>('actions');
  let data = $state<Snapshot>(emptySnapshot());
  let loading = $state(true);
  let busy = $state(false);
  let search = $state('');
  let filter = $state('all');
  let selected = $state('');
  let modal = $state<Modal>(null);
  let dialog = $state<HTMLDialogElement>();
  let message = $state('');
  let error = $state('');
  let formError = $state('');
  let editing = $state(false);
  let actionName = $state('');
  let description = $state('');
  let kind = $state<Kind>('http');
  let record = $state('');
  let field = $state('password');
  let destination = $state('');
  let method = $state('GET');
  let executable = $state('');
  let args = $state('');
  let cwd = $state('');
  let envName = $state('API_TOKEN');
  let loginSelector = $state('input[name=email]');
  let passwordSelector = $state('input[name=password]');
  let submitSelector = $state('button[type=submit]');
  let successSelector = $state('');
  let browserHeadless = $state(web);
  let advanced = $state(false);
  let editorJson = $state('');
  let agentName = $state('');
  let grants = $state<string[]>([]);
  let target = $state('');
  let result = $state('');
  let folderPath = $state('');
  let email = $state('');
  let region = $state('US');
  let theme = $state(localStorage.getItem('keeper-agent-theme') || 'dark');
  let systemDark = $state(true);
  const kindNames: Record<Kind, string> = {
    http: 'API request',
    command: 'Command',
    browser: 'Browser',
  };
  const kindIcons: Record<Kind, string> = {
    http: 'globe',
    command: 'terminal',
    browser: 'browser',
  };
  const nav: { id: Page; label: string; icon: string }[] = [
    { id: 'actions', label: 'Actions', icon: 'grid' },
    { id: 'agents', label: 'Agent access', icon: 'agents' },
    { id: 'activity', label: 'Activity', icon: 'activity' },
  ];
  const rows = $derived(
    data.actions.filter(
      (a) =>
        (filter === 'all' || a.kind === filter) &&
        `${a.name} ${a.description} ${a.destination}`.toLowerCase().includes(search.toLowerCase()),
    ),
  );
  const current = $derived(data.actions.find((a) => a.name === selected));
  const finished = $derived(data.events.filter((e) => e.status !== 'started'));
  const matchingEvents = $derived(
    finished.filter((e) =>
      `${e.action} ${e.client} ${e.status}`.toLowerCase().includes(search.toLowerCase()),
    ),
  );
  const referenceCount = $derived(data.actions.reduce((sum, a) => sum + a.secrets, 0));
  const pageTitle: Record<Page, string> = {
    actions: 'Approved actions',
    agents: 'Agent access',
    activity: 'Activity',
    vault: 'Your vault',
    settings: 'Settings',
  };
  $effect(() => {
    document.documentElement.dataset.theme =
      theme === 'system' ? (systemDark ? 'dark' : 'light') : theme;
    localStorage.setItem('keeper-agent-theme', theme);
  });
  $effect(() => {
    if (dialog && !dialog.open) dialog.showModal();
  });

  onMount(() => {
    const media = matchMedia('(prefers-color-scheme: dark)');
    systemDark = media.matches;
    const change = () => (systemDark = media.matches);
    media.addEventListener('change', change);
    refresh();
    return () => media.removeEventListener('change', change);
  });
  async function refresh() {
    try {
      error = '';
      data = await request();
      if (!selected && data.actions.length) selected = data.actions[0].name;
    } catch (e) {
      error = String(e instanceof Error ? e.message : e);
    } finally {
      loading = false;
    }
  }
  async function snapshotRefresh() {
    try {
      data = await request('snapshot');
    } catch (e) {
      error = String(e);
    }
  }
  // Keep operations explicit: no background polling, retries, or automatic runs.
  async function perform(job: () => Promise<void>) {
    busy = true;
    formError = '';
    error = '';
    try {
      await job();
    } catch (e) {
      const text = e instanceof Error ? e.message : String(e);
      if (modal) formError = text;
      else error = text;
    } finally {
      busy = false;
    }
  }
  function go(next: Page) {
    page = next;
    search = '';
    message = '';
    if (next === 'activity') snapshotRefresh();
  }
  function openNew() {
    if (!data.initialized) {
      go('vault');
      return;
    }
    editing = false;
    browserHeadless = web;
    actionName = '';
    description = '';
    kind = 'http';
    record = '';
    field = 'password';
    destination = '';
    executable = '';
    cwd = '';
    args = '';
    advanced = false;
    formError = '';
    modal = 'action';
  }
  async function editAction() {
    if (!current) return;
    await perform(async () => {
      const definition = await request<PolicyAction>('get_action', { name: current.name });
      actionName = current.name;
      description = definition.description || '';
      kind = definition.kind;
      editorJson = JSON.stringify(definition, null, 2);
      advanced = true;
      editing = true;
      modal = 'action';
    });
  }
  function definition(): PolicyAction {
    if (advanced) return JSON.parse(editorJson);
    const base = { kind, description, timeout: kind === 'browser' ? 180 : 60 };
    if (!record.trim())
      throw new Error('Enter the Keeper record UID. Secret values are not needed.');
    if (kind === 'http')
      return {
        ...base,
        url: destination,
        method,
        headers: { Authorization: 'Bearer {{token}}' },
        secrets: { token: { record: record.trim(), field } },
        outputs: {},
      };
    if (kind === 'command')
      return {
        ...base,
        argv: [executable, ...args.split('\n').filter(Boolean)],
        cwd,
        env: { [envName]: '{{token}}' },
        secrets: { token: { record: record.trim(), field } },
        output: 'none',
      };
    if (!successSelector.trim())
      throw new Error('Add a success selector so the app can confirm the login finished.');
    return {
      ...base,
      origins: [new URL(destination).origin],
      headless: browserHeadless,
      secrets: {
        username: { record: record.trim(), field: 'login' },
        password: { record: record.trim(), field: 'password' },
      },
      steps: [
        { op: 'goto', url: destination },
        { op: 'fill', selector: loginSelector, value: '{{username}}' },
        { op: 'fill', selector: passwordSelector, value: '{{password}}' },
        { op: 'click', selector: submitSelector },
        { op: 'wait', selector: successSelector },
      ],
    };
  }
  function openAdvanced() {
    try {
      editorJson = JSON.stringify(definition(), null, 2);
      advanced = true;
      formError = '';
    } catch {
      editorJson = JSON.stringify({ ...template(kind), description }, null, 2);
      advanced = true;
    }
  }
  async function saveAction() {
    await perform(async () => {
      if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$/.test(actionName))
        throw new Error('Use a name with letters, numbers, dots, underscores, or hyphens.');
      data = await request('save_action', {
        name: actionName,
        action: definition(),
        replace: editing,
      });
      selected = actionName;
      modal = null;
      message = 'Action saved. Restart a running broker to apply policy changes.';
    });
  }
  async function setup() {
    await perform(async () => {
      data = await request('initialize', { email, region });
      message = web
        ? 'Workspace created. Connect Keeper below.'
        : 'Broker folder created. Open the private terminal to connect Keeper.';
    });
  }
  async function choose() {
    if (web) {
      folderPath = data.statePath;
      formError = '';
      modal = 'folder';
      return;
    }
    await perform(async () => {
      if (await chooseState()) await snapshotRefresh();
      else if (preview) message = 'Folder selection is available in the desktop application.';
    });
  }
  async function selectFolder() {
    await perform(async () => {
      data = await request('select_state', { path: folderPath });
      selected = data.actions[0]?.name || '';
      modal = null;
      message = 'Workspace selected for this server session.';
    });
  }
  async function connect() {
    await perform(async () => {
      await loginTerminal();
      message = preview
        ? 'Preview connected. No real vault was opened.'
        : 'Private login terminal opened. Complete Keeper login there, then refresh this window.';
      if (preview) await snapshotRefresh();
    });
  }
  async function setupBrowser() {
    await perform(async () => {
      await browserSetupTerminal();
      message = preview
        ? 'Browser setup is available in the desktop app.'
        : 'Browser installer opened in a terminal. Wait for it to finish before running browser actions.';
    });
  }
  async function createAgent() {
    await perform(async () => {
      const response = await request<{ snapshot: Snapshot; path: string }>('create_client', {
        name: agentName,
        actions: grants,
      });
      data = response.snapshot;
      modal = null;
      message = `Access created. Client file: ${response.path}. Transfer only this file to the agent’s account.`;
    });
  }
  async function confirm() {
    await perform(async () => {
      data = await request(modal === 'revoke' ? 'revoke_client' : 'delete_action', {
        name: target,
      });
      modal = null;
      if (selected === target) selected = data.actions[0]?.name || '';
      message = 'Changes saved.';
    });
  }
  async function run() {
    await perform(async () => {
      const response = await request<unknown>('run', { name: target });
      result = JSON.stringify(response, null, 2);
      await snapshotRefresh();
    });
  }
  function timeAgo(time: string) {
    const seconds = Math.max(0, Math.round((Date.now() - Date.parse(time)) / 1000));
    return seconds < 60
      ? 'Just now'
      : seconds < 3600
        ? `${Math.floor(seconds / 60)}m ago`
        : seconds < 86400
          ? `${Math.floor(seconds / 3600)}h ago`
          : new Date(time).toLocaleDateString();
  }
  async function copyPath() {
    try {
      await navigator.clipboard.writeText(data.statePath);
      message = 'Broker folder path copied.';
    } catch {
      message = data.statePath;
    }
  }
</script>

<svelte:window
  onkeydown={(event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === 'k') {
      event.preventDefault();
      document.getElementById('workspace-search')?.focus();
    }
  }}
/>

<div class="app-shell">
  <aside class="sidebar">
    <a
      class="brand"
      href="#actions"
      onclick={(e) => {
        e.preventDefault();
        go('actions');
      }}
      aria-label="Keeper Agent home"
      ><span class="brand-mark"><Icon name="shield" size={25} /></span><span
        >keeper<span class="brand-sub">AGENT</span></span
      ></a
    >
    <div class="workspace-label">PERSONAL WORKSPACE</div>
    <nav aria-label="Main navigation">
      {#each nav as item}<button class:active={page === item.id} onclick={() => go(item.id)}
          ><Icon name={item.icon} size={18} /><span>{item.label}</span
          >{#if item.id === 'actions' && data.actions.length}<span class="nav-count"
              >{data.actions.length}</span
            >{/if}</button
        >{/each}
    </nav>
    <div class="sidebar-bottom">
      {#if web}<button class="button subtle full" onclick={() => perform(logout)}
          ><Icon name="lock" size={15} />Sign out</button
        >{/if}
      <div class="privacy-note">
        <span class="small-shield"><Icon name="lock" size={15} /></span>
        <div>
          <strong>Local by design</strong>
          <p>Your credentials stay<br />behind the broker.</p>
        </div>
      </div>
      <nav aria-label="Configuration">
        <button class:active={page === 'vault'} onclick={() => go('vault')}
          ><Icon name="key" size={18} /><span>Vault connection</span><span
            class:online={data.online}
            class="status-dot"
          ></span></button
        ><button class:active={page === 'settings'} onclick={() => go('settings')}
          ><Icon name="settings" size={18} /><span>Settings</span></button
        >
      </nav>
      <div class="identity">
        <div class="avatar">{(data.email || 'P').charAt(0).toUpperCase()}</div>
        <div>
          <strong>Personal vault</strong><span
            >{data.initialized ? data.email : 'Not connected yet'}</span
          >
        </div>
        <Icon name="lock" size={14} />
      </div>
    </div>
  </aside>

  <main>
    <header class="topbar">
      <div class="breadcrumbs">
        <Icon name="shield" size={15} /><span>Workspace</span><span class="slash">/</span><strong
          >{pageTitle[page]}</strong
        >
      </div>
      <div class="topbar-right">
        {#if preview}<span class="preview-badge">DESIGN PREVIEW</span>{/if}<span class="connection"
          ><span class:online={data.online} class="status-dot"></span>{data.online
            ? 'Broker connected'
            : 'Broker offline'}</span
        ><button
          class="icon-button"
          title="Refresh workspace"
          aria-label="Refresh workspace"
          disabled={busy || loading}
          onclick={snapshotRefresh}><Icon name="refresh" size={17} /></button
        >
      </div>
    </header>
    <div class="main-scroll">
      {#if error}<div class="notice error" role="alert">
          <Icon name="info" size={18} /><span>{error}</span><button
            class="icon-button"
            aria-label="Dismiss error"
            onclick={() => (error = '')}><Icon name="close" size={16} /></button
          >
        </div>{/if}
      {#if message}<div class="notice" role="status">
          <Icon name="check" size={18} /><span>{message}</span><button
            class="icon-button"
            aria-label="Dismiss notification"
            onclick={() => (message = '')}><Icon name="close" size={16} /></button
          >
        </div>{/if}
      {#if data.pendingRestart}<div class="notice warn">
          <Icon name="info" size={18} /><span
            >{web
              ? 'Policy changed. Disconnect and reconnect Keeper in Vault connection before running actions.'
              : 'Policy changed. Restart the broker in its private terminal before running actions.'}</span
          >
        </div>{/if}
      <div class="page-heading">
        <div>
          <div class="eyebrow">YOUR VAULT. YOUR RULES.</div>
          <h1>{pageTitle[page]}</h1>
          <p>
            {page === 'actions'
              ? 'Give your agents exactly what they need. Keep the keys to yourself.'
              : page === 'agents'
                ? 'A clear boundary for every agent in your workspace.'
                : page === 'activity'
                  ? 'A record of what ran, who requested it, and how it finished.'
                  : page === 'vault'
                    ? 'Connect once. Keep your credentials behind the broker.'
                    : 'A quieter workspace, configured your way.'}
          </p>
        </div>
        {#if page === 'actions'}<button
            class="button primary"
            disabled={loading || busy}
            onclick={openNew}><Icon name="plus" size={17} />New action</button
          >{:else if page === 'agents'}<button
            class="button primary"
            disabled={!data.initialized || !data.actions.length}
            onclick={() => {
              agentName = '';
              grants = [];
              formError = '';
              modal = 'agent';
            }}><Icon name="plus" size={17} />Add agent</button
          >{/if}
      </div>

      {#if loading}<div class="loading-state">
          <div class="spinner"></div>
          <p>Opening your workspace…</p>
        </div>
      {:else if page === 'actions'}
        <div class="summary-strip">
          <div>
            <span class="summary-icon gold"><Icon name="grid" size={17} /></span><strong
              >{data.actions.length}</strong
            ><span>approved actions</span>
          </div>
          <div>
            <span class="summary-icon"><Icon name="agents" size={17} /></span><strong
              >{data.clients.length}</strong
            ><span>connected agents</span>
          </div>
          <div>
            <span class="summary-icon"><Icon name="key" size={17} /></span><strong
              >{referenceCount}</strong
            ><span>secret references</span>
          </div>
          <span class="summary-tail"><Icon name="shield" size={14} />Scoped access only</span>
        </div>
        {#if !data.initialized}
          <section class="onboarding">
            <div class="onboarding-art">
              <div class="orbit one"></div>
              <div class="orbit two"></div>
              <div class="vault-symbol"><Icon name="shield" size={46} /></div>
              <span class="orbit-key"><Icon name="key" size={18} /></span>
            </div>
            <div class="eyebrow">A PRIVATE HOME FOR AGENT ACCESS</div>
            <h2>Your secrets can stay secret.</h2>
            <p>
              Connect your Keeper vault, define a few approved actions,<br class="desktop-break" /> and
              let your agents get to work.
            </p>
            <button class="button primary" onclick={() => go('vault')}
              >Set up your vault<Icon name="arrow" size={17} /></button
            ><button class="text-button" onclick={choose}>Use an existing broker folder</button>
            <div class="setup-steps">
              <span><b>01</b>Connect Keeper</span><span><b>02</b>Define actions</span><span
                ><b>03</b>Grant access</span
              >
            </div>
          </section>
        {:else}
          <div class="action-layout" class:has-selection={!!current}>
            <section class="action-list" aria-label="Approved actions">
              <div class="list-toolbar">
                <div class="tabs" aria-label="Action type">
                  <button class:chosen={filter === 'all'} onclick={() => (filter = 'all')}
                    >All actions</button
                  >{#each ['http', 'command', 'browser'] as type}<button
                      class:chosen={filter === type}
                      onclick={() => (filter = type)}
                      >{type === 'http' ? 'API' : type === 'command' ? 'CLI' : 'Browser'}</button
                    >{/each}
                </div>
                <label class="search"
                  ><Icon name="search" size={16} /><input
                    id="workspace-search"
                    aria-label="Search actions"
                    placeholder="Search actions"
                    bind:value={search}
                  /><kbd>⌘ K</kbd></label
                >
              </div>
              <div class="list-labels"><span>ACTION</span><span>ACCESS</span><span></span></div>
              {#each rows as action}<button
                  class="action-row"
                  class:selected={selected === action.name}
                  onclick={() => (selected = action.name)}
                  ><span class="action-type {action.kind}"
                    ><Icon name={kindIcons[action.kind]} size={21} /></span
                  ><span class="action-copy"
                    ><strong>{action.name}</strong><span
                      >{action.description || action.destination}</span
                    ><small>{action.destination}</small></span
                  ><span class="grant-count"
                    ><Icon name="agents" size={14} />{action.grants}<span class="grant-word">
                      {action.grants === 1 ? 'agent' : 'agents'}</span
                    ></span
                  ><Icon name="chevron" size={15} /></button
                >{:else}<div class="list-empty">
                  <Icon name={search ? 'search' : 'grid'} size={28} />
                  <h3>
                    {search || filter !== 'all'
                      ? 'No matching actions'
                      : 'Your first action starts here'}
                  </h3>
                  <p>
                    {search || filter !== 'all'
                      ? 'Try another search or action type.'
                      : 'Create a task your agents can run without seeing its credentials.'}
                  </p>
                  {#if !search && filter === 'all'}<button
                      class="button secondary"
                      onclick={openNew}>Create an action<Icon name="plus" size={16} /></button
                    >{/if}
                </div>{/each}
              <div class="list-footer">
                <span>{rows.length} {rows.length === 1 ? 'action' : 'actions'}</span><span
                  ><Icon name="lock" size={12} />No secret values in this view</span
                >
              </div>
            </section>
            {#if current}<aside class="inspector" aria-label="Action details">
                <div class="inspector-top">
                  <span class="section-label">ACTION DETAILS</span><button
                    class="icon-button"
                    aria-label="Close action details"
                    onclick={() => (selected = '')}><Icon name="close" size={16} /></button
                  >
                </div>
                <span class="action-type large {current.kind}"
                  ><Icon name={kindIcons[current.kind]} size={26} /></span
                >
                <h2>{current.name}</h2>
                <p class="inspector-description">
                  {current.description || 'A policy-controlled action in your workspace.'}
                </p>
                <span class="type-pill">{kindNames[current.kind]}</span>
                <dl>
                  <div>
                    <dt>Destination</dt>
                    <dd>{current.destination}</dd>
                  </div>
                  <div>
                    <dt>Credential access</dt>
                    <dd>{current.secrets} {current.secrets === 1 ? 'reference' : 'references'}</dd>
                  </div>
                  <div>
                    <dt>Allowed agents</dt>
                    <dd>{current.grants}</dd>
                  </div>
                  <div>
                    <dt>Time limit</dt>
                    <dd>{current.timeout} seconds</dd>
                  </div>
                </dl>
                <div class="permission-note">
                  <Icon name="shield" size={19} />
                  <p>Credentials are supplied by the broker only when this action runs.</p>
                </div>
                <button
                  class="button primary full"
                  disabled={!data.online || data.pendingRestart || busy}
                  onclick={() => {
                    target = current.name;
                    result = '';
                    formError = '';
                    modal = 'run';
                  }}><Icon name="play" size={15} />Run action</button
                >{#if !data.online}<span class="helper center"
                    >Connect your vault to run this action.</span
                  >{/if}
                <div class="inspector-controls">
                  <button class="button subtle" disabled={busy} onclick={editAction}
                    ><Icon name="edit" size={15} />Edit policy</button
                  ><button
                    class="icon-button danger"
                    aria-label="Delete action"
                    onclick={() => {
                      target = current.name;
                      formError = '';
                      modal = 'delete';
                    }}><Icon name="trash" size={16} /></button
                  >
                </div>
              </aside>{/if}
          </div>
        {/if}
        <div class="bottom-note">
          <Icon name="info" size={15} /><span
            >Agents request an action. Your broker handles the credentials.</span
          ><button onclick={() => go('agents')}>Manage access<Icon name="arrow" size={14} /></button
          >
        </div>
      {:else if page === 'agents'}
        <section class="panel">
          <div class="panel-title">
            <h2>Workspace agents <span class="count-badge">{data.clients.length}</span></h2>
            <span class="muted">Explicit permissions. Revocable access.</span>
          </div>
          {#each data.clients as client}<div class="agent-row">
              <span class="agent-avatar">{client.name.charAt(0).toUpperCase()}</span>
              <div class="agent-info">
                <strong>{client.name}</strong><span
                  >{client.actions.length} approved {client.actions.length === 1
                    ? 'action'
                    : 'actions'}</span
                >
                <div class="permission-tags">
                  {#each client.actions as a}<span>{a}</span>{/each}
                </div>
              </div>
              <span class="badge success">Access granted</span>
              {#if web}<button
                  class="button secondary"
                  disabled={busy}
                  onclick={() => perform(() => downloadClient(client.name))}>Download client</button
                >{/if}
              <button
                class="button subtle danger"
                onclick={() => {
                  target = client.name;
                  formError = '';
                  modal = 'revoke';
                }}>Revoke</button
              >
            </div>{:else}<div class="list-empty tall">
              <Icon name="agents" size={34} />
              <h3>A place for your trusted agents</h3>
              <p>Create an action first, then grant an agent permission to use it.</p>
              <button class="button secondary" onclick={() => go('actions')}
                >View actions<Icon name="arrow" size={16} /></button
              >
            </div>{/each}
        </section>
        <div class="bottom-note">
          <Icon name="lock" size={15} /><span
            >Client files contain access tokens. Transfer them privately to a separate agent
            account.</span
          >
        </div>
      {:else if page === 'activity'}
        <section class="panel">
          <div class="panel-title">
            <h2>Recent activity</h2>
            <label class="search"
              ><Icon name="search" size={16} /><input
                id="workspace-search"
                aria-label="Search activity"
                placeholder="Filter activity"
                bind:value={search}
              /></label
            >
          </div>
          <div class="activity-table">
            <div class="activity-head">
              <span>ACTION</span><span>REQUESTED BY</span><span>RESULT</span><span>WHEN</span>
            </div>
            {#each matchingEvents as event}<div class="event-row">
                <span
                  ><span class="event-icon" class:failed={event.status === 'failed'}
                    ><Icon name={event.status === 'failed' ? 'close' : 'check'} size={14} /></span
                  ><strong>{event.action}</strong></span
                ><span
                  >{event.client.startsWith('desktop-run-') ? 'Administrator' : event.client}</span
                ><span
                  ><span
                    class="badge"
                    class:success={event.status === 'completed'}
                    class:failure={event.status === 'failed'}
                    >{event.status === 'completed' ? 'Completed' : 'Failed'}</span
                  ></span
                ><time title={new Date(event.time).toLocaleString()}>{timeAgo(event.time)}</time>
              </div>{:else}<div class="list-empty tall">
                <Icon name="activity" size={32} />
                <h3>{search ? 'No matching activity' : 'A clear trail, without the secrets'}</h3>
                <p>
                  {search
                    ? 'Try a different action or agent name.'
                    : 'Completed and failed actions will appear here.'}
                </p>
              </div>{/each}
          </div>
          <div class="list-footer">
            <span>Latest 200 audit entries</span><span>Metadata only · no credentials</span>
          </div>
        </section>
      {:else if page === 'vault'}
        <div class="vault-layout">
          <section class="panel vault-card">
            <div class="vault-card-header">
              <span class="brand-mark"><Icon name="shield" size={29} /></span>
              <div>
                <h2>Keeper Personal</h2>
                <p>Your existing vault, connected locally.</p>
              </div>
              <span class="badge" class:success={data.online}
                >{data.online
                  ? 'Connected'
                  : data.initialized
                    ? 'Ready to connect'
                    : 'Not configured'}</span
              >
            </div>
            {#if !data.initialized}<form
                onsubmit={(e) => {
                  e.preventDefault();
                  setup();
                }}
              >
                <label
                  >Keeper email<input
                    type="email"
                    required
                    placeholder="you@example.com"
                    autocomplete="email"
                    bind:value={email}
                  /></label
                ><label
                  >Vault region<select bind:value={region}
                    >{#each ['US', 'EU', 'AU', 'CA', 'JP', 'US GOV'] as r}<option>{r}</option
                      >{/each}</select
                  ></label
                >
                <p class="field-hint">
                  {web
                    ? 'This creates a private folder on the broker host. Keeper login and MFA will appear here next.'
                    : 'This creates a private broker folder. You’ll enter your master password and MFA in a separate terminal.'}
                </p>
                <button class="button primary full" disabled={busy || !email}
                  >{busy ? 'Setting up…' : 'Create workspace'}<Icon
                    name="arrow"
                    size={16}
                  /></button
                ><button type="button" class="text-button full" onclick={choose}
                  >Choose an existing broker folder</button
                >
              </form>
            {:else}<dl class="vault-facts">
                <div>
                  <dt>Account</dt>
                  <dd>{data.email}</dd>
                </div>
                <div>
                  <dt>Region</dt>
                  <dd>{data.region}</dd>
                </div>
                <div>
                  <dt>Local endpoint</dt>
                  <dd><code>https://127.0.0.1:{data.port}</code></dd>
                </div>
                <div>
                  <dt>Connection</dt>
                  <dd>
                    {data.online ? 'Verified local TLS connection' : 'Waiting for private login'}
                  </dd>
                </div>
              </dl>
              <!-- Keeper browser login uses typed challenges, not a remote terminal. -->
              {#if web}<WebConnection online={data.online} onchanged={snapshotRefresh} />{:else}
                <button class="button primary full" disabled={busy || data.online} onclick={connect}
                  ><Icon name="terminal" size={17} />{data.online
                    ? 'Broker connected'
                    : 'Open private login terminal'}</button
                >
                <p class="field-hint">
                  Complete login in the terminal, then refresh this window. Close that terminal with
                  Ctrl+C to disconnect.
                </p>
                <button class="text-button" onclick={snapshotRefresh}
                  ><Icon name="refresh" size={14} />Refresh connection</button
                >{/if}{/if}
          </section>
          <aside class="vault-guidance">
            <span class="eyebrow">HOW ACCESS WORKS</span>
            <div class="guidance-step">
              <b>1</b>
              <div>
                <h3>You connect Keeper</h3>
                <p>
                  {web
                    ? 'Authenticate through this private web session. Keeper credentials stay on your broker and with Keeper.'
                    : 'Your login stays in the broker account’s private terminal.'}
                </p>
              </div>
            </div>
            <div class="guidance-step">
              <b>2</b>
              <div>
                <h3>You define the boundaries</h3>
                <p>Each action specifies a destination, credentials, and permitted task.</p>
              </div>
            </div>
            <div class="guidance-step">
              <b>3</b>
              <div>
                <h3>Agents request the work</h3>
                <p>The broker runs the action and returns its configured result.</p>
              </div>
            </div>
            <div class="security-callout">
              <Icon name="shield" size={19} />
              <p>
                Use a separate OS account for agents. Anyone with access to the broker account can
                access its files and permissions.
              </p>
            </div>
          </aside>
        </div>
      {:else}
        <section class="panel settings-panel">
          <div class="settings-row">
            <div>
              <h3>Appearance</h3>
              <p>Choose how Keeper Agent looks on this device.</p>
            </div>
            <select aria-label="Appearance" bind:value={theme}
              ><option value="dark">Dark charcoal</option><option value="light">Light</option
              ><option value="system">System</option></select
            >
          </div>
          <div class="settings-row">
            <div>
              <h3>Broker folder</h3>
              <p class="path">{data.statePath || 'Default private application folder'}</p>
            </div>
            <div class="button-group">
              <button class="icon-button" aria-label="Copy broker folder path" onclick={copyPath}
                ><Icon name="copy" size={16} /></button
              ><button class="button secondary" onclick={choose}
                ><Icon name="folder" size={16} />Change folder</button
              >
            </div>
          </div>
          <div class="settings-row">
            <div>
              <h3>Workflow browser</h3>
              <p>
                Install Chromium once before running browser actions.<br />The download stays in
                this OS account’s browser cache.
              </p>
            </div>
            {#if web}<WebConnection install />{:else}<button
                class="button secondary"
                disabled={busy}
                onclick={setupBrowser}><Icon name="browser" size={16} />Install browser</button
              >{/if}
          </div>
          <div class="settings-row">
            <div>
              <h3>Credential boundary</h3>
              <p>
                Run this administrator app under the broker account.<br />Grant agents only their
                scoped client files.
              </p>
            </div>
            <span class="badge">Administrator interface</span>
          </div>
          <div class="settings-row">
            <div>
              <h3>Keeper Agent</h3>
              <p>{web ? 'Web administrator' : 'Desktop'} 0.3.0 · Windows & macOS</p>
            </div>
            <span class="muted">Local. Deliberate. Yours.</span>
          </div>
        </section>
      {/if}
      <footer class="page-footer">
        <span><span class="footer-dot"></span>KEEPER AGENT</span><span
          >{preview
            ? 'Preview data is local to this page. No vault is connected.'
            : 'Local administration · no background polling'}</span
        >
      </footer>
    </div>
  </main>
</div>

{#if modal}<dialog
    bind:this={dialog}
    onclose={() => {
      if (!busy) modal = null;
    }}
    oncancel={(e) => {
      if (busy) e.preventDefault();
    }}
    class:wide={modal === 'action'}
  >
    <div class="dialog-header">
      <div>
        <span class="eyebrow">WORKSPACE CONTROL</span>
        <h2>
          {modal === 'action'
            ? editing
              ? 'Edit action policy'
              : 'Create an action'
            : modal === 'agent'
              ? 'Add an agent'
              : modal === 'run'
                ? `Run ${target}`
                : modal === 'revoke'
                  ? 'Revoke agent access?'
                  : modal === 'folder'
                    ? 'Choose a broker folder'
                    : 'Delete this action?'}
        </h2>
      </div>
      <button
        class="icon-button"
        aria-label="Close dialog"
        disabled={busy}
        onclick={() => (modal = null)}><Icon name="close" size={20} /></button
      >
    </div>
    <div class="dialog-body">
      {#if formError}<div class="notice error" role="alert">
          <Icon name="info" size={16} /><span>{formError}</span>
        </div>{/if}
      {#if modal === 'action'}<div class="form-grid">
          <label
            >Action name<input
              placeholder="github-profile"
              bind:value={actionName}
              disabled={editing}
            /></label
          ><label
            >Action type<select bind:value={kind} disabled={advanced}
              ><option value="http">API request</option><option value="command">Command</option
              ><option value="browser">Browser login</option></select
            ></label
          >
        </div>
        {#if advanced}<div class="editor-label">
            <span>Policy definition</span><span>Keeper references only · no literal secrets</span>
          </div>
          <textarea
            class="code-editor"
            aria-label="Policy JSON"
            spellcheck="false"
            bind:value={editorJson}
          ></textarea>
          <p class="field-hint">
            Policies are validated by the same broker as the CLI. Credential references use a record
            UID and field name.
          </p>
        {:else}<label
            >Description<input
              placeholder="What should this action do?"
              bind:value={description}
            /></label
          >
          {#if kind === 'http'}<div class="form-grid url-grid">
              <label
                >Method<select bind:value={method}
                  >{#each ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'] as m}<option>{m}</option
                    >{/each}</select
                ></label
              ><label
                >HTTPS endpoint<input
                  type="url"
                  placeholder="https://api.github.com/user"
                  bind:value={destination}
                /></label
              >
            </div>
            <div class="form-grid">
              <label
                >Keeper record UID<input
                  placeholder="Paste the record UID"
                  bind:value={record}
                /></label
              ><label
                >Token field<input
                  placeholder="password or custom:api_key"
                  bind:value={field}
                /></label
              >
            </div>
            <div class="inline-info">
              <Icon name="key" size={16} /><span
                >Uses Bearer authentication. Returns the response status only.</span
              >
            </div>
          {:else if kind === 'command'}<label
              >Executable<input
                placeholder="Absolute path to the trusted executable"
                bind:value={executable}
              /></label
            >
            <div class="form-grid">
              <label
                >Arguments <span class="muted">one per line</span><textarea
                  rows="3"
                  placeholder="repo&#10;view&#10;owner/project"
                  bind:value={args}
                ></textarea></label
              ><label
                >Working directory<input
                  placeholder="Absolute path to a trusted folder"
                  bind:value={cwd}
                /></label
              >
            </div>
            <div class="form-grid">
              <label
                >Keeper record UID<input
                  placeholder="Paste the record UID"
                  bind:value={record}
                /></label
              ><label
                >Environment variable<input placeholder="API_TOKEN" bind:value={envName} /></label
              >
            </div>
            <div class="inline-info">
              <Icon name="shield" size={16} /><span
                >Approved executables are trusted code. Output is suppressed by default.</span
              >
            </div>
          {:else}<label
              >Login URL<input
                type="url"
                placeholder="https://app.example.com/login"
                bind:value={destination}
              /></label
            ><label
              >Keeper login record UID<input
                placeholder="A record containing login and password fields"
                bind:value={record}
              /></label
            >
            <div class="form-grid">
              <label>Username selector<input bind:value={loginSelector} /></label><label
                >Password selector<input bind:value={passwordSelector} /></label
              ><label>Submit selector<input bind:value={submitSelector} /></label><label
                >Success selector<input
                  placeholder="Element visible after login"
                  bind:value={successSelector}
                /></label
              >
            </div>
            <div class="inline-info">
              <Icon name="browser" size={16} /><span
                >Install the workflow browser in Settings first. A visible workflow browser runs on
                the broker host; use headless mode for unattended tasks.</span
              >
            </div>{/if}
          {#if kind === 'browser'}<label class="checkbox-line"
              ><input type="checkbox" bind:checked={browserHeadless} />Run without a visible browser
              window</label
            >{/if}
          <button class="text-button advanced-link" onclick={openAdvanced}
            ><Icon name="settings" size={15} />Advanced policy editor<Icon
              name="chevron"
              size={13}
            /></button
          >
        {/if}
      {:else if modal === 'folder'}<label
          >Broker-host folder<input
            bind:value={folderPath}
            placeholder="Absolute path on the server"
          /></label
        >
        <p class="field-hint">
          Select an existing folder containing keeper.json on the machine hosting this web app.
          Disconnect the current broker first. This selection lasts until the server restarts.
        </p>
      {:else if modal === 'agent'}<label
          >Agent name<input placeholder="codex" bind:value={agentName} /></label
        >
        <div class="editor-label">
          <span>Permitted actions</span><span>{grants.length} selected</span>
        </div>
        <div class="grant-picker">
          {#each data.actions as action}<label class="grant-option"
              ><input type="checkbox" bind:group={grants} value={action.name} /><span
                class="action-type small {action.kind}"
                ><Icon name={kindIcons[action.kind]} size={16} /></span
              ><span><strong>{action.name}</strong><small>{action.destination}</small></span></label
            >{/each}
        </div>
        <p class="field-hint">
          A client file will be created in your private broker folder. Transfer only that file to
          the agent account. Its token is never displayed here.
        </p>
      {:else if modal === 'run'}{#if result}<div class="result-label">
            <Icon name="check" size={16} />Broker response
          </div>
          <pre class="result-output">{result}</pre>
          <p class="field-hint">
            Check the HTTP status or command exit code in the result. Results are not saved by the
            desktop app.
          </p>{:else}<p class="confirm-copy">
            This will run <strong>{target}</strong> against its configured destination using Keeper credentials.
            Any configured side effects will take place.
          </p>
          <div class="inline-info">
            <Icon name="shield" size={18} /><span
              >The broker supplies credentials and returns only the configured output.</span
            >
          </div>{/if}
      {:else}<p class="confirm-copy">
          {#if modal === 'revoke'}<strong>{target}</strong> will lose permission to request new actions.
            An action already running may finish.{:else}<strong>{target}</strong> will be removed from
            the policy. Agent grants must be revoked first.{/if}
        </p>{/if}
    </div>
    <div class="dialog-footer">
      <button class="button secondary" disabled={busy} onclick={() => (modal = null)}
        >{modal === 'run' && result ? 'Close' : 'Cancel'}</button
      >{#if modal === 'action'}<button
          class="button primary"
          disabled={busy || !actionName}
          onclick={saveAction}
          >{busy ? 'Saving…' : 'Save action'}<Icon name="check" size={16} /></button
        >{:else if modal === 'folder'}<button
          class="button primary"
          disabled={busy || !folderPath}
          onclick={selectFolder}>Use folder</button
        >{:else if modal === 'agent'}<button
          class="button primary"
          disabled={busy || !agentName || !grants.length}
          onclick={createAgent}
          >{busy ? 'Creating…' : 'Create agent access'}<Icon name="arrow" size={16} /></button
        >{:else if modal === 'run' && !result}<button
          class="button primary"
          disabled={busy}
          onclick={run}
          >{#if busy}<span class="spinner small"></span>{:else}<Icon
              name="play"
              size={15}
            />{/if}{busy ? 'Running…' : 'Run now'}</button
        >{:else if modal === 'revoke' || modal === 'delete'}<button
          class="button destructive"
          disabled={busy}
          onclick={confirm}
          >{busy ? 'Updating…' : modal === 'revoke' ? 'Revoke access' : 'Delete action'}</button
        >{/if}
    </div>
  </dialog>{/if}
