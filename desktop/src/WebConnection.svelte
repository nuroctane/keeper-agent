<script lang="ts">
  import { onMount } from 'svelte';
  import { request } from './api';
  import Icon from './Icon.svelte';
  let {
    install = false,
    online = false,
    onchanged = () => {},
  }: { install?: boolean; online?: boolean; onchanged?: () => void } = $props();
  type Status = {
    state: string;
    error?: string;
    challenge?: {
      id: string;
      kind: string;
      options: { id: string; label: string; secret?: boolean }[];
    };
  };
  let status = $state<Status>({ state: 'idle' });
  let action = $state('');
  let value = $state('');
  let error = $state('');
  let sending = $state(false);
  let alive = true;
  let timer: ReturnType<typeof setTimeout>;
  const active = $derived(
    ['connecting', 'installing', 'challenge', 'other-session'].includes(status.state),
  );
  const chosen = $derived(status.challenge?.options.find((x) => x.id === action));
  function accept(next: Status) {
    if (!alive) return;
    const old = status.challenge?.id;
    status = next;
    if (old !== next.challenge?.id) {
      action = next.challenge?.options[0]?.id || '';
      value = '';
    }
    clearTimeout(timer);
    if (['connecting', 'installing', 'other-session'].includes(next.state))
      timer = setTimeout(poll, 1000);
    if (['connected', 'completed', 'failed', 'idle'].includes(next.state)) onchanged();
  }
  async function poll() {
    try {
      accept(await request<Status>(install ? 'browser_status' : 'connection_status'));
    } catch (e) {
      if (alive) error = String(e);
    }
  }
  async function command(operation: string, payload: Record<string, unknown> = {}) {
    sending = true;
    error = '';
    try {
      accept(await request<Status>(operation, payload));
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      value = '';
      sending = false;
    }
  }
  onMount(() => {
    poll();
    return () => {
      alive = false;
      clearTimeout(timer);
      value = '';
    };
  });
</script>

<div class="web-connection" aria-live="polite">
  {#if error || status.error}<div class="notice error" role="alert">
      {error || status.error}
    </div>{/if}
  {#if status.state === 'challenge' && status.challenge}
    <form
      onsubmit={(e) => {
        e.preventDefault();
        command('login_answer', { id: status.challenge!.id, action, value });
      }}
    >
      <h3>
        {status.challenge.kind === 'password'
          ? 'Unlock your Keeper vault'
          : status.challenge.kind === 'device'
            ? 'Approve this broker device'
            : 'Verify your identity'}
      </h3>
      <p class="field-hint">
        Credentials go only to your authenticated broker and Keeper. They are not saved by this
        interface.
      </p>
      <label
        >Verification method<select bind:value={action}
          >{#each status.challenge.options as option}<option value={option.id}
              >{option.label}</option
            >{/each}</select
        ></label
      >
      {#if chosen?.secret}<label
          >{status.challenge.kind === 'password' ? 'Master password' : 'Verification code'}<input
            type="password"
            bind:value
            required
            autocomplete={status.challenge.kind === 'password'
              ? 'current-password'
              : 'one-time-code'}
          /></label
        >{/if}
      <button class="button primary" disabled={sending || (chosen?.secret && !value)}
        >{sending ? 'Submitting…' : 'Continue'}</button
      >
      <button
        type="button"
        class="button subtle"
        disabled={sending}
        onclick={() => command('disconnect')}>Cancel login</button
      >
    </form>
  {:else if active}<p class="field-hint">
      <span class="spinner small"></span>
      {status.state === 'installing'
        ? 'Installing Chromium on the broker host…'
        : status.state === 'other-session'
          ? 'Another administrator session is completing login.'
          : 'Connecting to Keeper…'}
    </p>
    {#if !install}<button
        class="button secondary"
        disabled={sending}
        onclick={() => command('disconnect')}>Cancel login</button
      >{/if}
  {:else if install}
    {#if status.state === 'completed'}<p class="field-hint">
        Workflow browser installed on the broker host.
      </p>{/if}
    <button class="button secondary" disabled={sending} onclick={() => command('install_browser')}
      ><Icon name="browser" size={16} />Install browser</button
    >
  {:else if online || status.state === 'connected'}
    <button class="button secondary" disabled={sending} onclick={() => command('disconnect')}
      ><Icon name="lock" size={16} />Disconnect Keeper</button
    >
    <p class="field-hint">
      Disconnect before changing workspaces or reconnecting to apply policy changes.
    </p>
  {:else}<button class="button primary full" disabled={sending} onclick={() => command('connect')}
      ><Icon name="key" size={16} />Connect Keeper</button
    >{/if}
</div>
