<script lang="ts">
  import { onMount } from 'svelte';
  import App from './App.svelte';
  import Icon from './Icon.svelte';
  import { web, webSession } from './api';
  let ready = $state(!web);
  let checking = $state(web);
  let accessKey = $state('');
  let error = $state('');
  let busy = $state(false);
  onMount(() => {
    const lock = () => {
      ready = false;
      accessKey = '';
      error = 'Your session ended. Sign in again.';
    };
    window.addEventListener('keeper-agent:locked', lock);
    if (web)
      webSession()
        .then((value) => (ready = value))
        .catch(() => (error = 'Cannot reach the administrator server.'))
        .finally(() => (checking = false));
    return () => window.removeEventListener('keeper-agent:locked', lock);
  });
  async function unlock() {
    busy = true;
    error = '';
    try {
      ready = await webSession(accessKey.trim());
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      accessKey = '';
      busy = false;
    }
  }
</script>

{#if ready}<App />{:else}
  <main class="web-unlock">
    <section class="panel unlock-card">
      <span class="brand-mark"><Icon name="shield" size={30} /></span>
      <div class="eyebrow">YOUR PRIVATE WORKSPACE</div>
      <h1>Welcome to Keeper Agent</h1>
      <p class="field-hint">Sign in to manage your broker, approved actions, and agent access.</p>
      {#if checking}<p role="status">Checking your session…</p>{:else}
        <form
          onsubmit={(e) => {
            e.preventDefault();
            unlock();
          }}
        >
          <label
            >Administrator access key<input
              type="password"
              bind:value={accessKey}
              required
              autocomplete="off"
              spellcheck="false"
            /></label
          >
          {#if error}<div class="notice error" role="alert">{error}</div>{/if}
          <button class="button primary full" disabled={busy || !accessKey}
            >{busy ? 'Signing in…' : 'Open workspace'}<Icon name="arrow" size={16} /></button
          >
        </form>
        <p class="field-hint">
          Use the access key from the private file identified when your web server starts. This is
          separate from your Keeper master password.
        </p>
      {/if}
    </section>
  </main>
{/if}
