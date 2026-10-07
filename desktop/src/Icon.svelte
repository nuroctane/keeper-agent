<script lang="ts">
  export let name = 'shield';
  export let size = 20;
  const paths: Record<string, string> = {
    shield: 'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z M9 12l2 2 4-4',
    grid: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
    key: 'M15 7a4 4 0 1 1-3.8 5.2L4 19H1v-3l7.2-7.2A4 4 0 0 1 15 7Z',
    agents:
      'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M22 21v-2a4 4 0 0 0-3-3.87 M16 3.13a4 4 0 0 1 0 7.75',
    activity: 'M3 12h4l3-8 4 16 3-8h4',
    settings:
      'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2',
    search: 'M11 3a8 8 0 1 0 0 16 8 8 0 0 0 0-16 M17 17l5 5',
    plus: 'M12 5v14 M5 12h14',
    arrow: 'M5 12h14 M14 7l5 5-5 5',
    chevron: 'm9 5 7 7-7 7',
    check: 'm5 12 4 4L19 6',
    close: 'm6 6 12 12 M6 18 18 6',
    refresh: 'M20 7a8 8 0 1 0 1 7 M20 3v5h-5',
    globe: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0 M3 12h18 M12 3c5 5 5 13 0 18-5-5-5-13 0-18',
    terminal: 'm5 7 5 5-5 5 M13 17h6',
    browser: 'M3 4h18v16H3z M3 9h18 M6 6.5h.01 M9 6.5h.01',
    play: 'm8 4 12 8-12 8V4Z',
    lock: 'M5 10h14v11H5z M8 10V6a4 4 0 0 1 8 0v4',
    folder: 'M3 5h6l2 2h10v13H3V5Z',
    copy: 'M8 8h12v13H8z M16 8V3H3v13h5',
    sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 1v3 M12 20v3 M1 12h3 M20 12h3 M4 4l2 2 M18 18l2 2 M4 20l2-2 M18 6l2-2',
    moon: 'M20 14A9 9 0 0 1 10 3a9 9 0 1 0 10 11Z',
    info: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 11v6 M12 7h.01',
    edit: 'm16 3 5 5-12 12H4v-5L16 3Z M13 6l5 5',
    trash: 'M3 6h18 M9 6V3h6v3 M5 6l1 15h12l1-15 M10 10v7 M14 10v7',
    download: 'M12 3v12 m-5-5 5 5 5-5 M4 16v5h16v-5',
  };
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="1.65"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"><path d={paths[name] || paths.shield} /></svg
>
