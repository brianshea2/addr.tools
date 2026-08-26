(() => {
  const root = document.documentElement;
  const themeButton = document.querySelector('[data-theme-toggle]');
  const storedTheme = localStorage.getItem('addr-theme');
  const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const setTheme = (theme) => {
    root.dataset.theme = theme;
    if (themeButton) themeButton.textContent = theme === 'dark' ? '☀' : '☾';
    if (themeButton) themeButton.setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
  };
  setTheme(storedTheme || (systemDark ? 'dark' : 'light'));
  themeButton?.addEventListener('click', () => {
    const theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('addr-theme', theme);
    setTheme(theme);
  });

  const form = document.querySelector('[data-lookup-form]');
  const input = document.querySelector('#lookup-input');
  const message = document.querySelector('[data-lookup-message]');
  const examples = document.querySelectorAll('[data-example]');
  examples.forEach((example) => example.addEventListener('click', () => { input.value = example.dataset.example; input.focus(); }));

  form?.addEventListener('submit', (event) => {
    event.preventDefault();
    const query = input.value.trim();
    if (!query) { message.textContent = 'Enter an IP address, hostname, domain, or CIDR range to begin.'; input.focus(); return; }
    message.textContent = `Preparing a lookup for ${query}…`;
    const target = `https://info.addr.tools/${encodeURIComponent(query)}`;
    window.setTimeout(() => { window.location.href = target; }, 250);
  });
})();
