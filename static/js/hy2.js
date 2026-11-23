// Hy2 web UI: small shared helpers (no dependencies)
(function () {
  // ---- Theme: follows the OS unless the user picks one ----
  var root = document.documentElement;
  function storedTheme() { try { return localStorage.getItem('hy2-theme'); } catch (e) { return null; } }
  function currentTheme() {
    return root.getAttribute('data-theme') ||
      (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  }
  function syncIcon() {
    var icon = document.querySelector('#theme-toggle .bi');
    if (icon) icon.className = 'bi ' + (currentTheme() === 'dark' ? 'bi-sun' : 'bi-moon');
  }
  window.hy2ToggleTheme = function () {
    var next = currentTheme() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('hy2-theme', next); } catch (e) {}
    syncIcon();
  };
  document.addEventListener('DOMContentLoaded', syncIcon);

  // ---- Toast ----
  window.hy2Toast = function (msg) {
    var t = document.getElementById('toast');
    if (!t) return;
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(t._h);
    t._h = setTimeout(function () { t.classList.remove('show'); }, 2600);
  };

  // ---- Tabs: <div class="tabs" data-tabs> <button data-tab="x"> ... <section data-pane="x"> ----
  function activate(container, name) {
    container.querySelectorAll('[data-tab]').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-tab') === name);
      b.setAttribute('aria-selected', b.getAttribute('data-tab') === name);
    });
    document.querySelectorAll('[data-pane]').forEach(function (p) {
      p.hidden = p.getAttribute('data-pane') !== name;
    });
  }
  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-tabs]').forEach(function (c) {
      var initial = (location.hash || '').slice(1);
      var names = Array.prototype.map.call(c.querySelectorAll('[data-tab]'), function (b) { return b.getAttribute('data-tab'); });
      activate(c, names.indexOf(initial) >= 0 ? initial : names[0]);
      c.addEventListener('click', function (e) {
        var b = e.target.closest('[data-tab]');
        if (!b) return;
        activate(c, b.getAttribute('data-tab'));
        history.replaceState(null, '', '#' + b.getAttribute('data-tab'));
      });
    });
  });

  // ---- Fetch JSON helper ----
  window.hy2Get = function (url, params) {
    var q = new URLSearchParams(params || {}).toString();
    return fetch(url + (q ? '?' + q : '')).then(function (r) {
      if (!r.ok) throw new Error(r.status + ' ' + r.statusText);
      return r.json();
    });
  };
})();
