/* AI for the Win: theme toggle, tab routing, lab filters and search.
   Behaves like the Edge DFIR and AI DFIR toolkit sites. Without JavaScript every panel stays visible. */
(function () {
  'use strict';
  var root = document.documentElement;
  function $(id) { return document.getElementById(id); }
  function all(sel, el) { return Array.prototype.slice.call((el || document).querySelectorAll(sel)); }
  function store(k, v) {
    try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (_) { return null; }
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  /* ------------------------------------------------------------ theme */
  function isDark() { return root.getAttribute('data-theme') === 'dark'; }
  function themeLabel() { var b = $('themeBtn'); if (b) b.textContent = isDark() ? '☀ Light' : '☾ Dark'; }
  themeLabel();
  if ($('themeBtn')) $('themeBtn').addEventListener('click', function () {
    var n = isDark() ? 'light' : 'dark';
    root.setAttribute('data-theme', n); store('aiftw-theme', n); themeLabel();
  });
  function hdrH() { var h = document.querySelector('.hdr'); if (h) root.style.setProperty('--hdr', h.offsetHeight + 'px'); }
  window.addEventListener('resize', hdrH); hdrH();

  /* ------------------------------------------------------------ lab filters (#labs?track=ml&api=no) */
  var NAMES = ['track', 'level', 'api', 'nb'];
  var form = $('labFilters'), rows = all('#labList .lrow');
  function checked(name) { return all('input[name=' + name + ']:checked', form).map(function (i) { return i.value; }); }
  function filterLabs() {
    if (!form) return;
    var want = {}; NAMES.forEach(function (n) { want[n] = checked(n); });
    var shown = 0;
    rows.forEach(function (r) {
      var ok = NAMES.every(function (n) { return !want[n].length || want[n].indexOf(r.dataset[n]) >= 0; });
      r.hidden = !ok; if (ok) shown++;
    });
    $('labCount').textContent = shown === rows.length ? rows.length + ' labs' : shown + ' of ' + rows.length + ' labs';
    $('labEmpty').hidden = shown > 0;
  }
  function filtersToHash() {
    var parts = [];
    NAMES.forEach(function (n) { var v = checked(n); if (v.length) parts.push(n + '=' + v.join(',')); });
    history.replaceState(null, '', '#labs' + (parts.length ? '?' + parts.join('&') : ''));
  }
  function queryToFilters(q) {
    if (!form) return;
    NAMES.forEach(function (n) {
      var v = (q.get(n) || '').split(',').filter(Boolean);
      all('input[name=' + n + ']', form).forEach(function (i) { i.checked = v.indexOf(i.value) >= 0; });
    });
    filterLabs();
  }
  if (form) {
    form.addEventListener('change', function () { filterLabs(); filtersToHash(); });
    form.addEventListener('reset', function () { setTimeout(function () { filterLabs(); filtersToHash(); }); });
  }

  /* ------------------------------------------------------------ tabs (home page only) */
  var panels = all('section.panel'), tabs = all('.tabs a[data-tab]');
  function parseHash() {
    var h = location.hash.slice(1), q = '', i = h.indexOf('?');
    if (i >= 0) { q = h.slice(i + 1); h = h.slice(0, i); }
    var p = h.split('/');
    return { tab: p[0] || 'start', sub: p[1] || '', q: new URLSearchParams(q) };
  }
  function route() {
    if (!panels.length) return;
    var r = parseHash(), tab = r.tab;
    if (!$('tab-' + tab)) tab = 'start';
    panels.forEach(function (p) { p.hidden = p.id !== 'tab-' + tab; });
    tabs.forEach(function (t) { t.setAttribute('aria-selected', String(t.dataset.tab === tab)); });
    if (tab === 'labs') queryToFilters(r.q);
    var row = tab === 'labs' && r.sub ? $('lab-' + r.sub) : null;
    if (row) {
      row.hidden = false; row.classList.add('hit');
      row.scrollIntoView({ block: 'center' });
      setTimeout(function () { row.classList.remove('hit'); }, 2400);
    } else {
      window.scrollTo(0, 0);
    }
  }
  if (panels.length) {
    window.addEventListener('hashchange', route);
    route();
  }

  /* ------------------------------------------------------------ search palette */
  var index = [];
  try { index = JSON.parse($('search-index').textContent); } catch (_) {}
  var box, input, list, items = [], sel = 0, lastFocus;

  function score(e, terms, raw) {
    if (/^\d{1,2}$/.test(raw) && e.n === +raw) return 100;
    var t = e.t.toLowerCase(), d = (e.d || '').toLowerCase(), k = e.k.toLowerCase(), s = 0;
    for (var i = 0; i < terms.length; i++) {
      var w = terms[i], hit = 0;
      if (t.indexOf(w) === 0) hit = 6; else if (t.indexOf(w) >= 0) hit = 4;
      if (k.indexOf(w) >= 0) hit = Math.max(hit, 2);
      if (d.indexOf(w) >= 0) hit = Math.max(hit, 1);
      if (!hit) return 0;
      s += hit;
    }
    return s;
  }
  function render() {
    var raw = input.value.trim().toLowerCase(), terms = raw.split(/\s+/).filter(Boolean);
    items = !terms.length ? index.slice(0, 8) : index
      .map(function (e) { return { e: e, s: score(e, terms, raw) }; })
      .filter(function (x) { return x.s > 0; })
      .sort(function (a, b) { return b.s - a.s; })
      .slice(0, 12).map(function (x) { return x.e; });
    sel = 0;
    list.innerHTML = items.length ? items.map(function (e, i) {
      return '<li><a href="' + esc(e.u) + '" role="option" aria-selected="' + (i === 0) + '">' +
        '<span class="k">' + esc(e.k) + '</span><span class="t">' + esc(e.t) + '</span>' +
        '<span class="d">' + esc(e.d) + '</span></a></li>';
    }).join('') : '<li class="empty">Nothing matches. Try a tool, a topic or a lab number.</li>';
  }
  function move(d) {
    var links = all('a', list); if (!links.length) return;
    links[sel].setAttribute('aria-selected', 'false');
    sel = (sel + d + links.length) % links.length;
    links[sel].setAttribute('aria-selected', 'true');
    links[sel].scrollIntoView({ block: 'nearest' });
  }
  function build() {
    var scrim = document.createElement('div');
    scrim.className = 'ps-scrim'; scrim.hidden = true;
    box = document.createElement('div');
    box.className = 'ps-box'; box.hidden = true;
    box.setAttribute('role', 'dialog'); box.setAttribute('aria-modal', 'true'); box.setAttribute('aria-label', 'Search');
    box.innerHTML = '<div class="ps-in"><span class="glyph" aria-hidden="true">&#8981;</span>' +
      '<input type="search" placeholder="Search labs, guides and questions" aria-label="Search" autocomplete="off">' +
      '<kbd>Esc</kbd></div><ul class="ps-res" role="listbox"></ul>' +
      '<div class="ps-foot">&#8593; &#8595; to move &#183; Enter to open &#183; a number jumps to that lab</div>';
    document.body.appendChild(scrim); document.body.appendChild(box);
    input = box.querySelector('input'); list = box.querySelector('.ps-res');
    input.addEventListener('input', render);
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'ArrowDown') { ev.preventDefault(); move(1); }
      else if (ev.key === 'ArrowUp') { ev.preventDefault(); move(-1); }
      else if (ev.key === 'Enter') { var a = all('a', list)[sel]; if (a) { ev.preventDefault(); a.click(); } }
    });
    list.addEventListener('click', function (ev) { if (ev.target.closest('a')) close(); });
    scrim.addEventListener('click', close);
    box.scrim = scrim;
  }
  function open() {
    if (!box) build();
    lastFocus = document.activeElement;
    box.hidden = box.scrim.hidden = false;
    input.value = ''; render(); input.focus();
  }
  function close() {
    if (!box || box.hidden) return;
    box.hidden = box.scrim.hidden = true;
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }
  if ($('searchBtn')) $('searchBtn').addEventListener('click', open);
  document.addEventListener('keydown', function (ev) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test((ev.target || {}).tagName || '') || (ev.target || {}).isContentEditable;
    if (ev.key === 'Escape') close();
    else if (!typing && (ev.key === '/' || ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'k'))) { ev.preventDefault(); open(); }
  });
})();
