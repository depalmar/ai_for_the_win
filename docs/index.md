---
layout: default
title: AI for the Win
---

<style>
:root {
  --primary: #6366f1;
  --primary-hover: #4f46e5;
  --secondary: #10b981;
  --accent: #f59e0b;
  --danger: #ef4444;
  --bg-dark: #0d1117;
  --bg-card: #161b22;
  --bg-card-hover: #1c2128;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --border: #30363d;
}

/* Hide Midnight theme default header entirely */
#header,
header.inner,
.inner > header,
nav:first-of-type:not(.sticky-nav) {
  display: none !important;
}

/* Hide theme attribution from sidebar and footer */
#header p + p,
footer,
.footer,
p:has(a[href*="mattgraham"]),
a[href*="mattgraham"],
/* Hide Midnight theme "Hosted on GitHub Pages - Theme by" footer */
body > footer,
#footer,
.wrapper > footer,
section + p,
section ~ p:last-of-type,
/* Target the specific theme footer text */
body > p:last-of-type,
.inner > p:last-of-type,
#main_content + p,
#main_content ~ p,
/* Hide incomplete theme attribution */
section p:last-child:not(.lab-desc):not(.path-desc):not(.prereq-text) {
  display: none !important;
}

/* Re-show our custom footer */
.footer-links,
.footer-links + p {
  display: flex !important;
}

/* Light theme override */
[data-theme="light"] {
  --primary: #4f46e5;
  --secondary: #059669;
  --bg-dark: #f8fafc;
  --bg-card: #ffffff;
  --bg-card-hover: #f1f5f9;
  --text: #1e293b;
  --text-muted: #64748b;
  --border: #e2e8f0;
}

[data-theme="light"] .sticky-nav {
  background: rgba(248, 250, 252, 0.95);
}

[data-theme="light"] .terminal-demo {
  background: #1e293b;
}

/* Theme toggle button */
.theme-toggle {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 0.4rem 0.8rem;
  cursor: pointer;
  font-size: 0.85rem;
  color: var(--text-muted);
  transition: all 0.2s;
  margin-left: 0.5rem;
}

.theme-toggle:hover {
  border-color: var(--primary);
  color: var(--primary);
}

/* Sticky Navigation */
.sticky-nav {
  position: sticky;
  top: 0;
  background: rgba(13, 17, 23, 0.95);
  backdrop-filter: blur(10px);
  border-bottom: 1px solid var(--border);
  padding: 0.75rem 0;
  z-index: 100;
  margin: -1rem -1rem 1rem -1rem;
  padding-left: 1rem;
  padding-right: 1rem;
}

.nav-content {
  display: flex;
  justify-content: space-between;
  align-items: center;
  max-width: 1200px;
  margin: 0 auto;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.nav-brand {
  font-weight: bold;
  font-size: 1.1rem;
  color: var(--primary);
  text-decoration: none;
}

.nav-links {
  display: flex;
  gap: 1.5rem;
  flex-wrap: wrap;
}

.nav-links a {
  color: var(--text-muted);
  text-decoration: none;
  font-size: 0.9rem;
  transition: color 0.2s;
}

.nav-links a:hover {
  color: var(--primary);
}

.github-badge {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
}

.github-badge img {
  height: 20px;
}

/* Hero */
.hero {
  text-align: center;
  padding: 2rem 0 3rem;
  border-bottom: 1px solid var(--border);
  margin-bottom: 2rem;
}

.hero h1 {
  font-size: 2.5rem;
  margin-bottom: 0.5rem;
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  color: var(--primary); /* Fallback */
}

.hero .tagline {
  font-size: 1.3rem;
  color: var(--text-muted);
  margin-bottom: 1.5rem;
}

.stats {
  display: flex;
  justify-content: center;
  gap: 1.5rem;
  flex-wrap: wrap;
  margin: 2rem 0;
}

.stat {
  text-align: center;
  padding: 1rem 1.25rem;
  background: var(--bg-card);
  border-radius: 8px;
  border: 1px solid var(--border);
  min-width: 100px;
}

.stat-number {
  font-size: 1.75rem;
  font-weight: bold;
  color: var(--primary);
}

.stat-label {
  font-size: 0.85rem;
  color: var(--text-muted);
}

.cta-buttons {
  display: flex;
  justify-content: center;
  gap: 1rem;
  margin-top: 2rem;
  flex-wrap: wrap;
}

.btn {
  display: inline-block;
  padding: 0.75rem 1.5rem;
  border-radius: 6px;
  text-decoration: none;
  font-weight: 600;
  transition: all 0.2s;
  cursor: pointer;
}

.btn-primary {
  background: var(--primary);
  color: white;
}

.btn-primary:hover {
  background: var(--primary-hover);
  transform: translateY(-2px);
}

.btn-secondary {
  background: transparent;
  color: var(--text);
  border: 1px solid var(--border);
}

.btn-secondary:hover {
  border-color: var(--primary);
  color: var(--primary);
}

.section {
  margin: 3rem 0;
  padding: 2rem 0;
  border-bottom: 1px solid var(--border);
}

.section-title {
  font-size: 1.5rem;
  margin-bottom: 1.5rem;
  color: var(--text);
}

/* Features */
.features {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
  margin-top: 1.5rem;
}

.feature {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
}

.feature-icon {
  font-size: 1.5rem;
  margin-bottom: 0.75rem;
}

.feature h3 {
  font-size: 1.1rem;
  margin-bottom: 0.5rem;
  color: var(--text);
}

.feature p {
  font-size: 0.9rem;
  color: var(--text-muted);
  margin: 0;
}

/* Prerequisites Checklist */
.prereq-section {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  margin-top: 1.5rem;
}

.prereq-section h3 {
  margin: 0 0 1rem;
  color: var(--text);
  font-size: 1.1rem;
}

.prereq-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.prereq-item {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
  padding: 0.75rem;
  background: var(--bg-dark);
  border-radius: 6px;
  border: 1px solid var(--border);
}

.prereq-check {
  color: var(--secondary);
  font-size: 1.1rem;
  flex-shrink: 0;
}

.prereq-text {
  font-size: 0.9rem;
  color: var(--text-muted);
}

.prereq-text strong {
  color: var(--text);
  display: block;
  margin-bottom: 0.25rem;
}

/* Lab Filter Tabs */
.lab-filters {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
}

.filter-btn {
  padding: 0.5rem 1rem;
  border: 1px solid var(--border);
  background: var(--bg-card);
  color: var(--text-muted);
  border-radius: 20px;
  cursor: pointer;
  font-size: 0.85rem;
  transition: all 0.2s;
}

.filter-btn:hover, .filter-btn.active {
  border-color: var(--primary);
  color: var(--primary);
  background: rgba(99, 102, 241, 0.1);
}

.filter-btn[data-filter="ml"].active { border-color: var(--secondary); color: var(--secondary); background: rgba(16, 185, 129, 0.1); }
.filter-btn[data-filter="llm"].active { border-color: var(--primary); color: var(--primary); }
.filter-btn[data-filter="dfir"].active { border-color: var(--danger); color: var(--danger); background: rgba(239, 68, 68, 0.1); }
.filter-btn[data-filter="advanced"].active { border-color: var(--accent); color: var(--accent); background: rgba(245, 158, 11, 0.1); }

/* Lab Grid */
.lab-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}

.lab-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  transition: all 0.2s;
  text-decoration: none;
  display: block;
}

.lab-card:hover {
  border-color: var(--primary);
  transform: translateY(-2px);
  background: var(--bg-card-hover);
}

.lab-header {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-bottom: 0.5rem;
}

.lab-number {
  background: var(--primary);
  color: white;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: bold;
}

.lab-number.ml { background: var(--secondary); }
.lab-number.llm { background: var(--primary); }
.lab-number.dfir { background: var(--danger); }
.lab-number.advanced { background: var(--accent); }

.lab-title {
  font-weight: 600;
  color: var(--text);
  flex: 1;
}

.lab-desc {
  font-size: 0.85rem;
  color: var(--text-muted);
  margin: 0 0 0.75rem;
}

.lab-meta {
  display: flex;
  gap: 1rem;
  font-size: 0.75rem;
  color: var(--text-muted);
  border-top: 1px solid var(--border);
  padding-top: 0.75rem;
  margin-top: 0.5rem;
}

.lab-meta span {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}

.difficulty {
  color: var(--accent);
}

.difficulty-1 { color: var(--secondary); }
.difficulty-2 { color: var(--accent); }
.difficulty-3 { color: var(--danger); }

/* Interactive Lab Navigator */
.lab-navigator {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  margin: 1.5rem 0;
  overflow-x: auto;
}

.nav-title {
  font-size: 1rem;
  color: var(--text);
  margin-bottom: 1rem;
  text-align: center;
}

.nav-path {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  flex-wrap: wrap;
  padding: 1rem 0;
}

.nav-stage {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
}

.nav-stage-label {
  font-size: 0.7rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.nav-labs {
  display: flex;
  gap: 0.25rem;
}

.nav-lab {
  width: 36px;
  height: 36px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.75rem;
  font-weight: bold;
  color: white;
  cursor: pointer;
  transition: transform 0.2s;
  text-decoration: none;
}

.nav-lab:hover {
  transform: scale(1.15);
}

.nav-lab.ml { background: var(--secondary); }
.nav-lab.llm { background: var(--primary); }
.nav-lab.dfir { background: var(--danger); }
.nav-lab.advanced { background: var(--accent); }
.nav-lab.intro { background: var(--text-muted); }

.nav-arrow {
  color: var(--text-muted);
  font-size: 1.5rem;
}

/* Path Cards - Expandable */
.path-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1rem;
  margin-top: 1.5rem;
}

.path-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}

.path-header {
  padding: 1.25rem;
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.path-header:hover {
  background: var(--bg-card-hover);
}

.path-header h3 {
  margin: 0;
  color: var(--text);
  font-size: 1.1rem;
}

.path-toggle {
  color: var(--text-muted);
  transition: transform 0.2s;
}

.path-card[open] .path-toggle {
  transform: rotate(180deg);
}

.path-content {
  padding: 0 1.25rem 1.25rem;
  border-top: 1px solid var(--border);
}

.path-desc {
  font-size: 0.9rem;
  color: var(--text-muted);
  margin: 1rem 0;
}

.path-labs-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.path-lab-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem;
  background: var(--bg-dark);
  border-radius: 4px;
  font-size: 0.85rem;
}

.path-lab-num {
  background: var(--primary);
  color: white;
  padding: 0.2rem 0.5rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-weight: bold;
  min-width: 28px;
  text-align: center;
}

.path-lab-num.intro { background: var(--text-muted); }
.path-lab-num.ml { background: var(--secondary); }
.path-lab-num.llm { background: var(--primary); }
.path-lab-num.advanced { background: var(--accent); }
.path-lab-num.dfir { background: var(--danger); }

.path-lab-name {
  color: var(--text);
}

.path-time {
  margin-left: auto;
  color: var(--text-muted);
  font-size: 0.75rem;
}

/* Cost Table */
.cost-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 1rem;
}

.cost-table th, .cost-table td {
  padding: 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

.cost-table th {
  color: var(--text);
  font-weight: 600;
}

.cost-table td {
  color: var(--text-muted);
}

.free { color: var(--secondary) !important; font-weight: 600; }

/* Quick Start */
.quick-start {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem;
  margin-top: 1.5rem;
}

.quick-start pre {
  background: var(--bg-dark);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1rem;
  overflow-x: auto;
}

.quick-start pre, .quick-start code {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 0.85rem;
  line-height: 1.5;
}

.quick-start code {
  color: var(--secondary);
}

/* FAQ */
.faq {
  margin-top: 1.5rem;
}

.faq-item {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 0.75rem;
}

.faq-item summary {
  cursor: pointer;
  font-weight: 600;
  color: var(--text);
  padding: 1rem 1.25rem;
  list-style: none;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.faq-item summary::-webkit-details-marker {
  display: none;
}

.faq-item summary::after {
  content: '+';
  font-size: 1.25rem;
  color: var(--text-muted);
}

.faq-item[open] summary::after {
  content: '-';
}

.faq-content {
  margin: 0;
  padding: 0.75rem 1.25rem 1rem;
  color: var(--text-muted);
  font-size: 0.9rem;
  line-height: 1.5;
}

/* Footer */
.footer-links {
  display: flex;
  justify-content: center;
  gap: 2rem;
  padding: 2rem 0;
  flex-wrap: wrap;
}

.footer-links a {
  color: var(--text-muted);
  text-decoration: none;
  transition: color 0.2s;
}

.footer-links a:hover {
  color: var(--primary);
}

/* Terminal typing animation */
.terminal-demo {
  background: #0d1117;
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem;
  margin: 1.5rem auto;
  max-width: 600px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
  font-size: 0.8rem;
  text-align: left;
}

.terminal-header {
  display: flex;
  gap: 6px;
  margin-bottom: 0.75rem;
}

.terminal-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}

.terminal-dot.red { background: #ff5f56; }
.terminal-dot.yellow { background: #ffbd2e; }
.terminal-dot.green { background: #27ca40; }

.terminal-line {
  color: #10b981;
  margin: 0.25rem 0;
  opacity: 0;
  animation: fadeIn 0.3s forwards;
}

.terminal-line::before {
  content: '$ ';
  color: #6366f1;
}

.terminal-line.output::before {
  content: '';
}

.terminal-line:nth-child(2) { animation-delay: 0.3s; }
.terminal-line:nth-child(3) { animation-delay: 0.5s; }
.terminal-line:nth-child(4) { animation-delay: 0.7s; }
.terminal-line:nth-child(5) { animation-delay: 0.9s; }
.terminal-line:nth-child(6) { animation-delay: 1.1s; }
.terminal-line:nth-child(7) { animation-delay: 1.3s; }
.terminal-line:nth-child(8) { animation-delay: 1.5s; }
.terminal-line:nth-child(9) { animation-delay: 1.7s; }
.terminal-line:nth-child(10) { animation-delay: 1.9s; }
.terminal-line:nth-child(11) { animation-delay: 2.1s; }
.terminal-line:nth-child(12) { animation-delay: 2.3s; }
.terminal-line:nth-child(13) { animation-delay: 2.5s; }
.terminal-line:nth-child(14) { animation-delay: 2.7s; }
.terminal-line:nth-child(15) { animation-delay: 2.9s; }
.terminal-line:nth-child(16) { animation-delay: 3.1s; }

@keyframes fadeIn {
  to { opacity: 1; }
}

.typing {
  border-right: 2px solid #10b981;
  animation: blink 0.7s infinite;
}

@keyframes blink {
  50% { border-color: transparent; }
}

/* Mobile Responsive */
@media (max-width: 768px) {
  .hero h1 {
    font-size: 1.75rem;
  }

  .hero .tagline {
    font-size: 1rem;
  }

  .stats {
    gap: 0.75rem;
  }

  .stat {
    padding: 0.75rem 1rem;
    min-width: 80px;
  }

  .stat-number {
    font-size: 1.5rem;
  }

  .nav-links {
    gap: 1rem;
  }

  .lab-grid {
    grid-template-columns: 1fr;
  }

  .path-grid {
    grid-template-columns: 1fr;
  }

  .features {
    grid-template-columns: 1fr;
  }

  .section {
    margin: 2rem 0;
    padding: 1.5rem 0;
  }

  .nav-path {
    justify-content: flex-start;
    overflow-x: auto;
    padding-bottom: 1rem;
  }

  .prereq-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 480px) {
  .sticky-nav {
    padding: 0.5rem 0.75rem;
  }

  .nav-content {
    flex-direction: column;
    gap: 0.75rem;
  }

  .cta-buttons {
    flex-direction: column;
    align-items: center;
  }

  .btn {
    width: 100%;
    max-width: 250px;
    text-align: center;
  }
}
</style>

<!-- Sticky Navigation -->
<nav class="sticky-nav">
  <div class="nav-content">
    <a href="#" class="nav-brand">AI for the Win</a>
    <div class="nav-links">
      <a href="#labs">Labs</a>
      <a href="#paths">Learning Paths</a>
      <a href="#cost">Cost</a>
      <a href="#faq">FAQ</a>
      <span class="github-badge">
        <a href="https://github.com/depalmar/ai_for_the_win">
          <img src="https://img.shields.io/github/stars/depalmar/ai_for_the_win?style=social" alt="GitHub stars">
        </a>
      </span>
      <button class="theme-toggle" onclick="toggleTheme()" title="Toggle light/dark mode">
        <span id="theme-icon">☀️</span>
      </button>
    </div>
  </div>
</nav>

<div class="hero">
  <img src="assets/images/logo.svg" alt="AI for the Win Logo" width="120" height="120" style="margin-bottom: 1rem;">
  <h1>AI for the Win</h1>
  <p class="tagline">Build AI-Powered Security Tools | Hands-On Learning</p>

  <div class="terminal-demo">
    <div class="terminal-header">
      <span class="terminal-dot red"></span>
      <span class="terminal-dot yellow"></span>
      <span class="terminal-dot green"></span>
    </div>
    <div class="terminal-line">python labs/lab01-phishing-classifier/solution/main.py</div>
    <div class="terminal-line output"></div>
    <div class="terminal-line output">[+] Trained on 1,000 labeled emails</div>
    <div class="terminal-line output">[+] Model: Random Forest with TF-IDF features</div>
    <div class="terminal-line output"></div>
    <div class="terminal-line output">Testing on new emails...</div>
    <div class="terminal-line output">  "Dear user, your account will be suspended" → 🚨 PHISHING (94%)</div>
    <div class="terminal-line output">  "Q3 revenue report attached"               → ✅ LEGIT (91%)</div>
    <div class="terminal-line output">  "Coinbase: verify identity immediately"    → 🚨 PHISHING (97%)</div>
    <div class="terminal-line output"></div>
    <div class="terminal-line output">Top phishing indicators learned:</div>
    <div class="terminal-line output">  1. urgency_score  (+0.34) ← "immediately", "suspend", "verify"</div>
    <div class="terminal-line output">  2. url_mismatch   (+0.28) ← display text ≠ actual link</div>
    <div class="terminal-line output">  3. sender_anomaly (+0.19) ← domain doesn't match brand<span class="typing"></span></div>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="stat-number">30+</div>
      <div class="stat-label">Hands-On Labs</div>
    </div>
    <div class="stat">
      <div class="stat-number">839</div>
      <div class="stat-label">Tests Passing</div>
    </div>
    <div class="stat">
      <div class="stat-number">9</div>
      <div class="stat-label">Learning Paths</div>
    </div>
    <div class="stat">
      <div class="stat-number">MIT</div>
      <div class="stat-label">Licensed</div>
    </div>
  </div>

  <div class="cta-buttons">
    <a href="https://github.com/depalmar/ai_for_the_win#get-started-in-5-minutes" class="btn btn-primary">Get Started</a>
    <a href="https://github.com/depalmar/ai_for_the_win" class="btn btn-secondary">View on GitHub</a>
  </div>
</div>

<!-- Prerequisites Checklist -->
<div class="section">
  <h2 class="section-title">What You Need to Start</h2>

  <div class="prereq-section">
    <h3>Prerequisites Checklist</h3>
    <div class="prereq-grid">
      <div class="prereq-item">
        <span class="prereq-check">&#10003;</span>
        <div class="prereq-text">
          <strong>Python 3.10+</strong>
          Any OS: Windows, macOS, Linux
        </div>
      </div>
      <div class="prereq-item">
        <span class="prereq-check">&#10003;</span>
        <div class="prereq-text">
          <strong>Code Editor</strong>
          VS Code, Cursor, or PyCharm
        </div>
      </div>
      <div class="prereq-item">
        <span class="prereq-check">&#10003;</span>
        <div class="prereq-text">
          <strong>8GB+ RAM</strong>
          16GB recommended for local LLMs
        </div>
      </div>
      <div class="prereq-item">
        <span class="prereq-check">&#10003;</span>
        <div class="prereq-text">
          <strong>Git Installed</strong>
          To clone the repository
        </div>
      </div>
      <div class="prereq-item">
        <span class="prereq-check">&#10003;</span>
        <div class="prereq-text">
          <strong>API Key (optional)</strong>
          Only needed for Labs 04+. Free options available.
        </div>
      </div>
      <div class="prereq-item">
        <span class="prereq-check">&#10003;</span>
        <div class="prereq-text">
          <strong>Security Background</strong>
          Basic security concepts helpful but not required
        </div>
      </div>
    </div>
  </div>
</div>

<div class="section">
  <h2 class="section-title">Why AI for the Win?</h2>

  <div class="features">
    <div class="feature">
      <div class="feature-icon">&#127919;</div>
      <h3>Built for Security Practitioners</h3>
      <p>Not generic ML courses. Every lab solves real security problems: phishing, malware, C2 detection, incident response.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">&#128736;</div>
      <h3>You Build Real Tools</h3>
      <p>No toy examples. Build classifiers, agents, RAG systems, and detection pipelines you can actually use.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">&#128640;</div>
      <h3>Vibe Coding Ready</h3>
      <p>Designed for AI-assisted development with Cursor, Claude Code, and Copilot. Learn the modern way.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">&#128176;</div>
      <h3>Start Free</h3>
      <p>Labs 01-03 need no API key. Learn ML foundations before spending on LLM APIs. Ollama option for $0 total.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">&#127891;</div>
      <h3>Beginner Friendly</h3>
      <p>New to Python? Start at Lab 00. Security-to-AI Glossary translates ML jargon into terms you know.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">&#128300;</div>
      <h3>839 Tests</h3>
      <p>Every lab has comprehensive tests. Know your code works before deploying. 100% pass rate.</p>
    </div>
  </div>
</div>

<!-- Interactive Lab Navigator -->
<div class="section" id="labs">
  <h2 class="section-title">Interactive Lab Navigator</h2>

  <div class="lab-navigator">
    <div class="nav-title">Your Learning Journey: Click any lab to explore</div>
    <div class="nav-path">
      <div class="nav-stage">
        <div class="nav-stage-label">Setup & Intro</div>
        <div class="nav-labs">
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00-environment-setup" class="nav-lab intro" title="Lab 00: Environment Setup">00</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00a-python-security-fundamentals" class="nav-lab intro" title="Lab 00a: Python for Security">00a</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00b-ml-concepts-primer" class="nav-lab intro" title="Lab 00b: ML Concepts">00b</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00c-intro-prompt-engineering" class="nav-lab intro" title="Lab 00c: Prompt Engineering">00c</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00d-ai-in-security-operations" class="nav-lab intro" title="Lab 00d: AI in Security Ops">00d</a>
        </div>
      </div>
      <span class="nav-arrow">&#8594;</span>
      <div class="nav-stage">
        <div class="nav-stage-label">ML Basics</div>
        <div class="nav-labs">
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab01-phishing-classifier" class="nav-lab ml" title="Lab 01: Phishing Classifier (~2 hrs)">01</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab02-malware-clustering" class="nav-lab ml" title="Lab 02: Malware Clustering (~2 hrs)">02</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab03-anomaly-detection" class="nav-lab ml" title="Lab 03: Anomaly Detection (~2 hrs)">03</a>
        </div>
      </div>
      <span class="nav-arrow">&#8594;</span>
      <div class="nav-stage">
        <div class="nav-stage-label">LLM Basics</div>
        <div class="nav-labs">
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab04-llm-log-analysis" class="nav-lab llm" title="Lab 04: LLM Log Analysis (~3 hrs)">04</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab05-threat-intel-agent" class="nav-lab llm" title="Lab 05: Threat Intel Agent (~3 hrs)">05</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab06-security-rag" class="nav-lab llm" title="Lab 06: Security RAG (~4 hrs)">06</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab07-yara-generator" class="nav-lab llm" title="Lab 07: YARA Generator (~3 hrs)">07</a>
        </div>
      </div>
      <span class="nav-arrow">&#8594;</span>
      <div class="nav-stage">
        <div class="nav-stage-label">Advanced</div>
        <div class="nav-labs">
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab08-vuln-scanner-ai" class="nav-lab advanced" title="Lab 08: Vuln Prioritizer (~4 hrs)">08</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab09-detection-pipeline" class="nav-lab advanced" title="Lab 09: Detection Pipeline (~5 hrs)">09</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab10-ir-copilot" class="nav-lab advanced" title="Lab 10: IR Copilot (~4 hrs)">10</a>
        </div>
      </div>
      <span class="nav-arrow">&#8594;</span>
      <div class="nav-stage">
        <div class="nav-stage-label">Expert DFIR</div>
        <div class="nav-labs">
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab11-ransomware-detection" class="nav-lab dfir" title="Lab 11: Ransomware Detection (~5 hrs)">11</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab12-ransomware-simulation" class="nav-lab dfir" title="Lab 12: Purple Team Sim (~6 hrs)">12</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab13-memory-forensics-ai" class="nav-lab dfir" title="Lab 13: Memory Forensics (~6 hrs)">13</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab14-c2-traffic-analysis" class="nav-lab dfir" title="Lab 14: C2 Traffic Analysis (~5 hrs)">14</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab15-lateral-movement-detection" class="nav-lab dfir" title="Lab 15: Lateral Movement (~5 hrs)">15</a>
        </div>
      </div>
      <span class="nav-arrow">&#8594;</span>
      <div class="nav-stage">
        <div class="nav-stage-label">Expert AI</div>
        <div class="nav-labs">
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab16-threat-actor-profiling" class="nav-lab dfir" title="Lab 16: Threat Actor Profiling (~5 hrs)">16</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab17-adversarial-ml" class="nav-lab dfir" title="Lab 17: Adversarial ML (~6 hrs)">17</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab18-fine-tuning-security" class="nav-lab dfir" title="Lab 18: Fine-Tuning (~8 hrs)">18</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab19-cloud-security-ai" class="nav-lab dfir" title="Lab 19: Cloud Security AI (~5 hrs)">19</a>
          <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab20-llm-red-teaming" class="nav-lab dfir" title="Lab 20: LLM Red Teaming (~6 hrs)">20</a>
        </div>
      </div>
    </div>
    <div style="text-align: center; margin-top: 1rem;">
      <span style="display: inline-flex; gap: 1rem; flex-wrap: wrap; justify-content: center; font-size: 0.8rem; color: var(--text-muted);">
        <span><span class="nav-lab ml" style="width: 16px; height: 16px; display: inline-flex; font-size: 0.6rem;">&#8226;</span> ML (No API)</span>
        <span><span class="nav-lab llm" style="width: 16px; height: 16px; display: inline-flex; font-size: 0.6rem;">&#8226;</span> LLM</span>
        <span><span class="nav-lab advanced" style="width: 16px; height: 16px; display: inline-flex; font-size: 0.6rem;">&#8226;</span> Advanced</span>
        <span><span class="nav-lab dfir" style="width: 16px; height: 16px; display: inline-flex; font-size: 0.6rem;">&#8226;</span> DFIR/Expert</span>
      </span>
    </div>
  </div>

  <h3 style="margin-top: 2rem; margin-bottom: 1rem;">All 30+ Labs (Including Bridge Labs)</h3>

  <!-- Lab Filter Tabs -->
  <div class="lab-filters">
    <button class="filter-btn active" data-filter="all" onclick="filterLabs('all')">All Labs</button>
    <button class="filter-btn" data-filter="ml" onclick="filterLabs('ml')">ML (No API)</button>
    <button class="filter-btn" data-filter="llm" onclick="filterLabs('llm')">LLM</button>
    <button class="filter-btn" data-filter="advanced" onclick="filterLabs('advanced')">Advanced</button>
    <button class="filter-btn" data-filter="dfir" onclick="filterLabs('dfir')">DFIR/Expert</button>
  </div>

  <div class="lab-grid" id="labGrid">
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00-environment-setup" class="lab-card" data-category="intro">
      <div class="lab-header">
        <span class="lab-number">00</span>
        <span class="lab-title">Environment Setup</span>
      </div>
      <p class="lab-desc">Python, VS Code, virtual env, Jupyter</p>
      <div class="lab-meta">
        <span>&#128337; ~30 min</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00a-python-security-fundamentals" class="lab-card" data-category="intro">
      <div class="lab-header">
        <span class="lab-number">00a</span>
        <span class="lab-title">Python for Security</span>
      </div>
      <p class="lab-desc">Variables, files, APIs, IOC extraction</p>
      <div class="lab-meta">
        <span>&#128337; ~2 hrs</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00b-ml-concepts-primer" class="lab-card" data-category="intro">
      <div class="lab-header">
        <span class="lab-number">00b</span>
        <span class="lab-title">ML Concepts</span>
      </div>
      <p class="lab-desc">Supervised, unsupervised, features, metrics</p>
      <div class="lab-meta">
        <span>&#128337; ~1 hr</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00c-intro-prompt-engineering" class="lab-card" data-category="intro">
      <div class="lab-header">
        <span class="lab-number">00c</span>
        <span class="lab-title">Prompt Engineering</span>
      </div>
      <p class="lab-desc">LLM basics, templates, free playgrounds</p>
      <div class="lab-meta">
        <span>&#128337; ~1 hr</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00d-ai-in-security-operations" class="lab-card" data-category="intro">
      <div class="lab-header">
        <span class="lab-number">00d</span>
        <span class="lab-title">AI in Security Ops</span>
      </div>
      <p class="lab-desc">Real-world use cases, limitations, workflows</p>
      <div class="lab-meta">
        <span>&#128337; ~1 hr</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00e-visualization-stats" class="lab-card" data-category="intro">
      <div class="lab-header">
        <span class="lab-number">00e</span>
        <span class="lab-title">Visualization & Stats</span>
      </div>
      <p class="lab-desc">Statistics, Plotly, security dashboards</p>
      <div class="lab-meta">
        <span>&#128337; ~2 hrs</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00f-hello-world-ml" class="lab-card" data-category="intro">
      <div class="lab-header">
        <span class="lab-number">00f</span>
        <span class="lab-title">Hello World ML</span>
      </div>
      <p class="lab-desc">Your first ML model, scikit-learn basics</p>
      <div class="lab-meta">
        <span>&#128337; ~1 hr</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab00g-working-with-apis" class="lab-card" data-category="intro">
      <div class="lab-header">
        <span class="lab-number">00g</span>
        <span class="lab-title">Working with APIs</span>
      </div>
      <p class="lab-desc">HTTP basics, requests, JSON parsing</p>
      <div class="lab-meta">
        <span>&#128337; ~1 hr</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab01-phishing-classifier" class="lab-card" data-category="ml">
      <div class="lab-header">
        <span class="lab-number ml">01</span>
        <span class="lab-title">Phishing Classifier</span>
      </div>
      <p class="lab-desc">ML text classification, TF-IDF, Random Forest</p>
      <div class="lab-meta">
        <span>&#128337; ~2 hrs</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab02-malware-clustering" class="lab-card" data-category="ml">
      <div class="lab-header">
        <span class="lab-number ml">02</span>
        <span class="lab-title">Malware Clustering</span>
      </div>
      <p class="lab-desc">K-Means, DBSCAN, feature extraction</p>
      <div class="lab-meta">
        <span>&#128337; ~2 hrs</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab03-anomaly-detection" class="lab-card" data-category="ml">
      <div class="lab-header">
        <span class="lab-number ml">03</span>
        <span class="lab-title">Anomaly Detection</span>
      </div>
      <p class="lab-desc">Isolation Forest, statistical baselines</p>
      <div class="lab-meta">
        <span>&#128337; ~2 hrs</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab03b-ml-vs-llm" class="lab-card" data-category="ml">
      <div class="lab-header">
        <span class="lab-number ml">03b</span>
        <span class="lab-title">ML vs LLM</span>
      </div>
      <p class="lab-desc">When to use ML vs LLM, cost comparison</p>
      <div class="lab-meta">
        <span>&#128337; ~1 hr</span>
        <span class="difficulty difficulty-1">&#9733;&#9734;&#9734; Beginner</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab04-llm-log-analysis" class="lab-card" data-category="llm">
      <div class="lab-header">
        <span class="lab-number llm">04</span>
        <span class="lab-title">LLM Log Analysis</span>
      </div>
      <p class="lab-desc">Prompt engineering, IOC extraction</p>
      <div class="lab-meta">
        <span>&#128337; ~3 hrs</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab05-threat-intel-agent" class="lab-card" data-category="llm">
      <div class="lab-header">
        <span class="lab-number llm">05</span>
        <span class="lab-title">Threat Intel Agent</span>
      </div>
      <p class="lab-desc">ReAct pattern, LangChain, autonomous investigation</p>
      <div class="lab-meta">
        <span>&#128337; ~3 hrs</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab06-security-rag" class="lab-card" data-category="llm">
      <div class="lab-header">
        <span class="lab-number llm">06</span>
        <span class="lab-title">Security RAG</span>
      </div>
      <p class="lab-desc">Vector embeddings, ChromaDB, doc Q&A</p>
      <div class="lab-meta">
        <span>&#128337; ~4 hrs</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab06a-embeddings-vectors" class="lab-card" data-category="llm">
      <div class="lab-header">
        <span class="lab-number llm">06b</span>
        <span class="lab-title">Embeddings & Vectors</span>
      </div>
      <p class="lab-desc">Deep dive into embeddings for RAG</p>
      <div class="lab-meta">
        <span>&#128337; ~2 hrs</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab07-yara-generator" class="lab-card" data-category="llm">
      <div class="lab-header">
        <span class="lab-number llm">07</span>
        <span class="lab-title">YARA Generator</span>
      </div>
      <p class="lab-desc">AI-assisted rule generation, validation</p>
      <div class="lab-meta">
        <span>&#128337; ~3 hrs</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab07a-binary-basics" class="lab-card" data-category="llm">
      <div class="lab-header">
        <span class="lab-number llm">07a</span>
        <span class="lab-title">Binary Basics</span>
      </div>
      <p class="lab-desc">PE files, headers, sections for YARA</p>
      <div class="lab-meta">
        <span>&#128337; ~2 hrs</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab08-vuln-scanner-ai" class="lab-card" data-category="advanced">
      <div class="lab-header">
        <span class="lab-number advanced">08</span>
        <span class="lab-title">Vuln Prioritizer</span>
      </div>
      <p class="lab-desc">CVSS scoring, risk-based prioritization</p>
      <div class="lab-meta">
        <span>&#128337; ~4 hrs</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab09-detection-pipeline" class="lab-card" data-category="advanced">
      <div class="lab-header">
        <span class="lab-number advanced">09</span>
        <span class="lab-title">Detection Pipeline</span>
      </div>
      <p class="lab-desc">Multi-stage ML + LLM architecture</p>
      <div class="lab-meta">
        <span>&#128337; ~5 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Advanced</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab10-ir-copilot" class="lab-card" data-category="advanced">
      <div class="lab-header">
        <span class="lab-number advanced">10</span>
        <span class="lab-title">IR Copilot</span>
      </div>
      <p class="lab-desc">Conversational IR assistant, playbooks</p>
      <div class="lab-meta">
        <span>&#128337; ~4 hrs</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab10a-dfir-fundamentals" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">10b</span>
        <span class="lab-title">DFIR Fundamentals</span>
      </div>
      <p class="lab-desc">IR lifecycle, Windows artifacts, ATT&CK</p>
      <div class="lab-meta">
        <span>&#128337; ~2 hrs</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab11-ransomware-detection" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">11</span>
        <span class="lab-title">Ransomware Detection</span>
      </div>
      <p class="lab-desc">Entropy analysis, behavioral detection</p>
      <div class="lab-meta">
        <span>&#128337; ~5 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Advanced</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab12-ransomware-simulation" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">12</span>
        <span class="lab-title">Purple Team Sim</span>
      </div>
      <p class="lab-desc">Safe adversary emulation, gap analysis</p>
      <div class="lab-meta">
        <span>&#128337; ~6 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Advanced</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab13-memory-forensics-ai" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">13</span>
        <span class="lab-title">Memory Forensics AI</span>
      </div>
      <p class="lab-desc">Volatility3, process injection, credentials</p>
      <div class="lab-meta">
        <span>&#128337; ~6 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Advanced</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab14-c2-traffic-analysis" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">14</span>
        <span class="lab-title">C2 Traffic Analysis</span>
      </div>
      <p class="lab-desc">Beaconing, DNS tunneling, JA3</p>
      <div class="lab-meta">
        <span>&#128337; ~5 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Advanced</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab15-lateral-movement-detection" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">15</span>
        <span class="lab-title">Lateral Movement</span>
      </div>
      <p class="lab-desc">Auth anomalies, attack path graphs</p>
      <div class="lab-meta">
        <span>&#128337; ~5 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Advanced</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab16-threat-actor-profiling" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">16</span>
        <span class="lab-title">Threat Actor Profiling</span>
      </div>
      <p class="lab-desc">TTP extraction, campaign clustering</p>
      <div class="lab-meta">
        <span>&#128337; ~5 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Advanced</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab17-adversarial-ml" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">17</span>
        <span class="lab-title">Adversarial ML</span>
      </div>
      <p class="lab-desc">Evasion attacks, poisoning, defenses</p>
      <div class="lab-meta">
        <span>&#128337; ~6 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Advanced</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab17a-ml-security-intro" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">17a</span>
        <span class="lab-title">ML Security Intro</span>
      </div>
      <p class="lab-desc">ML threat models, attack taxonomy</p>
      <div class="lab-meta">
        <span>&#128337; ~1 hr</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab18-fine-tuning-security" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">18</span>
        <span class="lab-title">Fine-Tuning</span>
      </div>
      <p class="lab-desc">Custom embeddings, LoRA, deployment</p>
      <div class="lab-meta">
        <span>&#128337; ~8 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Expert</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab19a-cloud-security-fundamentals" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">19a</span>
        <span class="lab-title">Cloud Security Basics</span>
      </div>
      <p class="lab-desc">AWS/Azure/GCP fundamentals, IAM, logs</p>
      <div class="lab-meta">
        <span>&#128337; ~2 hrs</span>
        <span class="difficulty difficulty-2">&#9733;&#9733;&#9734; Intermediate</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab19-cloud-security-ai" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">19</span>
        <span class="lab-title">Cloud Security AI</span>
      </div>
      <p class="lab-desc">AI-powered CloudTrail analysis</p>
      <div class="lab-meta">
        <span>&#128337; ~5 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Advanced</span>
      </div>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab20-llm-red-teaming" class="lab-card" data-category="dfir">
      <div class="lab-header">
        <span class="lab-number dfir">20</span>
        <span class="lab-title">LLM Red Teaming</span>
      </div>
      <p class="lab-desc">Prompt injection, jailbreaks, guardrails</p>
      <div class="lab-meta">
        <span>&#128337; ~6 hrs</span>
        <span class="difficulty difficulty-3">&#9733;&#9733;&#9733; Advanced</span>
      </div>
    </a>
  </div>

  <div class="cta-buttons" style="margin-top: 2rem;">
    <a href="https://github.com/depalmar/ai_for_the_win#get-started-in-5-minutes" class="btn btn-primary">Get Started</a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/labs" class="btn btn-secondary">Browse All Labs</a>
  </div>
</div>

<script>
function filterLabs(category) {
  const cards = document.querySelectorAll('.lab-card');
  const buttons = document.querySelectorAll('.filter-btn');

  buttons.forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  cards.forEach(card => {
    if (category === 'all' || card.dataset.category === category ||
        (category === 'ml' && card.dataset.category === 'intro')) {
      card.style.display = 'block';
    } else {
      card.style.display = 'none';
    }
  });
}

// Theme toggle functionality
function toggleTheme() {
  const html = document.documentElement;
  const icon = document.getElementById('theme-icon');
  if (html.dataset.theme === 'light') {
    html.dataset.theme = 'dark';
    icon.textContent = '☀️';
    localStorage.setItem('theme', 'dark');
  } else {
    html.dataset.theme = 'light';
    icon.textContent = '🌙';
    localStorage.setItem('theme', 'light');
  }
}

// Load saved theme preference on page load
(function() {
  const saved = localStorage.getItem('theme');
  if (saved === 'light') {
    document.documentElement.dataset.theme = 'light';
    const icon = document.getElementById('theme-icon');
    if (icon) icon.textContent = '🌙';
  }
})();

// Remove theme attribution footer
(function() {
  function removeThemeFooter() {
    document.querySelectorAll('p, footer, span').forEach(function(el) {
      if (el.textContent.includes('Theme by') ||
          el.textContent.includes('Hosted on GitHub Pages')) {
        el.style.display = 'none';
      }
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', removeThemeFooter);
  } else {
    removeThemeFooter();
  }
  setTimeout(removeThemeFooter, 500);
})();
</script>

<div class="section" id="paths">
  <h2 class="section-title">Choose Your Learning Path</h2>
  <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Click to expand each path and see the recommended labs</p>

  <div class="path-grid">
    <details class="path-card" open>
      <summary class="path-header">
        <h3>🟢 Beginner</h3>
        <span class="path-toggle">&#9660;</span>
      </summary>
      <div class="path-content">
        <p class="path-desc">Start here! Foundations → ML basics → LLM basics. No API key needed until Lab 04.</p>
        <p style="font-size: 0.8rem; color: var(--secondary); margin-bottom: 0.75rem; font-weight: 600;">📚 Foundations (Optional Prep)</p>
        <div class="path-labs-list">
          <div class="path-lab-item">
            <span class="path-lab-num intro">00</span>
            <span class="path-lab-name">Environment Setup</span>
            <span class="path-time">~30 min</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num intro">00a</span>
            <span class="path-lab-name">Python for Security</span>
            <span class="path-time">~2 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num intro">00b</span>
            <span class="path-lab-name">ML Concepts Primer</span>
            <span class="path-time">~1 hr</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num intro">00c</span>
            <span class="path-lab-name">Prompt Engineering</span>
            <span class="path-time">~1 hr</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num intro">00d</span>
            <span class="path-lab-name">AI in Security Ops</span>
            <span class="path-time">~1 hr</span>
          </div>
        </div>
        <p style="font-size: 0.8rem; color: var(--secondary); margin: 1rem 0 0.75rem; font-weight: 600;">🔬 ML Basics (No API Key)</p>
        <div class="path-labs-list">
          <div class="path-lab-item">
            <span class="path-lab-num ml">01</span>
            <span class="path-lab-name">Phishing Classifier</span>
            <span class="path-time">~2 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num ml">02</span>
            <span class="path-lab-name">Malware Clustering</span>
            <span class="path-time">~2 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num ml">03</span>
            <span class="path-lab-name">Anomaly Detection</span>
            <span class="path-time">~2 hrs</span>
          </div>
        </div>
        <p style="font-size: 0.8rem; color: var(--primary); margin: 1rem 0 0.75rem; font-weight: 600;">🤖 LLM Basics (API Key Required)</p>
        <div class="path-labs-list">
          <div class="path-lab-item">
            <span class="path-lab-num llm">04</span>
            <span class="path-lab-name">LLM Log Analysis</span>
            <span class="path-time">~3 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num llm">05</span>
            <span class="path-lab-name">Threat Intel Agent</span>
            <span class="path-time">~3 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num llm">06</span>
            <span class="path-lab-name">Security RAG</span>
            <span class="path-time">~4 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num llm">07</span>
            <span class="path-lab-name">YARA Generator</span>
            <span class="path-time">~3 hrs</span>
          </div>
        </div>
        <p style="margin-top: 1rem; font-size: 0.85rem; color: var(--text-muted);">Total: ~25 hours | Cost: Free → ~$5</p>
      </div>
    </details>

    <details class="path-card">
      <summary class="path-header">
        <h3>🟡 Intermediate</h3>
        <span class="path-toggle">&#9660;</span>
      </summary>
      <div class="path-content">
        <p class="path-desc">Build advanced tools. Detection pipelines, IR copilots, and DFIR automation.</p>
        <div class="path-labs-list">
          <div class="path-lab-item">
            <span class="path-lab-num advanced">08</span>
            <span class="path-lab-name">Vuln Prioritizer</span>
            <span class="path-time">~4 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num advanced">09</span>
            <span class="path-lab-name">Detection Pipeline</span>
            <span class="path-time">~5 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num advanced">10</span>
            <span class="path-lab-name">IR Copilot</span>
            <span class="path-time">~4 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num dfir">11</span>
            <span class="path-lab-name">Ransomware Detection</span>
            <span class="path-time">~5 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num dfir">12</span>
            <span class="path-lab-name">Purple Team Sim</span>
            <span class="path-time">~6 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num dfir">13</span>
            <span class="path-lab-name">Memory Forensics</span>
            <span class="path-time">~6 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num dfir">14</span>
            <span class="path-lab-name">C2 Traffic Analysis</span>
            <span class="path-time">~5 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num dfir">15</span>
            <span class="path-lab-name">Lateral Movement</span>
            <span class="path-time">~5 hrs</span>
          </div>
        </div>
        <p style="margin-top: 1rem; font-size: 0.85rem; color: var(--text-muted);">Total: ~40 hours | Cost: ~$15-25</p>
      </div>
    </details>

    <details class="path-card">
      <summary class="path-header">
        <h3>🔴 Expert</h3>
        <span class="path-toggle">&#9660;</span>
      </summary>
      <div class="path-content">
        <p class="path-desc">Advanced techniques: threat actor profiling, adversarial ML, fine-tuning, and red teaming.</p>
        <div class="path-labs-list">
          <div class="path-lab-item">
            <span class="path-lab-num dfir">16</span>
            <span class="path-lab-name">Threat Actor Profiling</span>
            <span class="path-time">~5 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num dfir">17</span>
            <span class="path-lab-name">Adversarial ML</span>
            <span class="path-time">~6 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num dfir">18</span>
            <span class="path-lab-name">Fine-Tuning</span>
            <span class="path-time">~8 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num dfir">19</span>
            <span class="path-lab-name">Cloud Security AI</span>
            <span class="path-time">~5 hrs</span>
          </div>
          <div class="path-lab-item">
            <span class="path-lab-num dfir">20</span>
            <span class="path-lab-name">LLM Red Teaming</span>
            <span class="path-time">~6 hrs</span>
          </div>
        </div>
        <p style="margin-top: 1rem; font-size: 0.85rem; color: var(--text-muted);">Total: ~30 hours | Cost: ~$10-20</p>
      </div>
    </details>

  </div>

  <h3 style="margin-top: 2.5rem; margin-bottom: 1rem;">By Role</h3>
  <div class="features" style="grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));">
    <a href="https://github.com/depalmar/ai_for_the_win/blob/main/resources/role-based-learning-paths.md#-soc-analyst-path" class="feature" style="text-decoration: none; cursor: pointer;">
      <div class="feature-icon">🔵</div>
      <h3 style="margin: 0;">SOC Analyst</h3>
      <p>Automate triage, reduce alert fatigue</p>
      <span style="font-size: 0.75rem; color: var(--secondary);">Labs 00→04→06→10</span>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/blob/main/resources/role-based-learning-paths.md#-threat-hunter-path" class="feature" style="text-decoration: none; cursor: pointer;">
      <div class="feature-icon">🟢</div>
      <h3 style="margin: 0;">Threat Hunter</h3>
      <p>Find unknowns, detect anomalies</p>
      <span style="font-size: 0.75rem; color: var(--secondary);">Labs 03→02→14→15</span>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/blob/main/resources/role-based-learning-paths.md#-detection-engineer-path" class="feature" style="text-decoration: none; cursor: pointer;">
      <div class="feature-icon">🟡</div>
      <h3 style="margin: 0;">Detection Engineer</h3>
      <p>ML-powered rules, fewer false positives</p>
      <span style="font-size: 0.75rem; color: var(--secondary);">Labs 01→03→07→09</span>
    </a>
    <a href="https://github.com/depalmar/ai_for_the_win/blob/main/resources/role-based-learning-paths.md#-red-team-path" class="feature" style="text-decoration: none; cursor: pointer;">
      <div class="feature-icon">🔴</div>
      <h3 style="margin: 0;">AI Red Team</h3>
      <p>Evade ML, attack AI systems</p>
      <span style="font-size: 0.75rem; color: var(--secondary);">Labs 03→17→20</span>
    </a>
  </div>

  <p style="text-align: center; margin-top: 1.5rem;">
    <a href="https://github.com/depalmar/ai_for_the_win/blob/main/resources/role-based-learning-paths.md" class="btn btn-secondary">View All 9 Role Paths</a>
  </p>
</div>

<div class="section" id="cost">
  <h2 class="section-title">Cost Breakdown</h2>

  <table class="cost-table">
    <thead>
      <tr>
        <th>Labs</th>
        <th>API Required</th>
        <th>Estimated Cost</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>00-03 (ML Foundations)</td>
        <td>No</td>
        <td class="free">Free</td>
      </tr>
      <tr>
        <td>04-07 (LLM Basics)</td>
        <td>Yes</td>
        <td>~$2-8</td>
      </tr>
      <tr>
        <td>08-10 (Advanced)</td>
        <td>Yes</td>
        <td>~$5-15</td>
      </tr>
      <tr>
        <td>11-20 (Expert)</td>
        <td>Yes</td>
        <td>~$10-25</td>
      </tr>
      <tr>
        <td><strong>With Ollama (local)</strong></td>
        <td>No</td>
        <td class="free">$0 Total</td>
      </tr>
    </tbody>
  </table>

  <div class="cta-buttons" style="margin-top: 2rem;">
    <a href="https://github.com/depalmar/ai_for_the_win/blob/main/docs/guides/api-keys-guide.md" class="btn btn-secondary">API Keys Setup Guide</a>
  </div>
</div>

<div class="section">
  <h2 class="section-title">Quick Start</h2>

  <div class="quick-start" style="margin-bottom: 1.5rem;">
    <h3 style="margin-top: 0; color: var(--secondary);">🚀 Option 1: Zero Setup (Colab)</h3>
    <p style="color: var(--text-muted); margin-bottom: 1rem;">Run labs directly in your browser — no installation needed!</p>
    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
      <a href="https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab01_phishing_classifier.ipynb" target="_blank" style="display: inline-block;"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open Lab 01"></a>
      <a href="https://colab.research.google.com/github/depalmar/ai_for_the_win/blob/main/notebooks/lab04_llm_log_analysis.ipynb" target="_blank" style="display: inline-block;"><img src="https://colab.research.google.com/assets/colab-badge.svg" alt="Open Lab 04"></a>
    </div>
    <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 1rem;">📓 <a href="https://github.com/depalmar/ai_for_the_win/tree/main/notebooks" style="color: var(--primary);">All 23 lab notebooks</a> available for Colab</p>
  </div>

  <div class="quick-start" style="margin-bottom: 1.5rem;">
    <h3 style="margin-top: 0; color: var(--secondary);">💻 Option 2: Local Setup</h3>
<pre><code># Clone and setup
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win
python -m venv venv
source venv/bin/activate  # Win: venv\Scripts\activate
pip install -r requirements.txt

# Run Lab 01 (no API key needed!)

python labs/lab01-phishing-classifier/solution/main.py</code></pre>

  </div>

  <div class="cta-buttons">
    <a href="https://github.com/depalmar/ai_for_the_win#get-started-in-5-minutes" class="btn btn-primary">Full Setup Instructions</a>
    <a href="https://github.com/depalmar/ai_for_the_win/tree/main/notebooks" class="btn btn-secondary">Browse All Notebooks</a>
  </div>
</div>

<div class="section" id="faq">
  <h2 class="section-title">Frequently Asked Questions</h2>
  <div class="faq">
    <details class="faq-item">
      <summary>Do I need prior ML/AI experience?</summary>
      <div class="faq-content">No. Labs 00a-00c cover Python basics, ML concepts, and prompt engineering from scratch. The Security-to-AI Glossary translates ML jargon into security terms you already know.</div>
    </details>
    <details class="faq-item">
      <summary>Which LLM provider should I use?</summary>
      <div class="faq-content">We recommend Anthropic Claude for best reasoning on security tasks. But all labs support OpenAI GPT-4, Google Gemini, and Ollama (free, local). You only need one.</div>
    </details>
    <details class="faq-item">
      <summary>Can I run everything locally without API costs?</summary>
      <div class="faq-content">Yes! Use Ollama to run models locally for free. Labs 01-03 don't need any API at all. You can complete the entire course for $0 if you use local models.</div>
    </details>
    <details class="faq-item">
      <summary>How long does it take to complete all labs?</summary>
      <div class="faq-content">The full course is approximately 40-89 hours depending on AI assistance level. With AI coding tools, most labs take 50-70% less time. Focus on your role's learning path first (~5-18 hours) for immediate value.</div>
    </details>
    <details class="faq-item">
      <summary>What if I get stuck on a lab?</summary>
      <div class="faq-content">Every lab includes complete solution code, step-by-step hints, and a Colab notebook you can run in your browser. Check GitHub Discussions for community help or open an issue.</div>
    </details>
    <details class="faq-item">
      <summary>Are the labs production-ready?</summary>
      <div class="faq-content">The solutions demonstrate core concepts. For production use, you'd add error handling, logging, and scale considerations. Lab 09 (Detection Pipeline) shows production architecture patterns.</div>
    </details>
    <details class="faq-item">
      <summary>How is this different from other ML courses?</summary>
      <div class="faq-content">Every lab solves a real security problem. You won't build iris classifiers or digit recognizers. You'll build phishing detectors, threat intel agents, and ransomware analyzers.</div>
    </details>
  </div>
</div>

<div class="section" style="border-bottom: none;">
  <h2 class="section-title">Resources</h2>

  <div class="features">
    <div class="feature">
      <div class="feature-icon">&#128218;</div>
      <h3><a href="https://github.com/depalmar/ai_for_the_win/blob/main/resources/security-to-ai-glossary.md">Security-to-AI Glossary</a></h3>
      <p>ML terms explained using security analogies</p>
    </div>
    <div class="feature">
      <div class="feature-icon">&#128506;</div>
      <h3><a href="https://github.com/depalmar/ai_for_the_win/blob/main/resources/role-based-learning-paths.md">Learning Paths</a></h3>
      <p>Curated paths for 9 security roles</p>
    </div>
    <div class="feature">
      <div class="feature-icon">&#128273;</div>
      <h3><a href="https://github.com/depalmar/ai_for_the_win/blob/main/docs/guides/api-keys-guide.md">API Keys Guide</a></h3>
      <p>Setup and cost management</p>
    </div>
    <div class="feature">
      <div class="feature-icon">&#128211;</div>
      <h3><a href="https://github.com/depalmar/ai_for_the_win/blob/main/docs/guides/jupyter-basics-guide.md">Jupyter Basics</a></h3>
      <p>Local notebook setup guide</p>
    </div>
    <div class="feature">
      <div class="feature-icon">☁️</div>
      <h3><a href="https://github.com/depalmar/ai_for_the_win/blob/main/docs/guides/colab-guide.md">Google Colab Guide</a></h3>
      <p>Zero-setup browser notebooks</p>
    </div>
  </div>
</div>

<div class="cta-buttons" style="margin: 2rem 0;">
  <a href="https://github.com/depalmar/ai_for_the_win#get-started-in-5-minutes" class="btn btn-primary">Get Started</a>
  <a href="https://github.com/depalmar/ai_for_the_win" class="btn btn-secondary">Star on GitHub</a>
</div>

<div class="footer-links">
  <a href="https://github.com/depalmar/ai_for_the_win">GitHub</a>
  <a href="https://github.com/depalmar/ai_for_the_win/discussions">Discussions</a>
  <a href="https://github.com/depalmar/ai_for_the_win/issues">Issues</a>
  <a href="https://github.com/depalmar/ai_for_the_win/releases">Releases</a>
</div>

<p style="text-align: center; color: var(--text-muted); font-size: 0.85rem;">
  MIT License | Built for security practitioners | Created by <a href="https://www.linkedin.com/in/raymond-depalma" style="color: var(--text-muted); text-decoration: underline;">Raymond DePalma</a>
</p>

<p style="text-align: center; color: var(--text-muted); font-size: 0.75rem; margin-top: 1rem; max-width: 600px; margin-left: auto; margin-right: auto;">
  <em>Disclaimer: This is a personal educational project created on personal time. It is not affiliated with, endorsed by, or sponsored by any employer or vendor. All tool references are for educational purposes only.</em>
</p>
