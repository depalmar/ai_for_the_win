---
layout: default
title: AI for the Win
---

<style>
:root {
  --primary: #6366f1;
  --secondary: #10b981;
  --accent: #f59e0b;
  --danger: #ef4444;
  --bg-dark: #0d1117;
  --bg-card: #161b22;
  --text: #c9d1d9;
  --text-muted: #8b949e;
  --border: #30363d;
}

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
}

.hero .tagline {
  font-size: 1.3rem;
  color: var(--text-muted);
  margin-bottom: 1.5rem;
}

.stats {
  display: flex;
  justify-content: center;
  gap: 2rem;
  flex-wrap: wrap;
  margin: 2rem 0;
}

.stat {
  text-align: center;
  padding: 1rem 1.5rem;
  background: var(--bg-card);
  border-radius: 8px;
  border: 1px solid var(--border);
}

.stat-number {
  font-size: 2rem;
  font-weight: bold;
  color: var(--primary);
}

.stat-label {
  font-size: 0.9rem;
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
}

.btn-primary {
  background: var(--primary);
  color: white;
}

.btn-primary:hover {
  background: #4f46e5;
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

.lab-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1rem;
  margin-top: 1.5rem;
}

.lab-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  transition: all 0.2s;
}

.lab-card:hover {
  border-color: var(--primary);
  transform: translateY(-2px);
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
}

.lab-desc {
  font-size: 0.85rem;
  color: var(--text-muted);
  margin: 0;
}

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
  padding: 1.25rem;
}

.path-card h3 {
  margin: 0 0 0.5rem;
  color: var(--text);
  font-size: 1.1rem;
}

.path-card p {
  font-size: 0.9rem;
  color: var(--text-muted);
  margin: 0 0 0.75rem;
}

.path-labs {
  font-size: 0.85rem;
  color: var(--primary);
}

.faq {
  margin-top: 1.5rem;
}

.faq-item {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 0.75rem;
  padding: 1rem 1.25rem;
}

.faq-item summary {
  cursor: pointer;
  font-weight: 600;
  color: var(--text);
}

.faq-item p {
  margin: 0.75rem 0 0;
  color: var(--text-muted);
  font-size: 0.9rem;
}

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

.quick-start code {
  color: var(--secondary);
}

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
</style>

<div class="hero">
  <h1>AI for the Win</h1>
  <p class="tagline">Build AI-Powered Security Tools | From Zero to Production</p>

  <div class="stats">
    <div class="stat">
      <div class="stat-number">25</div>
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
      <div class="stat-number">100%</div>
      <div class="stat-label">Open Source</div>
    </div>
  </div>

  <div class="cta-buttons">
    <a href="https://github.com/depalmar/ai_for_the_win#get-started-in-5-minutes" class="btn btn-primary">Get Started</a>
    <a href="https://github.com/depalmar/ai_for_the_win" class="btn btn-secondary">View on GitHub</a>
  </div>
</div>

<div class="section">
  <h2 class="section-title">Why AI for the Win?</h2>

  <div class="features">
    <div class="feature">
      <div class="feature-icon">🎯</div>
      <h3>Built for Security Practitioners</h3>
      <p>Not generic ML courses. Every lab solves real security problems: phishing, malware, C2 detection, incident response.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">🛠️</div>
      <h3>You Build Real Tools</h3>
      <p>No toy examples. Build classifiers, agents, RAG systems, and detection pipelines you can actually use.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">🚀</div>
      <h3>Vibe Coding Ready</h3>
      <p>Designed for AI-assisted development with Cursor, Claude Code, and Copilot. Learn the modern way.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">💰</div>
      <h3>Start Free</h3>
      <p>Labs 01-03 need no API key. Learn ML foundations before spending on LLM APIs. Ollama option for $0 total.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">🎓</div>
      <h3>Beginner Friendly</h3>
      <p>New to Python? Start at Lab 00. Security-to-AI glossary translates ML jargon into terms you know.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">🔬</div>
      <h3>839 Tests</h3>
      <p>Every lab has comprehensive tests. Know your code works before deploying. 100% pass rate.</p>
    </div>
  </div>
</div>

<div class="section">
  <h2 class="section-title">25 Labs: From Basics to Expert</h2>

  <div class="lab-grid">
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number">00</span>
        <span class="lab-title">Environment Setup</span>
      </div>
      <p class="lab-desc">Python, VS Code, virtual env, Jupyter</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number ml">01</span>
        <span class="lab-title">Phishing Classifier</span>
      </div>
      <p class="lab-desc">ML text classification, TF-IDF, Random Forest</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number ml">02</span>
        <span class="lab-title">Malware Clustering</span>
      </div>
      <p class="lab-desc">K-Means, DBSCAN, feature extraction</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number ml">03</span>
        <span class="lab-title">Anomaly Detection</span>
      </div>
      <p class="lab-desc">Isolation Forest, statistical baselines</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number llm">04</span>
        <span class="lab-title">LLM Log Analysis</span>
      </div>
      <p class="lab-desc">Prompt engineering, IOC extraction</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number llm">05</span>
        <span class="lab-title">Threat Intel Agent</span>
      </div>
      <p class="lab-desc">ReAct pattern, LangChain, autonomous investigation</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number llm">06</span>
        <span class="lab-title">Security RAG</span>
      </div>
      <p class="lab-desc">Vector embeddings, ChromaDB, doc Q&A</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number llm">07</span>
        <span class="lab-title">YARA Generator</span>
      </div>
      <p class="lab-desc">AI-assisted rule generation, validation</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number advanced">08</span>
        <span class="lab-title">Vuln Prioritizer</span>
      </div>
      <p class="lab-desc">CVSS scoring, risk-based prioritization</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number advanced">09</span>
        <span class="lab-title">Detection Pipeline</span>
      </div>
      <p class="lab-desc">Multi-stage ML + LLM architecture</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number advanced">10</span>
        <span class="lab-title">IR Copilot</span>
      </div>
      <p class="lab-desc">Conversational IR assistant, playbooks</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number dfir">11</span>
        <span class="lab-title">Ransomware Detection</span>
      </div>
      <p class="lab-desc">Entropy analysis, behavioral detection</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number dfir">12</span>
        <span class="lab-title">Purple Team Sim</span>
      </div>
      <p class="lab-desc">Safe adversary emulation, gap analysis</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number dfir">13</span>
        <span class="lab-title">Memory Forensics AI</span>
      </div>
      <p class="lab-desc">Volatility3, process injection, credentials</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number dfir">14</span>
        <span class="lab-title">C2 Traffic Analysis</span>
      </div>
      <p class="lab-desc">Beaconing, DNS tunneling, JA3</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number dfir">15</span>
        <span class="lab-title">Lateral Movement</span>
      </div>
      <p class="lab-desc">Auth anomalies, attack path graphs</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number dfir">16</span>
        <span class="lab-title">Threat Actor Profiling</span>
      </div>
      <p class="lab-desc">TTP extraction, campaign clustering</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number dfir">17</span>
        <span class="lab-title">Adversarial ML</span>
      </div>
      <p class="lab-desc">Evasion attacks, poisoning, defenses</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number dfir">18</span>
        <span class="lab-title">Fine-Tuning</span>
      </div>
      <p class="lab-desc">Custom embeddings, LoRA, deployment</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number dfir">19</span>
        <span class="lab-title">Cloud Security AI</span>
      </div>
      <p class="lab-desc">AWS/Azure/GCP, CloudTrail analysis</p>
    </div>
    <div class="lab-card">
      <div class="lab-header">
        <span class="lab-number dfir">20</span>
        <span class="lab-title">LLM Red Teaming</span>
      </div>
      <p class="lab-desc">Prompt injection, jailbreaks, guardrails</p>
    </div>
  </div>
</div>

<div class="section">
  <h2 class="section-title">Choose Your Learning Path</h2>

  <div class="path-grid">
    <div class="path-card">
      <h3>SOC Analyst</h3>
      <p>Automate alert triage, reduce fatigue, AI-assisted analysis</p>
      <div class="path-labs">Labs: 04 → 06 → 10</div>
    </div>
    <div class="path-card">
      <h3>Incident Responder</h3>
      <p>Faster investigations, automated evidence collection</p>
      <div class="path-labs">Labs: 04 → 10 → 11 → 13</div>
    </div>
    <div class="path-card">
      <h3>Threat Hunter</h3>
      <p>Find what rules miss, detect unknown threats</p>
      <div class="path-labs">Labs: 03 → 14 → 15 → 16</div>
    </div>
    <div class="path-card">
      <h3>Detection Engineer</h3>
      <p>ML-powered detection, fewer false positives</p>
      <div class="path-labs">Labs: 01 → 07 → 09</div>
    </div>
    <div class="path-card">
      <h3>Threat Intel Analyst</h3>
      <p>Automate IOC extraction, AI-powered reports</p>
      <div class="path-labs">Labs: 04 → 05 → 06 → 16</div>
    </div>
    <div class="path-card">
      <h3>Red Teamer</h3>
      <p>Evade ML detection, attack AI systems</p>
      <div class="path-labs">Labs: 03 → 17 → 20</div>
    </div>
  </div>

  <p style="text-align: center; margin-top: 1.5rem;">
    <a href="https://github.com/depalmar/ai_for_the_win/blob/main/resources/role-based-learning-paths.md" class="btn btn-secondary">View All 9 Learning Paths</a>
  </p>
</div>

<div class="section">
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
</div>

<div class="section">
  <h2 class="section-title">Quick Start</h2>

  <div class="quick-start">
<pre><code># Clone the repository
git clone https://github.com/depalmar/ai_for_the_win.git
cd ai_for_the_win

# Set up environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start with Lab 01 - no API key needed!
cd labs/lab01-phishing-classifier
python solution/main.py</code></pre>
  </div>
</div>

<div class="section">
  <h2 class="section-title">Frequently Asked Questions</h2>

  <div class="faq">
    <details class="faq-item">
      <summary>Do I need prior ML/AI experience?</summary>
      <p>No. Labs 00a-00c cover Python basics, ML concepts, and prompt engineering from scratch. The Security-to-AI Glossary translates ML jargon into security terms you already know.</p>
    </details>

    <details class="faq-item">
      <summary>Which LLM provider should I use?</summary>
      <p>We recommend Anthropic Claude for best reasoning on security tasks. But all labs support OpenAI GPT-4, Google Gemini, and Ollama (free, local). You only need one.</p>
    </details>

    <details class="faq-item">
      <summary>Can I run everything locally without API costs?</summary>
      <p>Yes! Use Ollama to run models locally for free. Labs 01-03 don't need any API at all. You can complete the entire course for $0 if you use local models.</p>
    </details>

    <details class="faq-item">
      <summary>What if I get stuck on a lab?</summary>
      <p>Every lab includes complete solution code, step-by-step hints, and a Jupyter notebook. Check GitHub Discussions for community help or open an issue.</p>
    </details>

    <details class="faq-item">
      <summary>Are the labs production-ready?</summary>
      <p>The solutions demonstrate core concepts. For production use, you'd add error handling, logging, and scale considerations. Lab 09 (Detection Pipeline) shows production architecture patterns.</p>
    </details>

    <details class="faq-item">
      <summary>How is this different from other ML courses?</summary>
      <p>Every lab solves a real security problem. You won't build iris classifiers or digit recognizers. You'll build phishing detectors, threat intel agents, and ransomware analyzers.</p>
    </details>
  </div>
</div>

<div class="section" style="border-bottom: none;">
  <h2 class="section-title">Resources</h2>

  <div class="features">
    <div class="feature">
      <div class="feature-icon">📚</div>
      <h3><a href="https://github.com/depalmar/ai_for_the_win/blob/main/resources/security-to-ai-glossary.md">Security-to-AI Glossary</a></h3>
      <p>ML terms explained using security analogies</p>
    </div>
    <div class="feature">
      <div class="feature-icon">🗺️</div>
      <h3><a href="https://github.com/depalmar/ai_for_the_win/blob/main/resources/role-based-learning-paths.md">Learning Paths</a></h3>
      <p>Curated paths for 9 security roles</p>
    </div>
    <div class="feature">
      <div class="feature-icon">🔑</div>
      <h3><a href="https://github.com/depalmar/ai_for_the_win/blob/main/setup/guides/api-keys-guide.md">API Keys Guide</a></h3>
      <p>Setup and cost management</p>
    </div>
    <div class="feature">
      <div class="feature-icon">📓</div>
      <h3><a href="https://github.com/depalmar/ai_for_the_win/blob/main/setup/guides/jupyter-basics-guide.md">Jupyter Basics</a></h3>
      <p>Notebook guide for security analysts</p>
    </div>
  </div>
</div>

<div class="footer-links">
  <a href="https://github.com/depalmar/ai_for_the_win">GitHub</a>
  <a href="https://github.com/depalmar/ai_for_the_win/discussions">Discussions</a>
  <a href="https://github.com/depalmar/ai_for_the_win/issues">Issues</a>
  <a href="https://github.com/depalmar/ai_for_the_win/releases">Releases</a>
</div>

<p style="text-align: center; color: var(--text-muted); font-size: 0.85rem;">
  MIT License | Built for security practitioners
</p>
