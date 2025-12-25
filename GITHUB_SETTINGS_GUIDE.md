# GitHub Repository Settings Configuration Guide

This guide covers the manual GitHub settings that need to be configured via the web interface to complete the repository security and automation setup.

## Quick Access

Repository Settings: `https://github.com/depalmar/ai_for_the_win/settings`

---

## 1. Branch Protection Rules ⚠️ CRITICAL

**Path:** Settings → Branches → Add rule

### Configure for `main` branch:

**Branch name pattern:** `main`

#### Protect matching branches:
- ✅ **Require a pull request before merging**
  - ✅ Require approvals: 1
  - ✅ Dismiss stale pull request approvals when new commits are pushed
  - ✅ Require review from Code Owners

- ✅ **Require status checks to pass before merging**
  - ✅ Require branches to be up to date before merging
  - **Required status checks** (add these):
    - `Lint`
    - `Test (3.11)`
    - `Security Scan`
    - `Documentation Check`
    - `CodeQL`

- ✅ **Require conversation resolution before merging**

- ✅ **Require signed commits** (optional but recommended)

- ✅ **Require linear history** (optional, keeps history clean)

- ✅ **Do not allow bypassing the above settings**

#### Rules applied to administrators:
- ✅ **Include administrators** (recommended)

#### Restrict who can push to matching branches:
- Leave empty (or restrict to specific teams if you add collaborators)

#### Allow force pushes:
- ❌ **Disabled** (IMPORTANT)

#### Allow deletions:
- ❌ **Disabled** (IMPORTANT)

**Click "Create" or "Save changes"**

---

## 2. Security & Analysis Features

**Path:** Settings → Code security and analysis

### Enable ALL of these:

#### Dependency graph
- ✅ **Enabled** (should already be on for public repos)

#### Dependabot alerts
- ✅ **Enable**
- Purpose: Get notified of vulnerabilities in dependencies

#### Dependabot security updates
- ✅ **Enable**
- Purpose: Automatic PRs to fix vulnerabilities

#### Grouped security updates
- ✅ **Enable**
- Purpose: Group related security updates into single PRs

#### Code scanning
- ✅ **Set up** → **CodeQL Analysis**
  - Select: Use existing workflow
  - The `.github/workflows/codeql.yml` file is already committed
  - Purpose: Automated code vulnerability scanning

#### Secret scanning
- ✅ **Enable**
- Purpose: Detect accidentally committed secrets
- Note: This is automatic for public repos but good to verify

#### Push protection
- ✅ **Enable**
- Purpose: Block pushes that contain secrets

**Click "Enable" for each feature**

---

## 3. GitHub Actions Settings

**Path:** Settings → Actions → General

### Actions permissions:
- ✅ **Allow all actions and reusable workflows** (current setting is fine)
- Alternative: **Allow select actions and reusable workflows** (more restrictive)

### Workflow permissions:
- ✅ Select: **Read repository contents and packages permissions**
- ✅ Check: **Allow GitHub Actions to create and approve pull requests**

### Fork pull request workflows:
- ✅ **Require approval for first-time contributors**
- Purpose: Security for community contributions

**Click "Save"**

---

## 4. Repository Topics

**Path:** Main repo page → About section (gear icon)

### Add these topics:

```
ai
machine-learning
cybersecurity
security
threat-detection
threat-intelligence
llm
langchain
anthropic-claude
security-training
hands-on-labs
ctf
malware-analysis
incident-response
vulnerability-assessment
anomaly-detection
ransomware
dfir
red-team
purple-team
siem
security-orchestration
mcp-server
python
jupyter-notebook
docker
```

**Click "Save changes"**

---

## 5. General Repository Settings

**Path:** Settings → General

### Features:
- ✅ **Wikis** (currently enabled - optional)
- ✅ **Issues** (currently enabled - KEEP)
- ✅ **Sponsorships** (optional)
- ✅ **Projects** (currently enabled - useful for roadmap)
- ❌ **Preserve this repository** (optional)

### Pull Requests:
- ✅ **Allow merge commits**
- ✅ **Allow squash merging** (DEFAULT - recommended)
  - Default: "Default commit message"
- ✅ **Allow rebase merging**
- ✅ **Always suggest updating pull request branches**
- ✅ **Allow auto-merge**
- ✅ **Automatically delete head branches** (RECOMMENDED - keeps repo clean)

### Archives:
- ❌ **Include Git LFS objects in archives** (not needed)

**Click "Update" or "Save"**

---

## 6. Notifications Settings (Optional)

**Path:** Settings → Notifications

### Email notifications:
Configure based on your preference:
- ✅ **Watching** repositories
- ✅ **Participating** in conversations
- ✅ **Dependabot alerts**
- ✅ **Actions workflow runs**

---

## 7. Secrets and Variables

**Path:** Settings → Secrets and variables → Actions

### Repository secrets (if needed):

Add these if you want to run integration tests in CI:

| Secret Name | Description | Required? |
|-------------|-------------|-----------|
| `ANTHROPIC_API_KEY` | Claude API key for integration tests | Optional |
| `OPENAI_API_KEY` | OpenAI API key for multi-provider tests | Optional |
| `CODECOV_TOKEN` | Codecov upload token | Optional |

**How to add:**
1. Click "New repository secret"
2. Name: `SECRET_NAME`
3. Value: `your-secret-value`
4. Click "Add secret"

---

## 8. Environments (Optional - for future)

**Path:** Settings → Environments

Useful if you want to add staging/production deployments later:

- **staging**: For testing releases
- **production**: For stable releases

Can add protection rules per environment.

---

## 9. Code Owners Verification

**Path:** Insights → Community → Code owners

After committing `.github/CODEOWNERS`:
- Verify it shows up here
- Check syntax is correct
- Test by opening a PR

---

## 10. Security Policy Verification

**Path:** Security tab

After committing `SECURITY.md`:
- Click "Security" tab
- Should show "Security policy defined"
- Verify "Report a vulnerability" button works

---

## 11. Repository Description & Website

**Path:** Main repo page → About section (gear icon)

### Description (current):
```
Complete AI-powered security training program with 22 hands-on labs,
15 CTF challenges, and enterprise integrations. Learn ML-based threat
detection, LLM security analysis, adversarial ML, and cloud security.
From beginner to expert.
```

### Website (optional):
- Add documentation site URL if you create one
- Or link to GitHub Pages

### Social preview image (optional):
- Upload a banner/logo image
- Recommended size: 1280×640px

---

## 12. Collaborators & Teams (if applicable)

**Path:** Settings → Collaborators and teams

If you add contributors:
- Add with appropriate permissions (Read, Triage, Write, Maintain, Admin)
- CODEOWNERS will auto-request reviews
- Branch protection will require their approvals

---

## Verification Checklist

After completing all settings:

### Security:
- [ ] Branch protection enabled on `main`
- [ ] Dependabot alerts enabled
- [ ] Dependabot security updates enabled
- [ ] CodeQL scanning enabled
- [ ] Secret scanning enabled
- [ ] Push protection enabled

### Repository:
- [ ] Topics added
- [ ] Description updated
- [ ] Auto-delete head branches enabled
- [ ] Squash merging set as default

### Actions:
- [ ] Workflow permissions configured
- [ ] Require approval for first-time contributors

### Files:
- [ ] `SECURITY.md` visible in Security tab
- [ ] `CODEOWNERS` visible in Insights
- [ ] All workflows showing in Actions tab

---

## Testing the Setup

### Test Branch Protection:
1. Create a new branch: `git checkout -b test-protection`
2. Make a small change
3. Push and create PR
4. Verify you cannot merge without:
   - CI passing
   - Review approval
5. Delete test branch

### Test Security Scanning:
1. Try to commit a fake API key
2. Push protection should block it
3. If not blocked, secret scanning should detect it

### Test Dependabot:
1. Check "Security" → "Dependabot alerts"
2. Should see any vulnerable dependencies
3. Dependabot should create PRs automatically

---

## Maintenance

### Weekly:
- Review Dependabot PRs
- Check Security alerts

### Monthly:
- Review stale issues/PRs
- Update protection rules if needed
- Review and merge grouped Dependabot updates

### Quarterly:
- Audit access permissions
- Review and update SECURITY.md
- Check CodeQL scan results

---

## Troubleshooting

### Branch protection not working:
- Verify status check names match exactly
- Ensure required checks are running in CI
- Check if administrator bypass is enabled

### Dependabot PRs not appearing:
- Verify Dependabot is enabled in Settings
- Check `.github/dependabot.yml` syntax
- May take up to 24 hours initially

### CodeQL not running:
- Check `.github/workflows/codeql.yml` exists
- Verify workflow permissions in Settings
- Check Actions tab for errors

---

## Additional Resources

- [GitHub Branch Protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches)
- [GitHub Security Features](https://docs.github.com/en/code-security)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Dependabot Configuration](https://docs.github.com/en/code-security/dependabot)

---

**Last Updated**: December 2025
**Next Review**: March 2026
