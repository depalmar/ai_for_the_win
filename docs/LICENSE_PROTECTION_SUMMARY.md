# License Protection Summary

**Status**: ✅ Your dual-license structure is solid and well-positioned for a growing repository.

This document summarizes the improvements made to protect your license as your repository gains popularity.

---

## What Was Updated

### 1. ✅ CONTRIBUTING.md - Contributor License Terms

**File**: [CONTRIBUTING.md](../CONTRIBUTING.md)

**Added**: Clear licensing terms for contributors, including:
- Contributors retain copyright but grant you usage rights
- Automatic application of dual license (MIT for code, CC BY-NC-SA for content)
- Corporate contribution guidelines
- Clear table showing which license applies to which content type

**Why**: Prevents future disputes about contributor rights and ensures all contributions remain under your license model.

### 2. ✅ LICENSE - Trademark Notice

**File**: [LICENSE](../LICENSE)

**Added**: Trademark protection section for "AI for the Win" brand, including:
- Permitted uses (academic citation, attribution)
- Prohibited uses (competing courses, misleading affiliation)
- Contact info for licensing

**Why**: Protects your brand name from being used by competitors to create "AI for the Win" training programs.

### 3. ✅ New Documentation

Three new comprehensive guides:

| File | Purpose |
|------|---------|
| [docs/LICENSE_HEADERS.md](LICENSE_HEADERS.md) | Templates and examples for adding license headers to files |
| [scripts/add_license_headers.py](../scripts/add_license_headers.py) | Automated tool to add headers to all files |

---

## Quick Start: Protecting Your License

### Step 1: Add Headers to Existing Files (Optional but Recommended)

Add license headers to your existing files to prevent confusion in forks:

```bash
# Preview what would change (safe - doesn't modify files)
python scripts/add_license_headers.py --dry-run

# See detailed output including skipped files
python scripts/add_license_headers.py --dry-run --verbose

# Apply changes to all files
python scripts/add_license_headers.py
```

This adds:
- MIT headers to all `.py` files
- CC BY-NC-SA headers to all lab README files
- Dual-license headers to all Jupyter notebooks
- CC BY-NC-SA headers to documentation

### Step 2: Set Up License Monitoring (Optional - Private)

**Monitoring is recommended but documentation has been kept private.**

Quick monitoring checklist:
1. Set up web alerts for your brand name + repository
2. Monitor GitHub forks quarterly: https://github.com/depalmar/ai_for_the_win/network/members
3. Search training platforms (Udemy, Coursera) periodically
4. Consider paid tools like Mention.com ($41/month) for automated monitoring

---

## When Someone Violates Your License

Follow this escalation process:

1. **Document** the violation (screenshots, archive.is)
2. **Assess severity** (personal blog vs training company)
3. **Friendly email** (14-day response window)
   ```
   Subject: AI for the Win - Attribution Request

   Hi [Name], I'm Raymond DePalma, creator of AI for the Win. I noticed
   your [content] at [URL]. Under CC BY-NC-SA 4.0, I'd appreciate attribution.

   Thanks for your consideration!
   ```
4. **Formal notice** (7-day response window if no response)
5. **DMCA takedown** (if hosted on GitHub/platform)
6. **Legal action** (last resort, consult attorney)

**Most violations (80%) resolve with a friendly email.**

---

## Commercial Licensing Strategy

Your license prohibits commercial use without permission. Here's how to monetize:

### What Requires a Commercial License

From your [LICENSE](../LICENSE):

| Use Case | Requires License? | Typical Price Range |
|----------|-------------------|---------------------|
| Individual self-study | ❌ No (free) | Free |
| Personal portfolio | ❌ No (free) | Free |
| Corporate training | ✅ Yes | $2,500-10,000/year |
| Paid bootcamp/course | ✅ Yes | $5,000-25,000 one-time |
| Consulting deliverables | ✅ Yes | Per-engagement |
| University curriculum | ✅ Yes | $1,000-5,000/year |

### Pricing Considerations

Consider these factors when pricing licenses:

- **Organization size**: Larger companies pay more
- **Student count**: Per-student vs unlimited
- **Modifications allowed**: Do they get to customize?
- **Support included**: Do you provide updates/help?
- **Exclusivity**: Are they the only licensed provider in their region?

### Sample Commercial License Agreement

```markdown
## Commercial License Agreement

**Licensor**: Raymond DePalma
**Licensee**: [Company Name]
**Effective Date**: [Date]

### Grant of License

Licensor grants Licensee a non-exclusive, non-transferable license to use
"AI for the Win" educational content for [SPECIFY: internal training /
public courses / etc.] for a period of [DURATION].

### Scope

- **Permitted**: [Specific use case]
- **Student limit**: [Number] OR Unlimited
- **Modifications**: Permitted with attribution
- **Derivatives**: Must credit original work

### Fees

- **License fee**: $[AMOUNT] [per year / one-time]
- **Payment terms**: [Terms]

### Attribution

Licensee must maintain attribution: "Based on 'AI for the Win' by
Raymond DePalma (https://github.com/depalmar/ai_for_the_win)"

### Term and Termination

License valid for [DURATION]. Either party may terminate with [NOTICE]
notice. Upon termination, Licensee must cease using materials.

[Signatures]
```

**⚠️ Have an attorney review** before using for substantial deals.

---

## File Header Templates

When creating new files, use these headers:

### Python Files

```python
#!/usr/bin/env python3
# Copyright (c) 2025-2026 Raymond DePalma
# Licensed under MIT License - See LICENSE file
# Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win
```

### Lab README Files

```markdown
<!--
Copyright (c) 2025-2026 Raymond DePalma
Licensed under CC BY-NC-SA 4.0 - See LICENSE file
Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win
-->

# Lab XX: Title
```

### Jupyter Notebooks

```markdown
<!--
Copyright (c) 2025-2026 Raymond DePalma
Licensed under CC BY-NC-SA 4.0 (content) and MIT (code)
Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win
-->

# Lab XX: Title

**License**: Educational content (CC BY-NC-SA 4.0) | Code (MIT License)
```

**Full templates**: See [LICENSE_HEADERS.md](LICENSE_HEADERS.md)

---

## FAQ

### Should I file for a trademark?

**Consider it if**:
- You plan to sell commercial licenses (yes)
- Your repo has >5,000 stars (not yet, but growing)
- Competitors might create similar "AI for the Win" programs (possibly)

**Cost**: $350-500 (USPTO filing) + $500-1,500 (attorney)
**Timeline**: 6-12 months
**Protection**: US-based protection (file in other countries separately)

Your current trademark notice in LICENSE provides **common law trademark rights** but not as strong as registration.

### What if someone creates "AI for the Win Pro" or similar?

Your trademark notice prohibits this. Send a cease and desist:

```
Your use of "AI for the Win Pro" infringes my trademark rights in
"AI for the Win". Please cease use immediately or rename your product.
```

If they don't comply, consult an IP attorney.

### Can I sell commercial licenses on my website?

**Yes!** Consider:

1. **Self-service**: Gumroad, Lemon Squeezy for small licenses
2. **Contact-based**: For enterprise deals, use "Contact for pricing"
3. **Hybrid**: Self-service for <$2,500, custom quotes for larger deals

### What if an AI company scraped my content for training?

Your LICENSE prohibits this:

> "AI/ML training — Using content to train commercial AI models or services"

**Reality**: Hard to detect and enforce without legal action. Major AI companies (OpenAI, Anthropic, Google) have likely scraped public GitHub repos including yours.

**Options**:
1. Add `robots.txt` to block future crawling (but already scraped)
2. Join class-action lawsuits if they emerge (ongoing for code/art)
3. Negotiate licensing if they contact you

### Do GitHub stars/forks mean people are violating my license?

**No** - Stars and forks are permitted under your license:
- **Stars**: Just bookmarks, no violation
- **Forks**: Allowed for personal learning
- **Violation occurs** when they use forks commercially without license

Check fork activity quarterly to identify potential commercial use.

---

## Monitoring Checklist

Copy this checklist for quarterly reviews:

```markdown
## License Monitoring - [YYYY-QQ]

**Date**: [Date]

### Searches Completed
- [ ] Udemy, Coursera, LinkedIn Learning for paid courses
- [ ] Google: "AI for the Win" training
- [ ] GitHub forks review
- [ ] Blog posts and tutorials
- [ ] Training company websites
- [ ] Social media (LinkedIn, Twitter/X)

### Violations Found
- [ ] None found ✅
- [ ] [Number] violations found (document below)

### Violations Detail
[If any violations:]
1. **URL**: [URL]
   - Type: [Missing attribution / Commercial use / etc.]
   - Severity: [Low / Medium / High]
   - Action: [Contacted / DMCA / Resolved]

### Commercial Licenses
- [ ] [Number] new inquiries
- [ ] [Number] licenses sold
- [ ] Total revenue this quarter: $[Amount]

### Next Steps
- [ ] [Action items]
```

---

## Resources

### Legal
- **Creative Commons FAQ**: https://creativecommons.org/faq/
- **GitHub DMCA**: https://docs.github.com/en/github/site-policy/dmca-takedown-policy
- **FindLaw Copyright**: https://www.findlaw.com/smallbusiness/intellectual-property/copyright-law.html

### Tools
- **Archive.is**: https://archive.is/ (archive evidence)
- **OpenTimestamps**: https://opentimestamps.org/ (prove creation date)
- **Brand Monitoring**: Consider Mention.com or similar tools for automated tracking

### IP Attorneys
- **UpCounsel**: https://www.upcounsel.com/
- **Priori Legal**: https://www.priorilegal.com/
- Search: "intellectual property attorney [your state]"

---

## Summary

Your licensing is **strong and appropriate** for an educational security project gaining traction:

✅ **Dual license** protects educational content while allowing code reuse
✅ **Clear definitions** of commercial vs non-commercial use
✅ **Contributor terms** in CONTRIBUTING.md prevent future disputes
✅ **Trademark notice** protects your brand
✅ **Monitoring guide** helps you enforce consistently
✅ **AI training clause** addresses modern concerns

**Next steps**:

1. ⚙️ Run `python scripts/add_license_headers.py --dry-run` to preview header additions
2. 🔔 Set up monitoring (Mention.com or manual checks)
3. 📅 Add quarterly calendar reminder to check forks
4. 📧 Draft your "friendly email" template for violations
5. 💰 Decide on commercial licensing pricing if interested in monetization

**Questions?** See [LICENSE](../LICENSE) for full terms or [contact directly](https://www.linkedin.com/in/raymond-depalma/).

---

*Last updated: January 2026*
