# License Headers Reference

This document provides license header templates for different file types in the AI for the Win project.

## When to Add Headers

Add license headers to:
- ✅ All lab README files
- ✅ All Python scripts and modules
- ✅ All Jupyter notebooks
- ✅ Documentation guides
- ❌ Data files, config files, or generated content

---

## Lab README.md Files (Educational Content)

Add at the **top** of every `labs/labXX-*/README.md`:

```markdown
<!--
Copyright (c) 2025-2026 Raymond DePalma
"AI for the Win" - https://github.com/depalmar/ai_for_the_win

This lab is licensed under CC BY-NC-SA 4.0.
For commercial use, contact: https://www.linkedin.com/in/raymond-depalma/
-->

# Lab XX: Title
```

**With badge** (recommended for high-visibility labs):

```markdown
<!--
Copyright (c) 2025-2026 Raymond DePalma
Licensed under CC BY-NC-SA 4.0 - See LICENSE file
-->

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

# Lab XX: Title
```

---

## Python Code Files (MIT License)

Add at the **top** of all `.py` files in `starter/`, `solution/`, `scripts/`:

```python
#!/usr/bin/env python3
"""
Brief description of what this script does.
"""
# Copyright (c) 2025-2026 Raymond DePalma
# Licensed under MIT License - See LICENSE file for full text
# Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win

import os
import sys
```

**For complex scripts** (with SPDX identifier):

```python
#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Raymond DePalma
"""
Lab XX: Description of functionality

This script demonstrates [key concept] for security analysis.

Usage:
    python main.py --input logs.csv --output results.json

License: MIT - See LICENSE file
Repository: https://github.com/depalmar/ai_for_the_win
"""

import os
import sys
```

---

## Jupyter Notebooks (.ipynb)

Add as the **first markdown cell** in every notebook:

```markdown
<!--
Copyright (c) 2025-2026 Raymond DePalma
Licensed under CC BY-NC-SA 4.0 (content) and MIT (code)
Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win
-->

# Lab XX: Title

**License**: Educational content (CC BY-NC-SA 4.0) | Code (MIT License)
**Repository**: [AI for the Win](https://github.com/depalmar/ai_for_the_win)
**Commercial Use**: Contact [Raymond DePalma](https://www.linkedin.com/in/raymond-depalma/)
```

**Quick version** (minimal):

```markdown
<!--
© 2025-2026 Raymond DePalma | CC BY-NC-SA 4.0 (content) + MIT (code)
https://github.com/depalmar/ai_for_the_win
-->

# Lab XX: Title
```

---

## Documentation Files (docs/guides/*.md)

Add at the **top** of documentation:

```markdown
<!--
Copyright (c) 2025-2026 Raymond DePalma
Licensed under CC BY-NC-SA 4.0
Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win
-->

# Guide Title
```

---

## Shell Scripts (.sh, .bash)

```bash
#!/bin/bash
# Copyright (c) 2025-2026 Raymond DePalma
# Licensed under MIT License - See LICENSE file
# Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win

set -e
```

---

## Configuration Files (Optional)

For YAML/JSON config files, licensing is optional but can be added:

```yaml
# Copyright (c) 2025-2026 Raymond DePalma
# MIT License - https://github.com/depalmar/ai_for_the_win/blob/main/LICENSE

version: "3"
services:
  ...
```

---

## Quick Reference Table

| File Type | Header Required? | License | Template |
|-----------|-----------------|---------|----------|
| Lab README.md | ✅ Yes | CC BY-NC-SA 4.0 | See "Lab README" above |
| Python (.py) | ✅ Yes | MIT | See "Python Code" above |
| Jupyter (.ipynb) | ✅ Yes | Dual (CC + MIT) | See "Jupyter Notebooks" above |
| Documentation (.md) | ✅ Yes | CC BY-NC-SA 4.0 | See "Documentation" above |
| Shell scripts (.sh) | ✅ Yes | MIT | See "Shell Scripts" above |
| Config files | ⚠️ Optional | MIT | See "Configuration" above |
| Data files (.csv, .json) | ❌ No | N/A | No header needed |
| Test files (tests/) | ✅ Yes | MIT | Same as Python code |

---

## Batch Adding Headers

### Find files missing headers

```bash
# Find Python files without license headers
find labs/ -name "*.py" -type f -exec grep -L "Copyright.*Raymond DePalma" {} \;

# Find lab READMEs without headers
find labs/ -name "README.md" -type f -exec grep -L "Copyright.*Raymond DePalma" {} \;
```

### Add headers to multiple files

Create a script `scripts/add_headers.py`:

```python
#!/usr/bin/env python3
"""Add license headers to files missing them."""
import os
from pathlib import Path

PYTHON_HEADER = '''#!/usr/bin/env python3
# Copyright (c) 2025-2026 Raymond DePalma
# Licensed under MIT License - See LICENSE file
# Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win

'''

MARKDOWN_HEADER = '''<!--
Copyright (c) 2025-2026 Raymond DePalma
Licensed under CC BY-NC-SA 4.0 - See LICENSE file
Part of "AI for the Win" - https://github.com/depalmar/ai_for_the_win
-->

'''

def add_header_if_missing(file_path, header):
    """Add header to file if it doesn't already have one."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    if 'Copyright' in content and 'Raymond DePalma' in content:
        print(f"  ✓ Already has header: {file_path}")
        return

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(header + content)

    print(f"  + Added header: {file_path}")

# Add headers to Python files
for py_file in Path('labs').rglob('*.py'):
    if 'venv' not in str(py_file) and '__pycache__' not in str(py_file):
        add_header_if_missing(py_file, PYTHON_HEADER)

# Add headers to README files
for readme in Path('labs').rglob('README.md'):
    add_header_if_missing(readme, MARKDOWN_HEADER)
```

---

## Attribution Examples

When others use your content (shows them how to properly attribute):

### For Blog Posts

```markdown
> This analysis is based on techniques from [Lab 31: Ransomware Detection](https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab31-ransomware-detection)
> by Raymond DePalma, licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).
> I modified the entropy calculation to include file header analysis.
```

### For Derivative Works

```markdown
# My Custom Lab (Based on AI for the Win)

This lab is adapted from [Lab 10: Phishing Classifier](https://github.com/depalmar/ai_for_the_win/tree/main/labs/lab10-phishing-classifier)
by Raymond DePalma.

**Original work**: Copyright © 2025-2026 Raymond DePalma, [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)
**Modifications**: Added SMS phishing detection, expanded feature set
**License**: CC BY-NC-SA 4.0 (same as original)
```

### For Forks

Add to forked README:

```markdown
---

**This is a fork of [AI for the Win](https://github.com/depalmar/ai_for_the_win) by Raymond DePalma.**

Original content licensed under CC BY-NC-SA 4.0 (educational content) and MIT License (code).
See [LICENSE](./LICENSE) file for full terms.

For commercial use of educational content, contact [Raymond DePalma](https://www.linkedin.com/in/raymond-depalma/).

---
```

---

## Enforcement Checklist

Use this checklist when you discover unauthorized use:

- [ ] Document the violation (screenshots, URLs, dates)
- [ ] Determine if use is truly commercial (check "Definitions" in LICENSE)
- [ ] Send friendly initial contact: "Hey, I noticed you're using my material..."
- [ ] If no response in 14 days, send formal DMCA notice
- [ ] For serious violations, consult IP attorney

**Template initial contact**:

> Hi [Name],
>
> I noticed you're using material from my "AI for the Win" project in [location]. I'm glad you found it useful!
>
> The educational content is licensed under CC BY-NC-SA 4.0, which requires attribution and prohibits commercial use without a license. [Describe the issue: missing attribution / commercial use / etc.]
>
> Could we discuss how to resolve this? I offer commercial licenses for [training programs / corporate use / etc.].
>
> Thanks,
> Raymond

---

## Questions?

- **Licensing questions**: Open a [GitHub Discussion](https://github.com/depalmar/ai_for_the_win/discussions)
- **Commercial licensing**: Contact [Raymond DePalma](https://www.linkedin.com/in/raymond-depalma/)
- **Violations**: Email directly (do not open public issue)
