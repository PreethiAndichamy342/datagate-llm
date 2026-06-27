# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |

Only the latest patch release of the current minor version receives security fixes.

## How to Report a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities through GitHub's private security advisory feature:

1. Go to the repository on GitHub.
2. Click **Security** > **Advisories** > **Report a vulnerability**.
3. Fill in the details: affected version, steps to reproduce, and potential impact.

Your report will be visible only to maintainers until a fix is released.

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | 48 hours after receipt |
| Fix for `critical` severity | 7 days after acknowledgement |
| Fix for `high` severity | 14 days after acknowledgement |
| Fix for `medium` / `low` severity | Next scheduled release |

If a critical fix requires a coordinated disclosure, we will work with you on timing before publishing.

## Scope

### In Scope

- Regex patterns in the rule JSON files that can be exploited for ReDoS (catastrophic backtracking).
- Logic bugs in `engine.py` that cause the scanner to silently skip matches (false-negative bypass).
- Path traversal or arbitrary file read via `rules_dir` parameter.
- Any mechanism by which calling `scan()` could execute arbitrary code or make network requests.

### Out of Scope

- Accuracy issues (false positives or false negatives that are not security bypasses) — open a regular issue.
- Missing rules for a new data type — open a regular issue or pull request.
- Vulnerabilities in optional dependencies (`onnxruntime`) — report directly to those projects.
- Issues that require the attacker to already control the Python process or the rules directory.
