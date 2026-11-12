# Developer Code Quality Checker

Reconstructed from the portfolio's Nokia static-checking tool: a 48-regex rule catalog used by 120+ developers, with a reported 60% reduction in manual review time. This clean-room rule set is illustrative and does not claim to reproduce the original regexes, internal codebase, adoption, or measured impact.

## Run

`python3 checker.py PATH [--fail-on-high]` scans Python, C/C++, JavaScript, and TypeScript text files. Findings include rule ID, severity, source location, and a short explanation. Patterns are intentionally visible in `checker.py`; review false positives before using results as a gate. It is a lightweight heuristic, not a replacement for human review or a security scanner.

## Verify

`python3 -m unittest -v`
