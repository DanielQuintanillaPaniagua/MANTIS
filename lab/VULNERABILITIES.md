# MK-002 — Planted vulnerabilities

This lab is intentionally vulnerable. Each vulnerability is isolated,
documented, and reproducible. MANTIS must detect exactly these three
cases in MK-005. No more, no less.

The **correct** behavior lives in git:

```bash
git show HEAD~1:lab/routes/invoices.py