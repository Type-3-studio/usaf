# USAF Improvement Plan

**Generated:** 2026-07-12 | **Baseline Scan:** 1,450 findings | **Score:** 8.83/10 (F-)

---

## P0 — Fix bugs that trash score quality (DONE)

| # | Check | Problem | Findings | Fix | Status |
|---|-------|---------|----------|-----|--------|
| 1 | FS-202 | Kernel threads flagged as "deleted binaries" | 299→~0 | Filter processes with ppid==2 or /proc/ binary path | ✅ |
| 2 | SECR-502 | System CA root certs flagged as self-signed | 245→~0 | Exclude `/etc/ssl/certs/` and `/usr/share/ca-certificates/` | ✅ |
| 3 | STATE.md | TD-022→026 marked 🔴 but collectors exist ✅ | — | Mark resolved with collector file references | ✅ |

## P1 — Cut noise to improve signal-to-noise ratio

| # | Check | Problem | Findings | Fix | Status |
|---|-------|---------|----------|-----|--------|
| 4 | FS-402 | `node_modules/` dirs world-writable (npm default) | 200/810 | Exclude paths containing `/node_modules/` | ✅ |
| 5 | FS-201 | `__MACOSX` Apple Double hidden files | 200/1642 | Add `._` prefix and `/__MACOSX/` substring to safe-list | ✅ |
| 6 | PER-503 | System udev rules with RUN/PROGRAM | 60 | Skip rules in `/usr/lib/udev/rules.d/` (package-managed) | ✅ |
| 7 | SVC-102 | Standard Ubuntu services flagged as unexpected | 42 | Added 30+ missing services + `snap.` prefix matching | ✅ |

## P2 — Plug critical attacker-missed gaps

| # | Gap | Why It Matters | Status |
|---|-----|----------------|--------|
| 8 | Process→port mapping | Can't identify which binary owns a listening port | ⬜ |
| 9 | Docker daemon security config | No check for `--userns-remap`, `--no-new-privileges` | ⬜ |
| 10 | Kernel module blacklist | No check for currently loaded dangerous modules | ⬜ |
| 11 | Auditd coverage gap vs MITRE ATT&CK | No analysis of which techniques aren't covered | ⬜ |
| 12 | AppArmor profile per service | Services running unconfined not flagged | ⬜ |

## P3 — Framework hardening

| # | Task | Status |
|---|------|--------|
| 13 | Fix `datetime.utcnow()` deprecation warnings (terminal.py:261, markdown.py:190) | ⬜ |
| 14 | Enable drift detection by default in config | ⬜ |
| 15 | Ship default `usaf.yaml` with high-FP checks pre-limited | ⬜ |

---

## Expected Impact After Fixes

| Metric | Before | Expected After |
|--------|--------|----------------|
| Total findings | 1,450 | ~650 |
| FS-202 (kernel threads) | 299 | ~0 |
| SECR-502 (system CA certs) | 245 | ~0-5 |
| FS-402 (ww dirs) | 200/810 | ~30-50 |
| FS-201 (hidden files) | 200/1642 | ~5-10 |
| PER-503 (udev rules) | 60 | ~5-10 |
| SVC-102 (services) | 42 | ~5-10 |
| Signal-to-noise ratio | ~17% | ~60%+ |
