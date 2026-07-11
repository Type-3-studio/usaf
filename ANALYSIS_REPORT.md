# USAF Analysis Report

**Date:** 2026-07-11
**Scan Report:** `reports/usaf-report-20260711_232507.txt`
**Initial Score:** 6.72/10 (Grade D)
**Total Findings:** 7,541

---

## Executive Summary

The USAF security audit produced 7,541 findings, but **96% came from just 2 categories** (FILESYSTEM: 6,435, PERMISSIONS: 817). The overall score of 6.72 (D) was unreliable because the scoring formula was mathematically broken (non-monotonic). A single check (FS-403 Orphaned Files) accounted for **4,370 findings (58% of total)**.

This report documents the root cause analysis and the 12 fixes implemented to address these issues at the architectural level.

---

## Root Cause Analysis

### Issue 1: Scoring Formula Non-Monotonic (CRITICAL)

**File:** `src/usaf/scoring/engine.py:124-126`

The formula was:
```python
normalized = min(10.0, total_penalty / max(1, total_findings) * (1.0 + total_findings * 0.1))
```

This **divided by the finding count** then multiplied by a density factor. The result was that adding more lower-severity findings **improved** the score:

| Scenario | Old Formula | Expected |
|---|---|---|
| 1 CRITICAL finding | **10.0** | 10.0 |
| 1 CRITICAL + 1 HIGH | **9.6** (lower = better??) | Should stay ≥ 10.0 |
| 1 CRITICAL + 1 LOW | **6.45** (lower = better??) | Should stay ≥ 10.0 |

Additionally, any category with at least 1 CRITICAL finding was pegged at 10.0, eliminating dynamic range.

**Fix:** Replaced with a monotonic formula:
```python
density_factor = 1.0 + 0.05 * log2(1.0 + total_findings)
normalized = min(10.0, total_penalty * density_factor)
```
- Score only ever increases (gets worse) as findings are added
- log2 density factor prevents unbounded growth from thousands of noise findings
- Natural dynamic range across all severity levels

---

### Issue 2: FS-403 Orphaned Files Produced 58% of All Findings (CRITICAL)

**File:** `src/usaf/checks/filesystem/checks.py:656-736`

**Root causes:**
1. Aggregated 3 data sources: `etc_snapshots`, `path_executables`, **and** `world_writable` (the biggest offender)
2. Only 3 prefix exclusions: flatpak, snapd, snap
3. No `max_findings` cap
4. The collector (`walker.py:94-129`) had **no file limit** on `_find_world_writable()`

**Fixes applied:**
1. Removed `world_writable` from data sources (these are inherently full of unowned files)
2. Added broad prefix exclusions: `/var/log/`, `/var/cache/`, `/var/tmp/`, `/tmp/`, `/var/lib/*`, `/var/spool/`, `/var/backups/`, etc.
3. Set `max_findings = 500` with truncation notification

---

### Issue 3: Correlation Engine Silently Swallows Exceptions (CRITICAL)

**File:** `src/usaf/correlation/engine.py:127-128`

```python
except Exception:
    pass
```

Any crash in any correlation rule was completely invisible. If `RogueServiceDeployment.evaluate()` raised an exception, no error was logged, no warning printed — the rule was just silently dropped.

**Fix:** Added logging via `logging.getLogger("usaf.correlation")`:
```python
except Exception as e:
    logger.warning("Correlation rule '%s' failed: %s", rule_id, e, exc_info=True)
```

---

### Issue 4: FileIntegrityBreach Always Fired (CRITICAL)

**File:** `src/usaf/correlation/rules.py:858-867`

The rule checked `combined_count < 2` across all finding types. Since FS-403 alone produced 4,370 findings, `combined_count >= 2` was **always true**, making this correlated finding useless noise on every scan.

**Fix:** Require at least **2 different check ID prefixes**:
```python
categories = set()
if orphaned: categories.add("FS-403")
if symlinks: categories.add("FS-301")
# ... etc
if len(categories) < 2:
    return []
```

---

### Issue 5-12: Additional Issues Found and Fixed

| # | Issue | File | Severity | Fix |
|---|---|---|---|---|
| 5 | No `max_findings` safety valve | `core/plugin.py` | HIGH | Added `max_findings: int = 0` with automatic truncation and summary finding |
| 6 | RogueServiceDeployment fires on 1 weak indicator | `correlation/rules.py:792-798` | HIGH | Now CRITICAL requires 3 indicators, HIGH for 2 |
| 7 | SupplyChainAttack ignored tampering without unknown repos | `correlation/rules.py:596-597` | HIGH | Allow `broken_sigs + modified_files >= 2` as alternative trigger |
| 8 | FS-201: 1,646 hidden file findings with no allowlist | `checks/filesystem/checks.py:218-273` | HIGH | Added `_KNOWN_SAFE_HIDDEN_NAMES` and `_KNOWN_SAFE_HIDDEN_PREFIXES`, set `max_findings=200` |
| 9 | Registry silently skips import errors | `core/registry.py:156-157` | HIGH | Added logging for failed module imports |
| 10 | Runner loses check category on errors | `core/runner.py` | HIGH | Added `_get_check_category()` to preserve actual category |
| 11 | FS-301: No allowlist for known system symlinks | `checks/filesystem/checks.py:353-409` | MEDIUM | Added `_KNOWN_SAFE_SYMLINKS` for /etc/localtime, resolv.conf, etc. |
| 12 | FS-402: Only 5 world-writable exceptions | `checks/filesystem/checks.py:620-686` | MEDIUM | Added prefix exclusions for /proc/, /sys/, /run/, set `max_findings=200` |
| — | Duplicate `_is_ssh_port` condition | `correlation/rules.py:100-103` | LOW | Removed copy-paste duplicate |
| — | Config: Added `ignore_paths` and `max_findings` override | `config/model.py` | MEDIUM | Path-based glob filtering in `_apply_ignore_list()` |

---

## Files Modified

| File | Changes |
|---|---|
| `src/usaf/scoring/engine.py` | Replaced non-monotonic scoring formula with monotonic log-based formula |
| `src/usaf/core/plugin.py` | Added `max_findings` with truncation logic in `evaluate()`, changed `ClassVar` to instance attributes |
| `src/usaf/core/runner.py` | Added `_get_check_category()`, preserved category on errors, added `ignore_paths` support, config override application |
| `src/usaf/core/registry.py` | Added logging for module import failures |
| `src/usaf/correlation/engine.py` | Added `logging.getLogger()`, replaced `except Exception: pass` with logged warning |
| `src/usaf/correlation/rules.py` | Fixed FileIntegrityBreach (2+ categories), RogueServiceDeployment (2+ indicators), SupplyChainAttack (no unknown repos needed), removed duplicate `_is_ssh_port` |
| `src/usaf/checks/filesystem/checks.py` | FS-201: allowlist; FS-301: allowlist; FS-402: more exceptions; FS-403: more exclusions, removed world_writable, max_findings |
| `src/usaf/config/model.py` | Added `max_findings` to `PluginOverride`, added `ignore_paths` to `USAFConfig` |
| `tests/unit/checks/test_filesystem_checks.py` | Updated FS-403 test to reflect removed world_writable source |

---

## Verification

- **All 902 tests pass** — no regressions
- **mypy clean** on all modified files — no type errors
- **ruff clean** on all modified files — no lint errors

---

## Expected Impact on Next Scan

| Metric | Before | Expected After |
|---|---|---|
| Total findings | 7,541 | ~500–800 |
| FS-403 findings | 4,370 (58%) | ~50–200 |
| FS-201 findings | ~1,646 | ~50–100 (with allowlist) |
| FS-402 findings | ~800 | ~50–100 (with more exceptions) |
| FS-301 findings | ~8 | ~0-1 (most are known-safe symlinks) |
| Critical findings | 3 | 0-2 (FileIntegrityBreach won't always fire) |
| Score usability | Broken (non-monotonic) | Correct (monotonic) |
| Silent failures | 3 locations | 0 (all logged) |

---

## Architectural Recommendations (Future)

1. **Enable baseline drift detection by default** — change `baseline.compare` default to `true`
2. **Ship default config** with high-FP checks pre-limited as `usaf.yaml`
3. **Add deduplication summary** for checks that exceed `max_findings` — currently shows count, could show summary by path prefix
4. **Monitor correlation rule output quality** — add telemetry on FP rate per rule
5. **Add CI benchmark** with known-good system profile to detect scoring regressions
