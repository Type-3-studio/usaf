# ADR 006: Scoring Engine

## Status
Accepted

## Context
Security findings need prioritization. A flat list of issues is not actionable. Users need to understand overall posture, category-level risks, and which findings to address first.

## Decision

### Scoring Model

```
Overall Score: 0.0 (perfect) - 10.0 (worst)
    |
    +-- Category Scores (weighted averages)
         |
         +-- Finding Scores (individual)
```

### Finding Score Calculation

```
base_score = severity_weight * finding_weight
  where:
    CRITICAL = 10.0
    HIGH     = 7.5
    MEDIUM   = 5.0
    LOW      = 2.5
    INFO     = 0.0

finding_weight = confidence_multiplier * exploitability_multiplier
final_score = base_score * finding_weight
```

### Category Score

Weighted average of finding scores within category, normalized by number of applicable checks.

### Overall Score

Weighted average of category scores. Categories can be weighted differently (e.g., Compromise > Info).

### CVSS Integration (Future)

- CVSS v3.1 vector strings parsed
- Environmental score adjustments
- Temporal score adjustments

## Consequences
- Clear prioritization for remediation
- Category breakdowns show weak areas
- Extensible weighting allows customization
- Historical comparison shows posture trends
- CVSS ready for future integration
