# ADR 004: Finding Model

## Status
Accepted

## Context
Security findings must be structured, actionable, and include evidence. Plain string output is unacceptable. Findings must support automation, filtering, and integration with external systems.

## Decision

### Finding Structure (Pydantic Model)

```python
class Finding(BaseModel):
    id: str                              # Unique ID (e.g., "SSH-101-001")
    check_id: str                        # Parent check ID
    category: CheckCategory
    severity: Severity                   # CRITICAL, HIGH, MEDIUM, LOW, INFO
    risk_score: float                    # 0.0 - 10.0
    title: str                           # Short title
    description: str                     # What was found
    rationale: str                       # WHY this matters (threat context)
    evidence: Evidence | None            # The proof
    detected_value: str | None           # What was actually found
    expected_value: str | None           # What should be there
    affected_component: str | None       # File, process, socket, etc.
    remediation: str                     # How to fix
    reference: str | None                # URL or document reference
    confidence: Confidence               # HIGH, MEDIUM, LOW
    false_positive_probability: float    # 0.0 - 1.0
    source: str                          # Plugin class name
    timestamp: datetime
    cve_ids: list[str]                   # Related CVEs
    cis_benchmarks: list[str]            # CIS control mappings
    mitre_attack_ids: list[str]          # MITRE ATT&CK mappings
    owasp_ids: list[str]                 # OWASP mappings
    tags: list[str]                      # Arbitrary tags
```

### Evidence Types

```python
class FileEvidence(BaseModel):
    path: str
    line: int | None
    content: str
    permission: str | None
    owner: str | None

class ProcessEvidence(BaseModel):
    pid: int
    name: str
    binary: str
    cmdline: str
    user: str
    ...

class NetworkEvidence(BaseModel):
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    process: str
    ...
```

## Consequences
- Machines can parse and act on findings
- Humans get complete context for triage
- False positive analysis is data-driven (not guesswork)
- External tool integration is straightforward
- Historical comparison is precise
