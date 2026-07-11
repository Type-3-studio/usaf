# ADR 007: Reporting Framework

## Status
Accepted

## Context
Different consumers need different output formats. Security engineers read terminals. CI/CD pipelines consume JSON. Compliance teams want SARIF. Management wants HTML dashboards. The framework must support all without coupling to any.

## Decision

### Reporter Interface

```python
class BaseReporter(ABC):
    name: ClassVar[str]
    extension: ClassVar[str]

    @abstractmethod
    def generate(self, results: ScanResult, config: ReportConfig) -> str:
        ...
```

### Default: Problems-Only Output

- By default, only findings (problems) are reported
- Successful checks are suppressed unless `--verbose` is specified
- Users care about actionable findings, not noise

### Report Types

1. **Terminal** (`rich`): Color-coded severity, collapsible sections, progress spinner
2. **JSON**: Structured output for machine consumption
3. **Markdown**: Readable documents for documentation and email
4. **HTML**: Self-contained report with CSS, severity badges, filtering
5. **SARIF**: Static Analysis Results Interchange Format (compliance)
6. **CSV**: Spreadsheet-friendly for analysis

### Report Sections

- Summary (score, total findings, timing)
- Findings by severity (grouped)
- Findings by category
- Top 10 worst findings
- Remediation guidance
- System information
- Compliance mappings

## Consequences
- New formats added without touching analysis code
- CI/CD pipelines consume JSON/SARIF
- Humans read terminal/Markdown/HTML
- Default mode is quiet (only problems)
- Verbose mode shows everything (debugging)
