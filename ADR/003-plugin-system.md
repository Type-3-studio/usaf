# ADR 003: Plugin System Design

## Status
Accepted

## Context
Every audit check should be a plugin. Adding new checks must not require modifying core framework code. The plugin system must support dependency ordering, categorization, and selective execution.

## Decision

### Plugin Interface

Every plugin implements `AuditCheck` abstract base class:

```python
class AuditCheck(ABC):
    id: ClassVar[str]                    # Unique identifier (e.g., "SSH-101")
    name: ClassVar[str]                  # Human-readable name
    category: ClassVar[CheckCategory]    # Category enum
    severity: ClassVar[Severity]         # Default severity
    description: ClassVar[str]           # What this checks
    depends: ClassVar[list[str]]         # Collector dependencies
    tags: ClassVar[list[str]]            # Metadata tags

    @abstractmethod
    def evaluate(self, collector: CollectorManager) -> CheckResult:
        ...
```

### Plugin Discovery

- Plugins register via a decorator `@register_check`
- Auto-discovery via namespace scanning at startup
- Explicit registration also supported for testing
- Registry maintains a directed acyclic graph of dependencies

### Plugin Categories

System, Network, Users, Permissions, Services, Packages, Kernel, Security, Persistence, Containers, Compliance, Compromise, Forensics

### Plugin Lifecycle

1. Discovery -> 2. Registration -> 3. Dependency Resolution -> 4. Data Collection -> 5. Evaluation -> 6. Result Collection

## Consequences
- Zero-boilerplate plugin addition
- Automatic dependency resolution
- Clear separation between data collection and analysis
- Easy to write tests: mock collector and call evaluate()
