# ADR 005: Collector Architecture

## Status
Accepted

## Context
With hundreds of checks running, executing shell commands per check is prohibitively expensive. Many checks need the same data (list of users, open ports, running processes). Data must be gathered once and reused.

## Decision

### Collector Pattern

Collectors are singleton data providers that gather system information once per scan.

```python
class BaseCollector(ABC):
    name: ClassVar[str]

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        """Gather data. Called once per scan."""
        ...

    @abstractmethod
    def get_data(self) -> dict[str, Any]:
        """Return cached data."""
        ...
```

### Collector Categories

- **System**: kernel, boot, hardware, virtualization info
- **Filesystem**: mount points, permissions, special files
- **Network**: sockets, interfaces, DNS, firewall rules
- **Processes**: process list, file descriptors, environment
- **Packages**: installed packages, repos, updates
- **Users**: users, groups, sudoers, shadow
- **Services**: systemd units, cron jobs, timers
- **Security**: AppArmor, SELinux, PAM, auditd, certificates
- **Container**: Docker, Podman containers and images

### Execution

- Collectors run once at scan start
- Results cached in `CollectorManager`
- Checks request data via `collector.get("collector_name")`
- Collectors can depend on other collectors
- Expensive collectors support timeout (30s default)

### Design Rules

- Use Python APIs over shell parsing (e.g., `os.listdir()` over `ls`)
- When shell is unavoidable, parse structured output (JSON, null-delimited)
- Never parse `ls` output. Never parse `ps` human output.
- Every collector documents its commands and data sources.

## Consequences
- O(n) subprocess calls instead of O(n*m)
- Clean caching and incremental scan support
- Offline mode: cached data replayed from disk
- Testable: mock collectors return known data
