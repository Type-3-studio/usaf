from __future__ import annotations

from typing import Any

from usaf.models.evidence import NetworkEvidence
from usaf.models.finding import Finding
from usaf.models.severity import Severity


class ContextAwareSeverity:
    """Represents a severity determined by system context rather than hardcoded value.

    Carries the original severity, adjusted severity, and the context
    that triggered the adjustment for full auditability.
    """

    def __init__(
        self,
        original: Severity,
        adjusted: Severity,
        check_id: str,
        context_reason: str,
    ) -> None:
        self.original = original
        self.adjusted = adjusted
        self.check_id = check_id
        self.context_reason = context_reason

    @property
    def changed(self) -> bool:
        return self.original != self.adjusted

    def __repr__(self) -> str:
        if self.changed:
            return f"{self.original.value}→{self.adjusted.value} ({self.context_reason})"
        return self.original.value


class SeverityContextEngine:
    """Evaluates system context to adjust finding severity dynamically.

    A finding's severity often depends on deployment context:
    - SSH on port 22 bound to 0.0.0.0 is worse than bound to localhost
    - A service account with no password is less critical than a human user
    - World-writable files in /tmp are expected; in /etc they are critical
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def evaluate(self, finding: Finding, collectors: dict[str, Any]) -> ContextAwareSeverity:
        """Determine context-adjusted severity for a finding."""
        original = finding.severity
        adjusted = original
        reason = "no context adjustment applied"

        # SSH checks: adjust based on network exposure
        if finding.check_id.startswith("SSH-"):
            adjusted, reason = self._evaluate_ssh_context(finding, collectors)

        # Permission checks: adjust based on file location
        elif finding.check_id.startswith("PRM-"):
            adjusted, reason = self._evaluate_permission_context(finding, collectors)

        # User checks: adjust based on account type
        elif finding.check_id.startswith("USR-"):
            adjusted, reason = self._evaluate_user_context(finding, collectors)

        # Network checks: adjust based on port sensitivity
        elif finding.check_id.startswith("NET-"):
            adjusted, reason = self._evaluate_network_context(finding, collectors)

        return ContextAwareSeverity(
            original=original,
            adjusted=adjusted,
            check_id=finding.check_id,
            context_reason=reason,
        )

    def apply_all(
        self, findings: list[Finding], collectors: dict[str, Any]
    ) -> dict[str, ContextAwareSeverity]:
        """Apply context evaluation to all findings at once.

        Returns a dict mapping finding IDs to their context-aware severity.
        """
        return {f.id: self.evaluate(f, collectors) for f in findings}

    def _evaluate_ssh_context(
        self, finding: Finding, collectors: dict[str, Any]
    ) -> tuple[Severity, str]:
        network_data = collectors.get("sockets", {})
        connections = network_data.get("connections", []) if isinstance(network_data, dict) else []

        ssh_connections = [
            c
            for c in connections
            if isinstance(c, dict)
            and c.get("local_port") == 22
            and c.get("state") == "LISTEN"
        ]

        if not ssh_connections:
            return finding.severity, "SSH not currently listening"

        has_public = any(
            c.get("local_address", "") in ("0.0.0.0", "::", "")
            for c in ssh_connections
        )
        has_localhost = any(
            c.get("local_address", "").startswith(("127.", "::1"))
            for c in ssh_connections
        )
        has_private = any(
            c.get("local_address", "").startswith(("10.", "172.16.", "192.168."))
            for c in ssh_connections
        )

        if has_public:
            return Severity.CRITICAL, "SSH exposed on all interfaces — internet-facing"
        if has_private:
            return Severity.HIGH, "SSH bound to private network interface"
        if has_localhost:
            return Severity.MEDIUM, "SSH bound to localhost only — reduced attack surface"
        return finding.severity, "SSH listening on unspecified address"

    def _evaluate_permission_context(
        self, finding: Finding, _collectors: dict[str, Any]
    ) -> tuple[Severity, str]:
        path = ""
        ev = finding.evidence
        if ev:
            path = getattr(ev, "path", "") or ""

        if not path:
            return finding.severity, "no file path available"

        # World-writable in /tmp or /dev/shm is expected
        if path.startswith(("/tmp", "/dev/shm", "/var/tmp")):
            return Severity.LOW, f"world-writable in temp directory ({path.split('/')[1]})"

        # SUID in /usr/bin is typically expected (package-owned)
        if path.startswith("/usr/bin/") or path.startswith("/bin/"):
            return Severity.MEDIUM, f"SUID in standard binary directory: {path}"

        # SUID in non-standard location is very suspicious
        if path.startswith(("/opt", "/home", "/var/www", "/tmp", "/dev/shm")):
            return Severity.CRITICAL, f"SUID binary in non-standard location: {path}"

        return finding.severity, "standard permission context"

    def _evaluate_user_context(
        self, finding: Finding, collectors: dict[str, Any]
    ) -> tuple[Severity, str]:
        username = finding.affected_component or ""
        users_data = collectors.get("users", {})

        user_info = users_data.get(username, {}) if isinstance(users_data, dict) else {}

        if isinstance(user_info, dict):
            uid = user_info.get("uid", 0)
            shell = user_info.get("shell", "")

            # Service accounts (UID < 1000, no login shell)
            is_service = (
                (isinstance(uid, int) and 0 < uid < 1000)
                or ("nologin" in str(shell) or "/false" in str(shell))
            )

            if is_service and finding.severity in (Severity.CRITICAL, Severity.HIGH):
                return Severity.MEDIUM, f"service account ({username}) — reduced exploitability"
            if not is_service and finding.severity == Severity.MEDIUM:
                return Severity.HIGH, f"human user account ({username}) — higher risk"
            if username == "root" and finding.severity >= Severity.HIGH:
                return Severity.CRITICAL, "root account finding — maximum severity warranted"

        return finding.severity, f"user context for {username}"

    def _evaluate_network_context(
        self, finding: Finding, _collectors: dict[str, Any]
    ) -> tuple[Severity, str]:
        ev = finding.evidence
        if not ev or not isinstance(ev, NetworkEvidence):
            return finding.severity, "no network evidence available"

        port = ev.local_port
        addr = ev.local_address

        # Sensitive services exposed on all interfaces
        if port in (22, 23, 3389, 5900, 5901) and addr in ("0.0.0.0", "::"):
            return Severity.CRITICAL, f"sensitive service (port {port}) on all interfaces"

        # Database ports exposed
        if port in (3306, 5432, 6379, 27017, 9200) and addr in ("0.0.0.0", "::"):
            return Severity.HIGH, f"database port {port} exposed on all interfaces"

        return finding.severity, "standard network exposure"
