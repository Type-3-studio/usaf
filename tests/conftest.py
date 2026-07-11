from __future__ import annotations

from typing import Any

import pytest

from usaf.collectors.base import BaseCollector
from usaf.collectors.manager import CollectorManager
from usaf.core.registry import PluginRegistry
from usaf.models.evidence import (
    RegistryEvidence,
)
from usaf.models.finding import Finding
from usaf.models.result import CheckResult, ScanResult
from usaf.models.severity import CheckCategory, Confidence, Severity


@pytest.fixture
def empty_registry() -> PluginRegistry:
    r = PluginRegistry()
    return r


@pytest.fixture
def collector_manager() -> CollectorManager:
    return CollectorManager()


class FakeCollector(BaseCollector):
    name = "test_collector"
    description = "Fake collector for testing"

    def _do_collect(self) -> dict[str, Any]:
        return {"test_key": "test_value", "number": 42}


@pytest.fixture
def fake_collector() -> FakeCollector:
    return FakeCollector()


@pytest.fixture
def fake_collectors() -> dict[str, dict[str, Any]]:
    return {
        "kernel_params": {
            "kernel.randomize_va_space": "2",
            "kernel.kptr_restrict": "2",
            "kernel.dmesg_restrict": "1",
            "fs.suid_dumpable": "0",
        },
        "users": {
            "users": [
                {
                    "username": "root",
                    "uid": 0,
                    "gid": 0,
                    "home": "/root",
                    "shell": "/bin/bash",
                    "password": "x",
                },
                {
                    "username": "bob",
                    "uid": 1000,
                    "gid": 1000,
                    "home": "/home/bob",
                    "shell": "/bin/bash",
                    "password": "x",
                },
            ],
            "shadow": [
                {"username": "root", "password_hash": "hashed", "locked": False},
                {"username": "bob", "password_hash": "hashed", "locked": False},
            ],
        },
        "sockets": {
            "tcp": [
                {
                    "protocol": "TCP",
                    "local_address": "0.0.0.0",
                    "local_port": 8080,
                    "state": "LISTEN",
                },
                {
                    "protocol": "TCP",
                    "local_address": "127.0.0.1",
                    "local_port": 5432,
                    "state": "LISTEN",
                },
            ],
            "tcp6": [],
            "udp": [],
            "udp6": [],
        },
        "interfaces": {
            "interfaces": [
                {"name": "eth0", "mac": "00:11:22:33:44:55", "state": "up", "promisc": False},
            ],
        },
    }


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        id="TEST-001-001",
        check_id="TEST-001",
        category=CheckCategory.SYSTEM,
        severity=Severity.HIGH,
        risk_score=7.5,
        title="Test finding",
        description="A test finding for unit tests",
        rationale="This is why it matters",
        remediation="Run this command to fix",
        evidence=RegistryEvidence(
            key="test.key",
            value="bad",
            expected="good",
            source="/etc/test",
        ),
        detected_value="bad",
        expected_value="good",
        affected_component="/etc/test",
        source="TestCheck",
        confidence=Confidence.HIGH,
    )


@pytest.fixture
def sample_check_result() -> CheckResult:
    return CheckResult(
        check_id="TEST-001",
        name="Test Check",
        category=CheckCategory.SYSTEM,
        passed=False,
        findings=[
            Finding(
                id="TEST-001-001",
                check_id="TEST-001",
                category=CheckCategory.SYSTEM,
                severity=Severity.HIGH,
                risk_score=7.5,
                title="Test finding",
                description="Test description",
                rationale="Test rationale",
                remediation="Test remediation",
                source="TestCheck",
            )
        ],
    )


@pytest.fixture
def sample_scan_result(sample_check_result: CheckResult) -> ScanResult:
    from usaf.models.result import ScanMetadata

    return ScanResult(
        metadata=ScanMetadata(
            hostname="test-host",
            os_info="Ubuntu 24.04",
        ),
        results=[sample_check_result],
    )
