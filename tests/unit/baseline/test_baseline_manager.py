from __future__ import annotations

import json
import tempfile

import pytest

from usaf.baseline.manager import BaselineDiff, BaselineManager, BaselineSnapshot
from usaf.core.exceptions import BaselineError
from usaf.models.result import ScanMetadata, ScanResult


class TestBaselineSnapshot:
    def test_create_snapshot(self):
        snap = BaselineSnapshot(
            created="2026-01-01T00:00:00",
            hostname="test-host",
            os_info="Ubuntu 24.04",
            kernel_info="6.8.0",
            packages={"openssh-server": "1:8.9p1"},
            users={"root": {"uid": 0, "gid": 0, "shell": "/bin/bash"}},
            services={"ssh": {"state": "running", "enabled": True}},
            ports={"tcp:22:0.0.0.0": {"pid": 123, "process": "sshd"}},
            suid_files={"/usr/bin/sudo": {"owner": "root"}},
            cron_jobs={"/etc/crontab": ["0 5 * * * root backup"]},
            kernel_params={"kernel.randomize_va_space": "2"},
            sshd_config={"PermitRootLogin": "no"},
        )
        assert snap.hostname == "test-host"
        assert snap.packages["openssh-server"] == "1:8.9p1"
        assert snap.suid_files["/usr/bin/sudo"]["owner"] == "root"


class TestBaselineDiff:
    def test_empty_diff(self):
        diff = BaselineDiff()
        assert not diff.has_changes
        assert diff.total_changes == 0

    def test_diff_with_additions(self):
        diff = BaselineDiff(
            added={"packages": [{"key": "curl", "value": "7.88.1"}]},
        )
        assert diff.has_changes
        assert diff.total_changes == 1

    def test_diff_with_modifications(self):
        diff = BaselineDiff(
            modified={"sshd_config": {"PermitRootLogin": {"old": "no", "new": "yes"}}},
        )
        assert diff.has_changes
        assert diff.total_changes == 1

    def test_diff_with_removals(self):
        diff = BaselineDiff(
            removed={"users": [{"key": "backup_user", "value": {"uid": 1001}}]},
        )
        assert diff.has_changes
        assert diff.total_changes == 1

    def test_complex_diff(self):
        diff = BaselineDiff(
            added={"packages": [{"key": "curl", "value": "7.0"}]},
            removed={"users": [{"key": "old_user", "value": {"uid": 1002}}]},
            modified={"kernel_params": {"vm.swappiness": {"old": "60", "new": "10"}}},
        )
        assert diff.has_changes
        assert diff.total_changes == 3
        assert len(diff.added["packages"]) == 1
        assert len(diff.removed["users"]) == 1
        assert len(diff.modified["kernel_params"]) == 1

    def test_model_dump_serializable(self):
        diff = BaselineDiff(
            added={"packages": [{"key": "curl", "value": "7.0"}]},
        )
        data = diff.model_dump()
        assert data["added"]["packages"][0]["key"] == "curl"


class TestBaselineManager:
    def test_store_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = BaselineManager(baseline_dir=tmpdir)
            snap = _make_test_snapshot()
            mgr.store("test-baseline", snap)
            loaded = mgr.load("test-baseline")
            assert loaded.hostname == "test-host"
            assert loaded.packages == snap.packages

    def test_load_nonexistent_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = BaselineManager(baseline_dir=tmpdir)
            with pytest.raises(BaselineError, match="not found"):
                mgr.load("nonexistent")

    def test_list_baselines(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = BaselineManager(baseline_dir=tmpdir)
            assert mgr.list_baselines() == []
            mgr.store("baseline-a", _make_test_snapshot())
            mgr.store("baseline-b", _make_test_snapshot())
            baselines = mgr.list_baselines()
            assert len(baselines) == 2
            assert "baseline-a" in baselines
            assert "baseline-b" in baselines

    def test_delete_baseline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = BaselineManager(baseline_dir=tmpdir)
            mgr.store("to-delete", _make_test_snapshot())
            assert len(mgr.list_baselines()) == 1
            mgr.delete("to-delete")
            assert mgr.list_baselines() == []

    def test_store_updates_timestamp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = BaselineManager(baseline_dir=tmpdir)
            snap = _make_test_snapshot()
            path = mgr.store("timed", snap)
            saved = json.loads(path.read_text())
            assert "created" in saved
            assert saved["hostname"] == "test-host"

    def test_diff_same_state(self):
        snap = _make_test_snapshot()
        mgr = BaselineManager(baseline_dir=tempfile.mkdtemp())
        diff = mgr.diff(snap, snap)
        assert not diff.has_changes

    def test_diff_different_packages(self):
        old = _make_test_snapshot()
        new = _make_test_snapshot()
        new.packages["new-pkg"] = "1.0"
        mgr = BaselineManager(baseline_dir=tempfile.mkdtemp())
        diff = mgr.diff(old, new)
        assert diff.has_changes
        assert "packages" in diff.added

    def test_diff_removed_packages(self):
        old = _make_test_snapshot()
        old.packages["removed-pkg"] = "1.0"
        new = _make_test_snapshot()
        mgr = BaselineManager(baseline_dir=tempfile.mkdtemp())
        diff = mgr.diff(old, new)
        assert diff.has_changes
        assert "packages" in diff.removed

    def test_diff_modified_kernel_param(self):
        old = _make_test_snapshot()
        new = _make_test_snapshot()
        new.kernel_params["kernel.randomize_va_space"] = "0"
        mgr = BaselineManager(baseline_dir=tempfile.mkdtemp())
        diff = mgr.diff(old, new)
        assert diff.has_changes
        assert "kernel_params" in diff.modified
        assert (
            diff.modified["kernel_params"]["kernel.randomize_va_space"]["old"] == "2"
        )


class TestBuildSnapshot:
    def test_build_from_scan_result(self):
        result = _make_scan_result()
        mgr = BaselineManager(baseline_dir=tempfile.mkdtemp())
        snap = mgr.build_snapshot(result)
        assert snap.hostname == "test-host"
        assert "openssh-server" in snap.packages

    def test_build_handles_empty_data(self):
        result = _make_empty_scan_result()
        mgr = BaselineManager(baseline_dir=tempfile.mkdtemp())
        snap = mgr.build_snapshot(result)
        assert snap.packages == {}
        assert snap.users == {}
        assert snap.ports == {}


def _make_test_snapshot() -> BaselineSnapshot:
    return BaselineSnapshot(
        created="2026-01-01T00:00:00",
        hostname="test-host",
        os_info="Ubuntu 24.04",
        kernel_info="6.8.0",
        packages={"openssh-server": "1:8.9p1", "sudo": "1.9.9"},
        users={"root": {"uid": 0, "gid": 0, "shell": "/bin/bash"}},
        services={"ssh": {"state": "running", "enabled": True}},
        ports={"tcp:22:0.0.0.0": {"pid": 123, "process": "sshd"}},
        suid_files={"/usr/bin/sudo": {"owner": "root", "permissions": "4755"}},
        cron_jobs={"/etc/crontab": ["0 5 * * * root backup"]},
        kernel_params={"kernel.randomize_va_space": "2"},
        sshd_config={"PermitRootLogin": "no", "Protocol": "2"},
    )


def _make_scan_result() -> ScanResult:
    return ScanResult(
        metadata=ScanMetadata(
            scan_name="test",
            hostname="test-host",
            os_info="Ubuntu 24.04",
            kernel_info="6.8.0",
        ),
        collectors_data={
            "apt": {
                "openssh-server": {"version": "1:8.9p1", "status": "installed"},
                "sudo": {"version": "1.9.9", "status": "installed"},
            },
            "users": {
                "root": {"uid": 0, "gid": 0, "shell": "/bin/bash", "home": "/root"},
            },
            "systemd": {
                "services": {
                    "ssh": {"state": "running", "enabled": True},
                },
            },
            "sockets": {
                "connections": [
                    {
                        "protocol": "tcp",
                        "local_address": "0.0.0.0",
                        "local_port": 22,
                        "pid": 123,
                        "process_name": "sshd",
                        "state": "LISTEN",
                    },
                ],
            },
            "kernel_params": {
                "kernel.randomize_va_space": "2",
                "net.ipv4.ip_forward": "0",
            },
        },
    )


def _make_empty_scan_result() -> ScanResult:
    return ScanResult(
        metadata=ScanMetadata(
            scan_name="test",
            hostname="test-host",
            os_info="Ubuntu 24.04",
            kernel_info="6.8.0",
        ),
        collectors_data={},
    )
