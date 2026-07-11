from __future__ import annotations

from unittest.mock import patch

import pytest

from usaf.collectors.manager import CollectorManager
from usaf.collectors.registry import collector_registry
from usaf.core.exceptions import CollectorError


class TestCollectorLifecycleIntegration:
    """Integration tests for collector registration and management."""

    def test_collector_manager_add_and_get(self):
        mgr = CollectorManager()
        collector_registry.discover()
        instances = collector_registry.create_all_instances()
        for inst in instances:
            mgr.add(inst)
        assert mgr.count == 15
        collected_names = sorted(mgr.names)
        expected_names = sorted([
            "apt", "auditd", "containers", "cron", "firewall",
            "groups", "interfaces", "kernel", "kernel_params",
            "mounts", "processes", "sockets", "sudo", "systemd", "users",
        ])
        assert collected_names == expected_names

    def test_collector_manager_rejects_duplicates(self):
        mgr = CollectorManager()
        collector_registry.discover()
        instances = collector_registry.create_all_instances()
        for inst in instances:
            mgr.add(inst)
        with pytest.raises(CollectorError, match="already registered"):
            mgr.add(instances[0])

    def test_collector_manager_get_collector(self):
        mgr = CollectorManager()
        collector_registry.discover()
        for inst in collector_registry.create_all_instances():
            mgr.add(inst)
        kernel = mgr.get_collector("kernel")
        assert kernel.name == "kernel"
        assert kernel.description != ""

    def test_collector_manager_get_collector_not_found(self):
        mgr = CollectorManager()
        with pytest.raises(CollectorError, match="not found"):
            mgr.get_collector("nonexistent")

    def test_collector_manager_collect_single(self):
        mgr = CollectorManager()
        collector_registry.discover()
        for inst in collector_registry.create_all_instances():
            mgr.add(inst)
        data = mgr.collect_single("kernel")
        assert isinstance(data, dict)
        assert "os" in data or "kernel" in data

    def test_collector_dependency_resolution_ordering(self):
        mgr = CollectorManager()
        collector_registry.discover()
        for inst in collector_registry.create_all_instances():
            mgr.add(inst)
        order = mgr._resolve_dependencies(mgr.names)
        assert len(order) == 15
        kernel_pos = order.index("kernel")
        kernel_params_pos = order.index("kernel_params")
        assert kernel_params_pos > kernel_pos


class TestCollectorRegistryIntegration:
    """Integration tests for the collector registry."""

    def test_discover_finds_all_collectors(self):
        collector_registry.discover()
        names = sorted(collector_registry.get_all_names())
        assert len(names) == 15
        assert names == [
            "apt",
            "auditd",
            "containers",
            "cron",
            "firewall",
            "groups",
            "interfaces",
            "kernel",
            "kernel_params",
            "mounts",
            "processes",
            "sockets",
            "sudo",
            "systemd",
            "users",
        ]

    def test_create_all_instances_returns_instances(self):
        collector_registry.discover()
        instances = collector_registry.create_all_instances()
        assert len(instances) == 15
        for inst in instances:
            assert hasattr(inst, "name")
            assert hasattr(inst, "collect")
            assert callable(inst.collect)

    def test_fake_collector_in_manager(self, fake_collector):
        mgr = CollectorManager([fake_collector])
        assert mgr.count == 1
        data = mgr.collect_single("test_collector")
        assert data["test_key"] == "test_value"
        assert data["number"] == 42
        assert "_collector_meta" in data


class TestCollectorManagerCollectAllIntegration:
    """Integration tests for collect_all with real collectors."""

    @pytest.mark.slow
    @patch("subprocess.run")
    def test_collect_all_subprocess_collectors(self, mock_run):
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stderr = ""

        mgr = CollectorManager()
        collector_registry.discover()
        for inst in collector_registry.create_all_instances():
            mgr.add(inst)
        data = mgr.collect_all()
        assert isinstance(data, dict)
        assert len(data) == 15
        must_have = {"kernel", "kernel_params", "users", "sockets", "processes", "apt"}
        assert must_have.issubset(set(data.keys()))

    def test_collect_all_partial(self):
        mgr = CollectorManager()
        collector_registry.discover()
        for inst in collector_registry.create_all_instances():
            mgr.add(inst)
        data = mgr.collect_all(["kernel"])
        assert "kernel" in data
        assert "users" not in data

    def test_clear_cache_resets_state(self):
        mgr = CollectorManager()
        collector_registry.discover()
        for inst in collector_registry.create_all_instances():
            mgr.add(inst)
        mgr.collect_all(["kernel"])
        assert mgr.get("kernel") is not None
        mgr.clear_cache()
        assert mgr.get("kernel") is None
