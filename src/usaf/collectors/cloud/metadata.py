from __future__ import annotations

import logging
import os
import socket
import subprocess
from pathlib import Path
from typing import Any

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector

logger = logging.getLogger("usaf.collectors.cloud")


def _run_cmd(cmd: list[str], timeout: int = 5) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _detect_cloud_provider() -> str | None:
    """Detect cloud provider by checking BIOS vendor or DMI data."""
    try:
        for path in ["/sys/devices/virtual/dmi/id/product_name",
                      "/sys/devices/virtual/dmi/id/sys_vendor",
                      "/sys/devices/virtual/dmi/id/product_version"]:
            content = Path(path).read_text().strip().lower()
            if "amazon" in content or "ec2" in content:
                return "aws"
            if "google" in content or "gce" in content:
                return "gcp"
            if "microsoft" in content or "azure" in content:
                return "azure"
            if "oracle" in content:
                return "oracle"
            if "digitalocean" in content:
                return "digitalocean"
            if "linode" in content:
                return "linode"
            if "scaleway" in content or "scw" in content:
                return "scaleway"
            if "vultr" in content:
                return "vultr"
            if "openstack" in content:
                return "openstack"
            if "kvm" in content and not content.startswith("kvm"):
                continue
    except OSError:
        pass
    try:
        result = _run_cmd(["systemd-detect-virt"])
        if result and "amazon" in result.lower():
            return "aws"
        if result and "kvm" in result.lower():
            detected = _detect_cloud_by_dns()
            if detected:
                return detected
    except OSError:
        pass
    return _detect_cloud_by_dns()


def _detect_cloud_by_dns() -> str | None:
    """Detect cloud by checking metadata DNS names."""
    dns_checks = {
        "aws": ("169.254.169.254", 80),
        "gcp": ("metadata.google.internal", 80),
        "azure": ("169.254.169.254", 80),
    }
    for provider, (host, port) in dns_checks.items():
        try:
            socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            return provider
        except (socket.gaierror, OSError):
            continue
    return None


def _check_imds_v1(provider: str, timeout: int = 2) -> bool:
    """Test if IMDSv1 (unauthenticated) is accessible."""
    if provider == "aws":
        result = _run_cmd([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--connect-timeout", str(timeout),
            "http://169.254.169.254/latest/meta-data/",
        ])
        return result == "200"
    if provider == "gcp":
        result = _run_cmd([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--connect-timeout", str(timeout),
            "-H", "Metadata-Flavor: Google",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
        ])
        return result == "200"
    if provider == "azure":
        result = _run_cmd([
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--connect-timeout", str(timeout),
            "-H", "Metadata: true",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ])
        return result == "200"
    return False


def _check_imds_v2_required() -> bool | None:
    """Check if IMDSv2 is enforced (AWS only)."""
    result = _run_cmd([
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--connect-timeout", "2",
        "http://169.254.169.254/latest/meta-data/",
    ])
    if result is None:
        return None
    return result != "200"


def _check_cloud_agents() -> dict[str, bool | str]:
    """Check if cloud management agents are running."""
    agents: dict[str, list[str]] = {
        "aws_ssm_agent": ["amazon-ssm-agent", "ssm-agent-worker"],
        "gcp_guest_agent": ["google-guest-agent", "google_guest_agent"],
        "azure_waagent": ["waagent", "WALinuxAgent"],
        "oracle_agent": ["oracle-cloud-agent"],
    }
    result: dict[str, bool | str] = {}
    try:
        proc = Path("/proc")
        for agent_name, processes in agents.items():
            found = False
            for pid_dir in proc.iterdir():
                if not pid_dir.name.isdigit():
                    continue
                try:
                    comm = (pid_dir / "comm").read_text().strip()
                    cmdline = (pid_dir / "cmdline").read_text().strip("\0")
                    for pname in processes:
                        if pname in comm or pname in cmdline:
                            found = True
                            break
                except OSError:
                    continue
            result[agent_name] = found
    except OSError:
        for agent_name in agents:
            result[agent_name] = False
    return result


def _check_kubernetes() -> dict[str, Any]:
    """Detect if running in a Kubernetes node or cluster."""
    k8s: dict[str, Any] = {
        "detected": False,
        "kubelet_running": False,
        "kubelet_config": None,
        "pods_running": 0,
        "secrets_present": False,
    }
    try:
        if Path("/etc/kubernetes").is_dir():
            k8s["detected"] = True
        if Path("/var/lib/kubelet").is_dir():
            k8s["detected"] = True
    except OSError:
        pass
    try:
        proc = Path("/proc")
        for pid_dir in proc.iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                comm = (pid_dir / "comm").read_text().strip()
                if "kubelet" in comm:
                    k8s["kubelet_running"] = True
                    break
            except OSError:
                continue
    except OSError:
        pass
    try:
        config_path = Path("/var/lib/kubelet/config.yaml")
        if config_path.exists():
            k8s["kubelet_config"] = "present"
    except OSError:
        pass
    try:
        pods_dir = Path("/var/lib/kubelet/pods")
        if pods_dir.is_dir():
            k8s["pods_running"] = len(list(pods_dir.iterdir()))
    except OSError:
        pass
    try:
        secrets_dir = Path("/var/lib/kubelet/secrets")
        if secrets_dir.is_dir():
            k8s["secrets_present"] = True
    except OSError:
        pass
    return k8s


def _check_cloud_credentials() -> dict[str, Any]:
    """Check for cloud credential files on the filesystem."""
    creds: dict[str, Any] = {
        "aws_credentials_exist": False,
        "aws_credential_count": 0,
        "gcp_credentials_exist": False,
        "gcp_credential_count": 0,
        "azure_credentials_exist": False,
        "azure_credential_count": 0,
    }
    aws_cred_paths = [
        Path.home() / ".aws" / "credentials",
        Path("/root/.aws/credentials"),
    ]
    for p in aws_cred_paths:
        try:
            if p.exists():
                creds["aws_credentials_exist"] = True
                creds["aws_credential_count"] += sum(
                    1 for line in p.read_text().splitlines()
                    if line.startswith("[") and line.endswith("]")
                )
        except OSError:
            pass
    gcp_cred_patterns = [
        Path.home() / ".config" / "gcloud",
        Path("/root/.config/gcloud"),
    ]
    for p in gcp_cred_patterns:
        try:
            if p.is_dir():
                cred_files = [f for f in p.rglob("*.json") if "key" in f.name.lower() or "cred" in f.name.lower()]
                if cred_files:
                    creds["gcp_credentials_exist"] = True
                    creds["gcp_credential_count"] = len(cred_files)
        except OSError:
            pass
    azure_cred_paths = [
        Path.home() / ".azure" / "azureProfile.json",
        Path("/root/.azure/azureProfile.json"),
    ]
    for p in azure_cred_paths:
        try:
            if p.exists():
                creds["azure_credentials_exist"] = True
                creds["azure_credential_count"] += 1
        except OSError:
            pass
    return creds


def _check_cloud_storage_tools() -> dict[str, bool]:
    """Detect cloud storage CLI tools."""
    return {
        "aws_cli": _run_cmd(["which", "aws"]) is not None,
        "gcloud_cli": _run_cmd(["which", "gcloud"]) is not None,
        "az_cli": _run_cmd(["which", "az"]) is not None,
        "s3cmd": _run_cmd(["which", "s3cmd"]) is not None,
        "mc_cli": _run_cmd(["which", "mc"]) is not None,
    }


def _check_metadata_service_exposure() -> dict[str, Any]:
    """Check if cloud metadata service is accessible from inside containers or via SSRF vectors."""
    exposure: dict[str, Any] = {
        "imds_reachable": False,
        "imds_v1_accessible": False,
        "imds_v2_required": None,
        "provider": None,
    }
    provider = _detect_cloud_provider()
    if not provider:
        return exposure
    exposure["provider"] = provider
    imds_v1 = _check_imds_v1(provider)
    exposure["imds_reachable"] = imds_v1
    exposure["imds_v1_accessible"] = imds_v1
    if provider == "aws":
        exposure["imds_v2_required"] = _check_imds_v2_required()
    return exposure


@register_collector
class CloudMetadataCollector(BaseCollector):
    name = "cloud"
    description = "Cloud provider detection, metadata service state, agents, K8s, and credential presence"

    def _do_collect(self) -> dict[str, Any]:
        provider = _detect_cloud_provider()
        metadata_service = _check_metadata_service_exposure()
        return {
            "provider": provider,
            "on_cloud": provider is not None,
            "metadata_service": metadata_service,
            "agents": _check_cloud_agents(),
            "kubernetes": _check_kubernetes(),
            "credentials": _check_cloud_credentials(),
            "storage_tools": _check_cloud_storage_tools(),
            "environment": {
                "aws_region": os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"),
                "gcp_project": os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT"),
                "azure_subscription": os.environ.get("AZURE_SUBSCRIPTION_ID"),
                "k8s_service_host": os.environ.get("KUBERNETES_SERVICE_HOST"),
            },
            "kubelet_config_raw": _get_kubelet_config(),
        }


def _get_kubelet_config() -> dict[str, Any] | None:
    """Attempt to read kubelet configuration."""
    paths = [
        "/var/lib/kubelet/config.yaml",
        "/etc/kubernetes/kubelet.conf",
        "/etc/kubernetes/kubelet-config.yaml",
    ]
    for p in paths:
        try:
            import yaml
            content = Path(p).read_text()
            parsed = yaml.safe_load(content)
            if parsed and isinstance(parsed, dict):
                return {
                    "path": p,
                    "authentication": parsed.get("authentication"),
                    "authorization": parsed.get("authorization"),
                    "read_only_port": parsed.get("readOnlyPort"),
                    "protect_kernel_defaults": parsed.get("protectKernelDefaults"),
                    "seccomp_default": parsed.get("seccompDefault"),
                    "feature_gates": parsed.get("featureGates"),
                }
        except (OSError, ImportError, yaml.YAMLError):
            continue
    return None
