from __future__ import annotations

import concurrent.futures
import platform
import sys
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import usaf.__about__ as about
import usaf.checks  # noqa: F401 - Trigger plugin registration
from usaf.cache.engine import CacheEngine
from usaf.collectors.manager import CollectorManager
from usaf.collectors.registry import collector_registry
from usaf.config.loader import load_config
from usaf.core.exceptions import PluginDependencyError
from usaf.core.registry import registry
from usaf.models.result import CheckResult, ScanMetadata, ScanResult

# Phase 2 components
from usaf.correlation.engine import (
    CorrelatedFinding,
    CorrelationEngine,
)
from usaf.correlation.rules import (
    DataExfilSurface,
    SSHBruteForceSurface,
    SuspiciousPersistence,
    UnauthorizedService,
)
from usaf.severity.engine import SeverityContextEngine

# Optional imports (graceful fallback if not available)
from usaf.scoring.engine import ScoringEngine


class ScanRunner:
    """Orchestrates the full security scan lifecycle.

    Implements a multi-phase pipeline:
      1. Data collection
      2. Security check execution
      3. Correlation (cross-check analysis)
      4. Context-aware severity adjustment
      5. Scoring
    """

    def __init__(self, config_path: str | None = None) -> None:
        self.config_path = config_path
        self.config = load_config(config_path)
        self.collector_manager = CollectorManager()
        self.scoring_engine = ScoringEngine()
        self.cache = CacheEngine() if self.config.general.cache else None

        # Phase 2 components
        self.correlation_engine = self._build_correlation_engine()
        self.severity_context = SeverityContextEngine()
        self.baseline_manager: Any = None
        self.profile_manager: Any = None

        self._setup_collectors()

    def _build_correlation_engine(self) -> CorrelationEngine:
        """Build the correlation engine with all registered rules."""
        engine = CorrelationEngine()
        engine.register(SSHBruteForceSurface())
        engine.register(SuspiciousPersistence())
        engine.register(UnauthorizedService())
        engine.register(DataExfilSurface())
        return engine

    def _setup_collectors(self) -> None:
        """Auto-discover and register all collectors.

        Walks the usaf.collectors namespace, imports every module (which
        triggers @register_collector decorators), then instantiates all
        registered collector classes into the CollectorManager.
        """
        collector_registry.discover()
        for instance in collector_registry.create_all_instances():
            self.collector_manager.add(instance)

    def run(self, check_ids: list[str] | None = None, verbose: bool = False) -> ScanResult:
        start_time = time.time()
        scan_start_dt = datetime.now(UTC)
        scan_id = str(uuid.uuid4())

        metadata = ScanMetadata(
            scan_name=self.config.general.scan_name,
            scan_id=scan_id,
            hostname=platform.node(),
            os_info=self._get_os_info(),
            kernel_info=platform.release(),
            usaf_version=about.__version__,
            python_version=sys.version,
            configuration_file=self.config_path or str(self.config.general.scan_name),
        )

        if verbose:
            print("[*] Collecting system data...")

        # Phase 1: Collect data
        collectors_data: dict[str, dict[str, Any]] = {}
        collector_names = self._resolve_collector_dependencies()
        for name in collector_names:
            try:
                data = self.collector_manager.collect_single(name)
                collectors_data[name] = data
            except Exception as e:
                collectors_data[name] = {"_error": str(e)}
                metadata.errors.append(f"Collector '{name}': {e}")
                if verbose:
                    print(f"  [!] Collector '{name}' failed: {e}")
        metadata.collector_count = self.collector_manager.count

        if verbose:
            print("[*] Running security checks...")

        # Phase 2: Resolve check dependencies and filter
        all_check_ids = registry.get_all_ids()
        enabled_ids = self._filter_checks(all_check_ids)
        execution_order = registry.resolve_dependencies(enabled_ids)

        metadata.total_checks = len(all_check_ids)
        metadata.enabled_checks = len(enabled_ids)

        # Phase 3: Execute checks (parallel if config.general.parallel)
        results: list[CheckResult] = []
        if self.config.general.parallel and len(execution_order) > 1:
            def _run_check(check_id: str) -> CheckResult:
                try:
                    instance = registry.get_instance(check_id)
                    result = instance.evaluate(collectors_data)
                    result = self._apply_ignore_list(result)
                    return result
                except PluginDependencyError as e:
                    return CheckResult(
                        check_id=check_id,
                        name=check_id,
                        category="GENERAL",
                        passed=False,
                        error=str(e),
                        execution_time_ms=0.0,
                    )
                except Exception as e:
                    return CheckResult(
                        check_id=check_id,
                        name=check_id,
                        category="GENERAL",
                        passed=False,
                        error=f"{type(e).__name__}: {e}",
                        execution_time_ms=0.0,
                    )

            if verbose:
                print(f"  -> Running {len(execution_order)} checks in parallel ({self.config.general.max_workers} workers)")
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.general.max_workers
            ) as executor:
                future_map = {
                    executor.submit(_run_check, cid): cid for cid in execution_order
                }
                for future in concurrent.futures.as_completed(future_map):
                    cid = future_map[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        results.append(
                            CheckResult(
                                check_id=cid,
                                name=cid,
                                category="GENERAL",
                                passed=False,
                                error=f"ExecutorError: {e}",
                                execution_time_ms=0.0,
                            )
                        )
        else:
            for check_id in execution_order:
                try:
                    instance = registry.get_instance(check_id)
                    if verbose:
                        print(f"  -> Running {check_id}: {instance.name}...")
                    result = instance.evaluate(collectors_data)
                    result = self._apply_ignore_list(result)
                    results.append(result)
                except PluginDependencyError as e:
                    results.append(
                        CheckResult(
                            check_id=check_id,
                            name=check_id,
                            category="GENERAL",
                            passed=False,
                            error=str(e),
                            execution_time_ms=0.0,
                        )
                    )
                except Exception as e:
                    results.append(
                        CheckResult(
                            check_id=check_id,
                            name=check_id,
                            category="GENERAL",
                            passed=False,
                            error=f"{type(e).__name__}: {e}",
                            execution_time_ms=0.0,
                        )
                    )

        # Phase 3.5: Correlation — cross-check analysis
        if self.config.general.cache:
            all_findings = [f for r in results for f in r.findings]
            correlated = self.correlation_engine.evaluate(all_findings)
            if correlated:
                self._inject_correlated_findings(results, correlated)
                if verbose:
                    print(f"  -> Correlation produced {len(correlated)} synthetic finding(s)")

        # Phase 3.75: Context-aware severity adjustment
        severity_adjustments = self.severity_context.apply_all(
            [f for r in results for f in r.findings],
            collectors_data,
        )
        adjustments_count = sum(1 for s in severity_adjustments.values() if s.changed)
        if adjustments_count and verbose:
            print(f"  -> Severity adjusted for {adjustments_count} finding(s)")

        # Phase 4: Build result
        metadata.end_time = datetime.now(UTC)
        metadata.duration_seconds = time.time() - start_time

        return ScanResult(
            metadata=metadata,
            results=results,
            collectors_data=collectors_data,
        )

    def score(self, result: ScanResult) -> Any:
        return self.scoring_engine.calculate(result)

    def help_text(self) -> str:
        return "Run 'usaf scan' to perform a security audit."

    def _resolve_collector_dependencies(self) -> list[str]:
        return self.collector_manager.names

    def _filter_checks(self, all_ids: list[str]) -> list[str]:
        """Apply enabled/disabled/ignore filters from config."""
        plugin_cfg = self.config.plugins
        ignore_patterns = self.config.ignore

        if plugin_cfg.enabled and plugin_cfg.enabled != ["*"]:
            enabled_set = set(plugin_cfg.enabled)
        else:
            enabled_set = set(all_ids)

        disabled_set = set(plugin_cfg.disabled)

        # Handle overrides
        for check_id, override in plugin_cfg.overrides.items():
            if override.enabled is False:
                disabled_set.add(check_id)
            elif override.enabled is True:
                enabled_set.add(check_id)

        result = []
        for cid in all_ids:
            if cid in disabled_set:
                continue
            if cid in enabled_set:
                result.append(cid)

        return result

    def _apply_ignore_list(self, result: CheckResult) -> CheckResult:
        """Remove findings matching ignore patterns."""
        ignore_patterns = self.config.ignore
        if not ignore_patterns:
            return result

        import fnmatch

        result.findings = [
            f
            for f in result.findings
            if not any(fnmatch.fnmatch(f.id, pattern) for pattern in ignore_patterns)
        ]
        result.passed = len(result.findings) == 0
        return result

    @staticmethod
    def _inject_correlated_findings(
        results: list[CheckResult], correlated: list[CorrelatedFinding]
    ) -> None:
        """Inject correlated findings as a synthetic check result."""
        if not correlated:
            return
        from usaf.models.severity import CheckCategory, Severity

        corr_result = CheckResult(
            check_id="CORRELATION",
            name="Cross-Check Correlation Analysis",
            category=CheckCategory.COMPROMISE,
            passed=len(correlated) == 0,
            findings=[  # type: ignore[arg-type]
                f for f in correlated
            ],
        )
        results.append(corr_result)

    @staticmethod
    def _get_os_info() -> str:
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip('"\n')
        except OSError:
            pass
        return platform.system()
