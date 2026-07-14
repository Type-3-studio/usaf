from __future__ import annotations

import concurrent.futures
import logging
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
from usaf.core.compliance.evaluator import ComplianceEvaluator
from usaf.core.exceptions import PluginDependencyError
from usaf.core.progress import ScanProgress
from usaf.core.registry import registry

# Phase 2 components
from usaf.correlation.engine import (
    CorrelatedFinding,
    CorrelationEngine,
)
from usaf.correlation.rules import (
    ActiveBreachIndicators,
    BootIntegrityFailure,
    CloudCompromiseRule,
    ComplianceGapRule,
    ContainerEscapePath,
    CredentialCompromise,
    DataExfilSurface,
    DefenseEvasionIndicators,
    DNSHijacking,
    ExposedAttackSurface,
    ExposedVulnerableService,
    FileIntegrityBreach,
    PriorityRemediationRule,
    RogueServiceDeployment,
    SSHBruteForceSurface,
    SuidArmingChain,
    SupplyChainAttack,
    SuspiciousPersistence,
    UnauthorizedService,
)
from usaf.correlation.scenarios import CORE_SCENARIOS
from usaf.correlation.yaml_loader import YamlRuleLoader
from usaf.knowledge.base import KnowledgeBase
from usaf.models.result import CheckResult, ScanMetadata, ScanResult
from usaf.models.scenario import ScenarioResult
from usaf.models.severity import CheckCategory

# Optional imports (graceful fallback if not available)
from usaf.scoring.engine import ScoringEngine
from usaf.severity.engine import SeverityContextEngine

logger = logging.getLogger("usaf.runner")


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
        self.knowledge_base = KnowledgeBase()
        self.compliance_evaluator = ComplianceEvaluator()
        self.baseline_manager: Any = None
        self.profile_manager: Any = None

        self._setup_collectors()

    @staticmethod
    def _get_check_category(check_id: str) -> CheckCategory:
        try:
            cls = registry.get_class(check_id)
            return cls.category
        except Exception:
            return CheckCategory.GENERAL

    def _build_correlation_engine(self) -> CorrelationEngine:
        """Build the correlation engine with all registered rules.

        Phase 5: Loads YAML-defined rules from policies/correlation/
        and registers 8 core attack scenarios for scenario scoring.
        """
        engine = CorrelationEngine()

        # Register built-in Python rules
        engine.register(SSHBruteForceSurface())
        engine.register(SuspiciousPersistence())
        engine.register(UnauthorizedService())
        engine.register(DataExfilSurface())
        engine.register(SuidArmingChain())
        engine.register(DefenseEvasionIndicators())
        engine.register(ExposedVulnerableService())
        engine.register(SupplyChainAttack())
        engine.register(BootIntegrityFailure())
        engine.register(DNSHijacking())
        engine.register(RogueServiceDeployment())
        engine.register(FileIntegrityBreach())
        engine.register(ContainerEscapePath())
        engine.register(CredentialCompromise())
        engine.register(ActiveBreachIndicators())
        engine.register(ExposedAttackSurface())

        # Phase 6: Cloud & Compliance correlation rules
        engine.register(CloudCompromiseRule())
        engine.register(ComplianceGapRule())
        engine.register(PriorityRemediationRule())

        # Phase 5: Load YAML-defined rules from policies/correlation/
        yaml_loader = YamlRuleLoader()
        yaml_rules = yaml_loader.load_all()
        for rule in yaml_rules:
            try:
                engine.register(rule)
                logger.info("Registered YAML correlation rule: %s", rule.id)
            except ValueError:
                logger.debug("YAML rule '%s' already registered (skipping)", rule.id)

        # Phase 5: Register core attack scenarios
        engine.register_scenarios(CORE_SCENARIOS)

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

    def _collect_single(self, name: str) -> tuple[str, dict[str, Any]]:
        try:
            data = self.collector_manager.collect_single(name)
            return name, data
        except Exception as e:
            return name, {"_error": str(e)}

    def run(
        self,
        check_ids: list[str] | None = None,
        verbose: bool = False,
        show_progress: bool = True,
    ) -> ScanResult:
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

        progress = ScanProgress() if show_progress else None

        if verbose:
            print("[*] Collecting system data...")

        # Phase 1: Collect data (parallel if config.general.parallel)
        collectors_data: dict[str, dict[str, Any]] = {}
        collector_names = self._resolve_collector_dependencies()

        if progress:
            progress.start_collecting(len(collector_names))

        if self.config.general.parallel and len(collector_names) > 1:
            if verbose:
                print(f"  -> Collecting from {len(collector_names)} collectors in parallel ({self.config.general.max_workers} workers)")
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.general.max_workers
            ) as executor:
                coll_future_map: dict[concurrent.futures.Future[tuple[str, dict[str, Any]]], str] = {
                    executor.submit(self._collect_single, name): name
                    for name in collector_names
                }
                for coll_future in concurrent.futures.as_completed(coll_future_map):
                    name = coll_future_map[coll_future]
                    try:
                        _, data = coll_future.result()
                        collectors_data[name] = data
                        if "_error" in data:
                            metadata.errors.append(f"Collector '{name}': {data['_error']}")
                            if verbose:
                                print(f"  [!] Collector '{name}' failed: {data['_error']}")
                    except Exception as e:
                        collectors_data[name] = {"_error": str(e)}
                        metadata.errors.append(f"Collector '{name}': {e}")
                        if verbose:
                            print(f"  [!] Collector '{name}' failed: {e}")
                    if progress:
                        progress.advance_collectors()
        else:
            for name in collector_names:
                _, data = self._collect_single(name)
                collectors_data[name] = data
                if "_error" in data:
                    metadata.errors.append(f"Collector '{name}': {data['_error']}")
                    if verbose:
                        print(f"  [!] Collector '{name}' failed: {data['_error']}")
                if progress:
                    progress.advance_collectors()

        metadata.collector_count = self.collector_manager.count

        if progress:
            progress.finish_collecting()

        if verbose:
            print("[*] Running security checks...")

        # Phase 2: Resolve check dependencies and filter
        all_check_ids = registry.get_all_ids()
        enabled_ids = self._filter_checks(all_check_ids)
        execution_order = registry.resolve_dependencies(enabled_ids)

        metadata.total_checks = len(all_check_ids)
        metadata.enabled_checks = len(enabled_ids)

        if progress:
            progress.start_checks(len(execution_order))

        # Phase 3: Execute checks (parallel if config.general.parallel)
        results: list[CheckResult] = []
        if self.config.general.parallel and len(execution_order) > 1:
            def _apply_overrides(instance: Any) -> None:
                override = self.config.plugins.overrides.get(instance.id)
                if override and override.max_findings is not None:
                    instance.max_findings = override.max_findings

            def _run_check(check_id: str) -> CheckResult:
                try:
                    instance = registry.get_instance(check_id)
                    _apply_overrides(instance)
                    result = instance.evaluate(collectors_data, self.config)
                    result = self._apply_ignore_list(result)
                    return result
                except PluginDependencyError as e:
                    return CheckResult(
                        check_id=check_id,
                        name=check_id,
                        category=self._get_check_category(check_id),
                        passed=False,
                        error=str(e),
                        execution_time_ms=0.0,
                    )
                except Exception as e:
                    return CheckResult(
                        check_id=check_id,
                        name=check_id,
                        category=self._get_check_category(check_id),
                        passed=False,
                        error=f"{type(e).__name__}: {e}",
                        execution_time_ms=0.0,
                    )

            if verbose:
                print(f"  -> Running {len(execution_order)} checks in parallel ({self.config.general.max_workers} workers)")
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.general.max_workers
            ) as executor:
                future_to_cid: dict[concurrent.futures.Future[CheckResult], str] = {
                    executor.submit(_run_check, cid): cid for cid in execution_order
                }
                for future in concurrent.futures.as_completed(future_to_cid):
                    cid = future_to_cid[future]
                    try:
                        cr = future.result()
                        results.append(cr)
                    except Exception as e:
                        results.append(
                            CheckResult(
                                check_id=cid,
                                name=cid,
                                category=self._get_check_category(cid),
                                passed=False,
                                error=f"ExecutorError: {e}",
                                execution_time_ms=0.0,
                            )
                        )
                    if progress:
                        progress.advance_checks()
        else:
            for check_id in execution_order:
                try:
                    instance = registry.get_instance(check_id)
                    override = self.config.plugins.overrides.get(instance.id)
                    if override and override.max_findings is not None:
                        instance.max_findings = override.max_findings
                    if verbose:
                        print(f"  -> Running {check_id}: {instance.name}...")
                    result = instance.evaluate(collectors_data, self.config)
                    result = self._apply_ignore_list(result)
                    results.append(result)
                except PluginDependencyError as e:
                    results.append(
                        CheckResult(
                            check_id=check_id,
                            name=check_id,
                            category=self._get_check_category(check_id),
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
                            category=self._get_check_category(check_id),
                            passed=False,
                            error=f"{type(e).__name__}: {e}",
                            execution_time_ms=0.0,
                        )
                    )
                if progress:
                    progress.advance_checks()

        if progress:
            progress.finish_checks()
            progress.set_spinner("Post-processing findings...")

        # Phase 3.5: Correlation — cross-check analysis
        all_findings = [f for r in results for f in r.findings]
        correlated = self.correlation_engine.evaluate(all_findings)
        if correlated:
            self._inject_correlated_findings(results, correlated)
            if verbose:
                print(f"  -> Correlation produced {len(correlated)} synthetic finding(s)")

        # Phase 3.6: Scenario scoring — evaluate attack scenarios
        all_findings = [f for r in results for f in r.findings]
        scenario_correlated = [
            f for f in all_findings
            if isinstance(f, CorrelatedFinding)
        ]
        scenario_results = self.correlation_engine.evaluate_scenarios(scenario_correlated)
        if scenario_results:
            self._inject_scenario_results(results, scenario_results)
            if verbose:
                for s in scenario_results:
                    print(f"  -> Scenario '{s.scenario_name}': triggered ({s.confidence:.0%} confidence)")

        # Phase 3.75: Context-aware severity adjustment
        all_findings = [f for r in results for f in r.findings]
        severity_adjustments = self.severity_context.apply_all(
            all_findings,
            collectors_data,
        )
        adjustments_count = 0
        for f in all_findings:
            adj = severity_adjustments.get(f.id)
            if adj and adj.changed:
                f.severity = adj.adjusted
                f.risk_score = adj.adjusted.score
                adjustments_count += 1
        if adjustments_count and verbose:
            print(f"  -> Severity adjusted for {adjustments_count} finding(s)")

        # Phase 3.8: Knowledge-based finding enrichment
        enriched_count = 0
        for f in all_findings:
            entry = self.knowledge_base.get(f.check_id)
            if entry:
                f.reference = f.reference or entry.mitre_mappings[0] if entry.mitre_mappings else None
                # Merge KB tags into finding tags if not already present
                existing_tags = set(f.tags)
                for tag in entry.tags:
                    if tag not in existing_tags:
                        f.tags.append(tag)
                        existing_tags.add(tag)
                enriched_count += 1
        if enriched_count and verbose:
            print(f"  -> Knowledge enrichment applied to {enriched_count} finding(s)")

        # Phase 3.9: Compliance evaluation — meta-evaluation across all findings
        all_findings = [f for r in results for f in r.findings]
        compliance_results = self.compliance_evaluator.evaluate(
            all_findings,
            collectors_data,
        )
        for cr in compliance_results:
            results.append(cr)
        if verbose and compliance_results:
            total_compliance_findings = sum(len(r.findings) for r in compliance_results)
            print(f"  -> Compliance evaluation: {len(compliance_results)} framework(s) evaluated, "
                  f"{total_compliance_findings} finding(s)")

        # Phase 4: Build result
        metadata.end_time = datetime.now(UTC)
        metadata.duration_seconds = time.time() - start_time

        if progress:
            progress.stop()

        return ScanResult(
            metadata=metadata,
            results=results,
            collectors_data=collectors_data,
        )

    def compare_baseline(
        self,
        result: ScanResult,
        baseline_name: str = "default-baseline",
        verbose: bool = False,
    ) -> dict[str, Any]:
        """Compare scan result against a stored baseline.

        Returns a dict with keys: diff (BaselineDiff | None), auto_created (bool),
        auto_created_path (str | None), error (str | None).
        Also handles auto-creation if configured.
        """
        from usaf.baseline.manager import BaselineManager
        from usaf.core.exceptions import BaselineError

        baseline_mgr = BaselineManager()
        result_data: dict[str, Any] = {
            "diff": None,
            "auto_created": False,
            "auto_created_path": None,
            "error": None,
        }

        try:
            baseline = baseline_mgr.load(baseline_name)
            snapshot = baseline_mgr.build_snapshot(result)
            diff = baseline_mgr.diff(baseline, snapshot)
            result_data["diff"] = diff

            if diff.has_changes:
                result.metadata.errors.append(
                    f"Baseline drift detected: {diff.total_changes} change(s) "
                    f"(added: {sum(len(v) for v in diff.added.values())}, "
                    f"removed: {sum(len(v) for v in diff.removed.values())}, "
                    f"modified: {sum(len(v) for v in diff.modified.values())})"
                )
                if verbose:
                    print(f"  -> Baseline drift: {diff.total_changes} change(s)")
            elif verbose:
                print("  -> Baseline: no drift detected")

        except BaselineError:
            if self.config.baseline.auto_baseline:
                if verbose:
                    print("  -> No baseline found. Auto-creating...")
                try:
                    snapshot = baseline_mgr.build_snapshot(result)
                    path = baseline_mgr.store(baseline_name, snapshot)
                    result_data["auto_created"] = True
                    result_data["auto_created_path"] = str(path)
                    if verbose:
                        print(f"  -> Baseline '{baseline_name}' created at {path}")
                except Exception as e:
                    if verbose:
                        print(f"  [!] Auto-baseline failed: {e}")
            elif verbose:
                print("  -> No baseline found. Run 'usaf baseline init' to create one.")

        except Exception as e:
            result_data["error"] = str(e)
            if verbose:
                print(f"  [!] Baseline diff skipped: {e}")

        return result_data

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
        """Remove findings matching ignore patterns (by ID or path)."""
        import fnmatch

        ignore_patterns = self.config.ignore
        ignore_paths = self.config.ignore_paths

        if not ignore_patterns and not ignore_paths:
            return result

        def _is_ignored(finding: Any) -> bool:
            if ignore_patterns and any(fnmatch.fnmatch(finding.id, p) for p in ignore_patterns):
                return True
            if ignore_paths and finding.affected_component:
                for pat in ignore_paths:
                    if fnmatch.fnmatch(finding.affected_component, pat):
                        return True
            return False

        result.findings = [f for f in result.findings if not _is_ignored(f)]
        result.passed = len(result.findings) == 0
        return result

    @staticmethod
    def _inject_correlated_findings(
        results: list[CheckResult], correlated: list[CorrelatedFinding]
    ) -> None:
        """Inject correlated findings as a synthetic check result."""
        if not correlated:
            return
        from usaf.models.severity import CheckCategory

        corr_result = CheckResult(
            check_id="CORRELATION",
            name="Cross-Check Correlation Analysis",
            category=CheckCategory.COMPROMISE,
            passed=len(correlated) == 0,
            findings=[f for f in correlated],
        )
        results.append(corr_result)

    @staticmethod
    def _inject_scenario_results(
        results: list[CheckResult], scenarios: list[ScenarioResult]
    ) -> None:
        """Inject scenario results as synthetic check results."""
        from usaf.models.severity import CheckCategory

        for scenario in scenarios:
            if not scenario.triggered:
                continue

            scenario_result = CheckResult(
                check_id=f"SCENARIO-{scenario.scenario_id}",
                name=f"Scenario: {scenario.scenario_name}",
                category=CheckCategory.COMPROMISE,
                passed=False,
                findings=[
                    CorrelatedFinding(
                        id=f"{scenario.scenario_id}-001",
                        check_id=f"SCENARIO-{scenario.scenario_id}",
                        category=CheckCategory.COMPROMISE,
                        severity=scenario.severity,
                        risk_score=scenario.severity.score,
                        title=f"Attack Scenario Triggered: {scenario.scenario_name}",
                        description=scenario.description,
                        rationale=(
                            f"The {scenario.scenario_name} attack scenario was triggered "
                            f"with {scenario.rules_triggered}/{scenario.total_rules} constituent "
                            f"correlation rules firing. Confidence: {scenario.confidence:.0%}. "
                            "This represents a real-world attack pattern that requires investigation."
                        ),
                        remediation=(
                            "1. Review all correlated findings for this scenario\n"
                            "2. Follow remediation steps for each individual finding\n"
                            "3. Escalate to security team for incident response\n"
                            "4. Harden systems against the detected attack pattern"
                        ),
                        source="ScenarioEngine",
                        source_findings=scenario.source_finding_ids,
                        correlation_rule=f"SCENARIO-{scenario.scenario_id}",
                        tags=[str(p.value) for p in scenario.kill_chain_phases],
                        mitre_attack_ids=[],
                    )
                ],
            )
            results.append(scenario_result)

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
