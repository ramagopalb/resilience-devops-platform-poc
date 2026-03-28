"""
Reliability Monitor — SLO tracking and incident automation for the Resilience platform.

Provides:
- SLO/SLA tracking with error budget calculation
- Incident detection and automated runbook execution
- MTTR/MTBF calculation and DORA metrics
- PagerDuty/alerting integration
- Chaos engineering test validation
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


class IncidentSeverity(str, Enum):
    P1 = "P1"  # Critical — service down
    P2 = "P2"  # High — significant degradation
    P3 = "P3"  # Medium — minor impact
    P4 = "P4"  # Low — informational


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    MITIGATING = "MITIGATING"
    RESOLVED = "RESOLVED"


class SLOStatus(str, Enum):
    HEALTHY = "HEALTHY"
    AT_RISK = "AT_RISK"
    BREACHED = "BREACHED"


@dataclass
class SLOConfig:
    service: str
    availability_target: float  # e.g. 99.9
    latency_p99_ms: float
    error_budget_burn_rate_threshold: float = 5.0
    window_days: int = 30

    @property
    def error_budget_minutes(self) -> float:
        """Total error budget in minutes over the SLO window."""
        downtime_fraction = (100 - self.availability_target) / 100
        return downtime_fraction * self.window_days * 24 * 60


@dataclass
class SLOMetrics:
    service: str
    measured_at: datetime
    availability_percent: float
    latency_p99_ms: float
    error_rate_percent: float
    request_count: int
    error_count: int

    @property
    def success_rate(self) -> float:
        if self.request_count == 0:
            return 100.0
        return ((self.request_count - self.error_count) / self.request_count) * 100


@dataclass
class ErrorBudget:
    service: str
    window_days: int
    total_budget_minutes: float
    consumed_minutes: float

    @property
    def remaining_minutes(self) -> float:
        return max(0.0, self.total_budget_minutes - self.consumed_minutes)

    @property
    def consumed_percent(self) -> float:
        if self.total_budget_minutes == 0:
            return 100.0
        return (self.consumed_minutes / self.total_budget_minutes) * 100

    @property
    def remaining_percent(self) -> float:
        return max(0.0, 100.0 - self.consumed_percent)

    @property
    def is_exhausted(self) -> bool:
        return self.consumed_minutes >= self.total_budget_minutes


@dataclass
class Incident:
    incident_id: str
    service: str
    severity: IncidentSeverity
    title: str
    description: str
    detected_at: datetime
    status: IncidentStatus = IncidentStatus.OPEN
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None
    runbook_executed: bool = False
    runbook_steps: list[str] = field(default_factory=list)

    @property
    def time_to_acknowledge_minutes(self) -> float | None:
        if self.acknowledged_at is None:
            return None
        return (self.acknowledged_at - self.detected_at).total_seconds() / 60

    @property
    def time_to_resolve_minutes(self) -> float | None:
        if self.resolved_at is None:
            return None
        return (self.resolved_at - self.detected_at).total_seconds() / 60

    def acknowledge(self, at: datetime | None = None) -> None:
        self.status = IncidentStatus.ACKNOWLEDGED
        self.acknowledged_at = at or datetime.now(timezone.utc)

    def resolve(self, at: datetime | None = None) -> None:
        self.status = IncidentStatus.RESOLVED
        self.resolved_at = at or datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "service": self.service,
            "severity": self.severity.value,
            "title": self.title,
            "status": self.status.value,
            "detected_at": self.detected_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "tta_minutes": self.time_to_acknowledge_minutes,
            "ttr_minutes": self.time_to_resolve_minutes,
            "runbook_executed": self.runbook_executed,
            "runbook_steps": self.runbook_steps,
        }


class RunbookExecutor:
    """Automated runbook execution for incident response."""

    def __init__(self) -> None:
        self._runbooks: dict[str, Callable[[Incident], list[str]]] = {}
        self._register_default_runbooks()

    def _register_default_runbooks(self) -> None:
        self._runbooks["high_error_rate"] = self._runbook_high_error_rate
        self._runbooks["high_latency"] = self._runbook_high_latency
        self._runbooks["service_unavailable"] = self._runbook_service_unavailable
        self._runbooks["memory_pressure"] = self._runbook_memory_pressure

    def _runbook_high_error_rate(self, incident: Incident) -> list[str]:
        return [
            f"[RB-001] Check application logs for error patterns: kubectl logs -n {incident.service} --tail=100",
            "[RB-001] Check recent deployments: kubectl rollout history deployment",
            "[RB-001] Verify downstream dependencies and database connectivity",
            "[RB-001] Check error rate trend in Datadog APM dashboard",
            "[RB-001] If error rate > 20%, initiate canary rollback: kubectl rollout undo deployment",
        ]

    def _runbook_high_latency(self, incident: Incident) -> list[str]:
        return [
            f"[RB-002] Check P99 latency breakdown in Grafana: service={incident.service}",
            "[RB-002] Inspect database slow query log for lock contention",
            "[RB-002] Check HPA scaling status: kubectl get hpa -n default",
            "[RB-002] Review CloudWatch CPU/memory metrics for node pressure",
            "[RB-002] If latency > 2x SLO threshold, scale deployment: kubectl scale deployment --replicas=+2",
        ]

    def _runbook_service_unavailable(self, incident: Incident) -> list[str]:
        return [
            f"[RB-003] Check pod status: kubectl get pods -n {incident.service} -o wide",
            "[RB-003] Describe failing pods: kubectl describe pod <pod-name>",
            "[RB-003] Check node health: kubectl get nodes",
            "[RB-003] Review EKS cluster events: kubectl get events --sort-by=lastTimestamp",
            "[RB-003] Verify Fargate profile availability and task limits",
            "[RB-003] Escalate to P1 if not resolved within 5 minutes",
        ]

    def _runbook_memory_pressure(self, incident: Incident) -> list[str]:
        return [
            "[RB-004] Check memory usage: kubectl top pods -n default --sort-by=memory",
            "[RB-004] Review OOMKilled pods in recent events",
            "[RB-004] Increase memory limits if consistently at threshold",
            "[RB-004] Check for memory leaks in application metrics",
        ]

    def execute(self, incident: Incident, runbook_type: str) -> list[str]:
        """Execute a runbook for the given incident."""
        runbook_fn = self._runbooks.get(runbook_type)
        if runbook_fn is None:
            steps = [f"[GENERIC] No specific runbook for '{runbook_type}' — check Confluence for manual steps"]
        else:
            steps = runbook_fn(incident)

        incident.runbook_executed = True
        incident.runbook_steps = steps
        logger.info("Executed runbook '%s' for incident %s (%d steps)",
                    runbook_type, incident.incident_id, len(steps))
        return steps

    def register_runbook(self, name: str, fn: Callable[[Incident], list[str]]) -> None:
        """Register a custom runbook."""
        self._runbooks[name] = fn


class ReliabilityMonitor:
    """
    Monitors SLOs, manages incidents, and automates reliability operations.

    Features:
    - Real-time SLO evaluation against thresholds
    - Error budget tracking and burn-rate alerting
    - Automated runbook execution on incident detection
    - DORA metrics calculation
    - Chaos engineering test result tracking
    """

    def __init__(self, slo_configs: list[SLOConfig]) -> None:
        self.slo_configs = {s.service: s for s in slo_configs}
        self.incidents: list[Incident] = []
        self.metrics_history: list[SLOMetrics] = []
        self.runbook_executor = RunbookExecutor()
        self._alert_callbacks: list[Callable[[Incident], None]] = []

    def add_alert_callback(self, callback: Callable[[Incident], None]) -> None:
        """Register an alert callback (e.g., PagerDuty, Slack)."""
        self._alert_callbacks.append(callback)

    def evaluate_slo(self, metrics: SLOMetrics) -> SLOStatus:
        """Evaluate SLO compliance for a given set of metrics."""
        config = self.slo_configs.get(metrics.service)
        if config is None:
            logger.warning("No SLO config found for service: %s", metrics.service)
            return SLOStatus.HEALTHY

        self.metrics_history.append(metrics)

        if metrics.availability_percent < config.availability_target:
            return SLOStatus.BREACHED

        burn_rate = self._calculate_burn_rate(metrics, config)
        if burn_rate > config.error_budget_burn_rate_threshold:
            return SLOStatus.AT_RISK

        if metrics.latency_p99_ms > config.latency_p99_ms * 1.5:
            return SLOStatus.AT_RISK

        return SLOStatus.HEALTHY

    def _calculate_burn_rate(self, metrics: SLOMetrics, config: SLOConfig) -> float:
        """Calculate the error budget burn rate."""
        if config.availability_target >= 100:
            return 0.0
        allowed_error_rate = (100 - config.availability_target) / 100
        if allowed_error_rate == 0:
            return float("inf") if metrics.error_rate_percent > 0 else 0.0
        actual_error_rate = metrics.error_rate_percent / 100
        return actual_error_rate / allowed_error_rate

    def calculate_error_budget(self, service: str, consumed_downtime_minutes: float) -> ErrorBudget:
        """Calculate the error budget for a service."""
        config = self.slo_configs.get(service)
        if config is None:
            raise ValueError(f"No SLO config found for service: {service}")

        return ErrorBudget(
            service=service,
            window_days=config.window_days,
            total_budget_minutes=config.error_budget_minutes,
            consumed_minutes=consumed_downtime_minutes,
        )

    def create_incident(
        self,
        service: str,
        severity: IncidentSeverity,
        title: str,
        description: str,
        auto_runbook: str | None = None,
    ) -> Incident:
        """Create and register an incident, optionally triggering a runbook."""
        incident_id = f"INC-{len(self.incidents) + 1:04d}"
        incident = Incident(
            incident_id=incident_id,
            service=service,
            severity=severity,
            title=title,
            description=description,
            detected_at=datetime.now(timezone.utc),
        )
        self.incidents.append(incident)

        if auto_runbook:
            self.runbook_executor.execute(incident, auto_runbook)

        for callback in self._alert_callbacks:
            try:
                callback(incident)
            except Exception as exc:
                logger.error("Alert callback failed: %s", exc)

        logger.info("Created incident %s [%s]: %s", incident_id, severity.value, title)
        return incident

    def get_open_incidents(self) -> list[Incident]:
        return [i for i in self.incidents if i.status != IncidentStatus.RESOLVED]

    def calculate_mttr(self) -> float | None:
        """Calculate Mean Time to Resolve (MTTR) in minutes."""
        resolved = [
            i for i in self.incidents
            if i.status == IncidentStatus.RESOLVED and i.time_to_resolve_minutes is not None
        ]
        if not resolved:
            return None
        return sum(i.time_to_resolve_minutes for i in resolved) / len(resolved)  # type: ignore[arg-type]

    def calculate_dora_metrics(self, deployments: list[dict[str, Any]]) -> dict[str, Any]:
        """Calculate DORA metrics from deployment history."""
        if not deployments:
            return {
                "deployment_frequency": 0.0,
                "lead_time_for_changes_hours": None,
                "change_failure_rate": 0.0,
                "mttr_minutes": self.calculate_mttr(),
            }

        # Deployment frequency (per day)
        if len(deployments) > 1:
            timestamps = [d["deployed_at"] for d in deployments if "deployed_at" in d]
            if len(timestamps) > 1:
                span = (max(timestamps) - min(timestamps)).total_seconds() / 86400
                frequency = len(deployments) / max(span, 1)
            else:
                frequency = float(len(deployments))
        else:
            frequency = 1.0

        # Lead time for changes
        lead_times = [
            d.get("lead_time_hours") for d in deployments if d.get("lead_time_hours") is not None
        ]
        avg_lead_time = sum(lead_times) / len(lead_times) if lead_times else None

        # Change failure rate
        failed = sum(1 for d in deployments if d.get("failed", False))
        change_failure_rate = (failed / len(deployments)) * 100 if deployments else 0.0

        return {
            "deployment_frequency": round(frequency, 2),
            "lead_time_for_changes_hours": round(avg_lead_time, 2) if avg_lead_time else None,
            "change_failure_rate": round(change_failure_rate, 2),
            "mttr_minutes": self.calculate_mttr(),
            "total_deployments": len(deployments),
            "failed_deployments": failed,
        }

    def validate_chaos_test(
        self,
        test_name: str,
        baseline_metrics: SLOMetrics,
        chaos_metrics: SLOMetrics,
        recovery_metrics: SLOMetrics,
    ) -> dict[str, Any]:
        """Validate chaos engineering test results against SLO thresholds."""
        config = self.slo_configs.get(baseline_metrics.service)
        result: dict[str, Any] = {
            "test_name": test_name,
            "service": baseline_metrics.service,
            "passed": True,
            "checks": [],
        }

        # Check availability during chaos
        if config:
            min_acceptable = config.availability_target * 0.8  # 20% degradation tolerance
            avail_pass = chaos_metrics.availability_percent >= min_acceptable
            result["checks"].append({
                "check": "availability_during_chaos",
                "expected": f">= {min_acceptable:.1f}%",
                "actual": f"{chaos_metrics.availability_percent:.2f}%",
                "passed": avail_pass,
            })
            if not avail_pass:
                result["passed"] = False

        # Check recovery to baseline
        recovery_threshold = 0.99  # Must recover to 99% of baseline
        recovered = recovery_metrics.availability_percent >= (
            baseline_metrics.availability_percent * recovery_threshold
        )
        result["checks"].append({
            "check": "recovery_to_baseline",
            "expected": f">= {baseline_metrics.availability_percent * recovery_threshold:.2f}%",
            "actual": f"{recovery_metrics.availability_percent:.2f}%",
            "passed": recovered,
        })
        if not recovered:
            result["passed"] = False

        # Check latency recovery
        latency_recovered = recovery_metrics.latency_p99_ms <= baseline_metrics.latency_p99_ms * 1.1
        result["checks"].append({
            "check": "latency_recovery",
            "expected": f"<= {baseline_metrics.latency_p99_ms * 1.1:.0f}ms",
            "actual": f"{recovery_metrics.latency_p99_ms:.0f}ms",
            "passed": latency_recovered,
        })
        if not latency_recovered:
            result["passed"] = False

        return result

    def get_dashboard_summary(self) -> dict[str, Any]:
        """Generate a summary suitable for a Grafana/Datadog dashboard."""
        open_incidents = self.get_open_incidents()
        p1_count = sum(1 for i in open_incidents if i.severity == IncidentSeverity.P1)
        p2_count = sum(1 for i in open_incidents if i.severity == IncidentSeverity.P2)

        return {
            "open_incidents": len(open_incidents),
            "p1_incidents": p1_count,
            "p2_incidents": p2_count,
            "total_incidents": len(self.incidents),
            "mttr_minutes": self.calculate_mttr(),
            "services_monitored": list(self.slo_configs.keys()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
