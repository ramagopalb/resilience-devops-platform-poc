"""Tests for reliability_monitor.py -- 45 tests covering SLO, incidents, runbooks, DORA."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from datetime import datetime, timedelta, timezone

from resilience_platform.reliability_monitor import (
    ReliabilityMonitor,
    SLOConfig,
    SLOMetrics,
    SLOStatus,
    Incident,
    IncidentSeverity,
    IncidentStatus,
    ErrorBudget,
    RunbookExecutor,
)

UTC = timezone.utc


def make_slo_config(service="api", availability=99.9, latency_p99=500.0):
    return SLOConfig(
        service=service,
        availability_target=availability,
        latency_p99_ms=latency_p99,
        error_budget_burn_rate_threshold=5.0,
        window_days=30,
    )


def make_metrics(service="api", avail=99.95, latency=200.0, error_rate=0.05,
                 requests=10000, errors=5):
    return SLOMetrics(
        service=service,
        measured_at=datetime.now(UTC),
        availability_percent=avail,
        latency_p99_ms=latency,
        error_rate_percent=error_rate,
        request_count=requests,
        error_count=errors,
    )


class TestSLOConfig:
    def test_error_budget_minutes_99_9(self):
        config = make_slo_config(availability=99.9)
        # 0.1% of 30 days * 24h * 60min = 43.2 min
        assert abs(config.error_budget_minutes - 43.2) < 0.1

    def test_error_budget_minutes_99_99(self):
        config = make_slo_config(availability=99.99)
        assert config.error_budget_minutes < 5.0

    def test_error_budget_minutes_99_0(self):
        config = make_slo_config(availability=99.0)
        # 1% of 43200 min = 432 min
        assert abs(config.error_budget_minutes - 432.0) < 0.1


class TestSLOMetrics:
    def test_success_rate_calculation(self):
        m = make_metrics(requests=1000, errors=10)
        assert abs(m.success_rate - 99.0) < 0.01

    def test_success_rate_zero_requests(self):
        m = make_metrics(requests=0, errors=0)
        assert m.success_rate == 100.0

    def test_success_rate_all_errors(self):
        m = make_metrics(requests=100, errors=100)
        assert m.success_rate == 0.0


class TestErrorBudget:
    def test_remaining_minutes(self):
        budget = ErrorBudget(service="api", window_days=30,
                             total_budget_minutes=43.2, consumed_minutes=10.0)
        assert abs(budget.remaining_minutes - 33.2) < 0.01

    def test_consumed_percent(self):
        budget = ErrorBudget(service="api", window_days=30,
                             total_budget_minutes=43.2, consumed_minutes=21.6)
        assert abs(budget.consumed_percent - 50.0) < 0.01

    def test_remaining_percent(self):
        budget = ErrorBudget(service="api", window_days=30,
                             total_budget_minutes=43.2, consumed_minutes=21.6)
        assert abs(budget.remaining_percent - 50.0) < 0.01

    def test_exhausted_when_consumed_exceeds_total(self):
        budget = ErrorBudget(service="api", window_days=30,
                             total_budget_minutes=43.2, consumed_minutes=50.0)
        assert budget.is_exhausted is True

    def test_not_exhausted_when_budget_remains(self):
        budget = ErrorBudget(service="api", window_days=30,
                             total_budget_minutes=43.2, consumed_minutes=10.0)
        assert budget.is_exhausted is False

    def test_remaining_never_negative(self):
        budget = ErrorBudget(service="api", window_days=30,
                             total_budget_minutes=43.2, consumed_minutes=100.0)
        assert budget.remaining_minutes == 0.0


class TestIncident:
    def test_new_incident_is_open(self):
        inc = Incident(
            incident_id="INC-0001", service="api",
            severity=IncidentSeverity.P1, title="Service Down",
            description="API returning 503",
            detected_at=datetime.now(UTC),
        )
        assert inc.status == IncidentStatus.OPEN

    def test_acknowledge_sets_status(self):
        inc = Incident(
            incident_id="INC-0002", service="api",
            severity=IncidentSeverity.P2, title="High Error Rate",
            description="5% error rate detected",
            detected_at=datetime.now(UTC),
        )
        inc.acknowledge()
        assert inc.status == IncidentStatus.ACKNOWLEDGED
        assert inc.acknowledged_at is not None

    def test_resolve_sets_status(self):
        detected = datetime.now(UTC)
        resolved = detected + timedelta(minutes=30)
        inc = Incident(
            incident_id="INC-0003", service="api",
            severity=IncidentSeverity.P3, title="Minor Issue",
            description="minor",
            detected_at=detected,
        )
        inc.resolve(at=resolved)
        assert inc.status == IncidentStatus.RESOLVED
        assert inc.resolved_at == resolved

    def test_ttr_calculation(self):
        detected = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        resolved = datetime(2025, 1, 1, 10, 30, 0, tzinfo=UTC)
        inc = Incident(
            incident_id="INC-0004", service="api",
            severity=IncidentSeverity.P1, title="Service Down",
            description="down",
            detected_at=detected,
        )
        inc.resolve(at=resolved)
        assert inc.time_to_resolve_minutes == 30.0

    def test_tta_calculation(self):
        detected = datetime(2025, 1, 1, 10, 0, 0, tzinfo=UTC)
        acknowledged = datetime(2025, 1, 1, 10, 5, 0, tzinfo=UTC)
        inc = Incident(
            incident_id="INC-0005", service="api",
            severity=IncidentSeverity.P2, title="Degradation",
            description="degraded",
            detected_at=detected,
        )
        inc.acknowledge(at=acknowledged)
        assert inc.time_to_acknowledge_minutes == 5.0

    def test_ttr_none_when_not_resolved(self):
        inc = Incident(
            incident_id="INC-0006", service="api",
            severity=IncidentSeverity.P3, title="Minor",
            description="minor",
            detected_at=datetime.now(UTC),
        )
        assert inc.time_to_resolve_minutes is None

    def test_to_dict_has_expected_keys(self):
        inc = Incident(
            incident_id="INC-0007", service="api",
            severity=IncidentSeverity.P1, title="Down",
            description="down",
            detected_at=datetime.now(UTC),
        )
        d = inc.to_dict()
        for key in ["incident_id", "service", "severity", "title", "status", "detected_at"]:
            assert key in d


class TestRunbookExecutor:
    def setup_method(self):
        self.executor = RunbookExecutor()

    def test_high_error_rate_runbook_returns_steps(self):
        inc = Incident(
            incident_id="INC-0010", service="api",
            severity=IncidentSeverity.P2, title="High Error Rate",
            description="errors",
            detected_at=datetime.now(UTC),
        )
        steps = self.executor.execute(inc, "high_error_rate")
        assert len(steps) > 0
        assert inc.runbook_executed is True
        assert inc.runbook_steps == steps

    def test_high_latency_runbook_returns_steps(self):
        inc = Incident(
            incident_id="INC-0011", service="api",
            severity=IncidentSeverity.P2, title="Latency",
            description="slow",
            detected_at=datetime.now(UTC),
        )
        steps = self.executor.execute(inc, "high_latency")
        assert len(steps) > 0

    def test_service_unavailable_runbook_returns_steps(self):
        inc = Incident(
            incident_id="INC-0012", service="api",
            severity=IncidentSeverity.P1, title="Down",
            description="down",
            detected_at=datetime.now(UTC),
        )
        steps = self.executor.execute(inc, "service_unavailable")
        assert len(steps) > 0

    def test_unknown_runbook_returns_generic_step(self):
        inc = Incident(
            incident_id="INC-0013", service="api",
            severity=IncidentSeverity.P4, title="Info",
            description="info",
            detected_at=datetime.now(UTC),
        )
        steps = self.executor.execute(inc, "unknown_runbook_type")
        assert len(steps) == 1
        assert "GENERIC" in steps[0]

    def test_custom_runbook_registration(self):
        def my_runbook(incident):
            return ["custom step 1", "custom step 2"]

        self.executor.register_runbook("my_custom", my_runbook)
        inc = Incident(
            incident_id="INC-0014", service="api",
            severity=IncidentSeverity.P3, title="Custom",
            description="custom",
            detected_at=datetime.now(UTC),
        )
        steps = self.executor.execute(inc, "my_custom")
        assert steps == ["custom step 1", "custom step 2"]


class TestReliabilityMonitor:
    def setup_method(self):
        self.monitor = ReliabilityMonitor([
            make_slo_config("api", 99.9, 500.0),
            make_slo_config("data-service", 99.5, 1000.0),
        ])

    def test_healthy_metrics_returns_healthy(self):
        m = make_metrics("api", avail=99.95, latency=200.0, error_rate=0.05)
        status = self.monitor.evaluate_slo(m)
        assert status == SLOStatus.HEALTHY

    def test_availability_below_target_returns_breached(self):
        m = make_metrics("api", avail=99.5, latency=200.0, error_rate=0.5)
        status = self.monitor.evaluate_slo(m)
        assert status == SLOStatus.BREACHED

    def test_high_error_rate_returns_at_risk(self):
        m = make_metrics("api", avail=99.95, latency=200.0, error_rate=1.0)
        status = self.monitor.evaluate_slo(m)
        assert status == SLOStatus.AT_RISK

    def test_high_latency_returns_at_risk(self):
        m = make_metrics("api", avail=99.95, latency=1200.0, error_rate=0.01)
        status = self.monitor.evaluate_slo(m)
        assert status == SLOStatus.AT_RISK

    def test_unknown_service_returns_healthy(self):
        m = make_metrics("unknown-svc", avail=0.0, latency=99999.0, error_rate=100.0)
        status = self.monitor.evaluate_slo(m)
        assert status == SLOStatus.HEALTHY

    def test_create_incident_assigns_id(self):
        inc = self.monitor.create_incident(
            "api", IncidentSeverity.P2, "High Error Rate", "5% errors")
        assert inc.incident_id == "INC-0001"
        assert inc.status == IncidentStatus.OPEN

    def test_create_incident_with_auto_runbook(self):
        inc = self.monitor.create_incident(
            "api", IncidentSeverity.P2, "Error Spike", "errors",
            auto_runbook="high_error_rate")
        assert inc.runbook_executed is True
        assert len(inc.runbook_steps) > 0

    def test_alert_callback_invoked_on_incident(self):
        calls = []
        self.monitor.add_alert_callback(lambda inc: calls.append(inc.incident_id))
        self.monitor.create_incident("api", IncidentSeverity.P1, "Down", "down")
        assert len(calls) == 1

    def test_get_open_incidents_excludes_resolved(self):
        inc = self.monitor.create_incident("api", IncidentSeverity.P3, "Minor", "minor")
        inc.resolve()
        open_incs = self.monitor.get_open_incidents()
        assert inc not in open_incs

    def test_calculate_mttr_no_resolved(self):
        assert self.monitor.calculate_mttr() is None

    def test_calculate_mttr_with_resolved_incidents(self):
        inc = self.monitor.create_incident("api", IncidentSeverity.P2, "Slow", "latency")
        resolved_at = inc.detected_at + timedelta(minutes=60)
        inc.resolve(at=resolved_at)
        mttr = self.monitor.calculate_mttr()
        assert mttr == 60.0

    def test_calculate_error_budget(self):
        budget = self.monitor.calculate_error_budget("api", consumed_downtime_minutes=10.0)
        assert budget.service == "api"
        assert budget.remaining_minutes > 0

    def test_calculate_error_budget_unknown_service_raises(self):
        with pytest.raises(ValueError):
            self.monitor.calculate_error_budget("nonexistent", 0.0)

    def test_dora_metrics_empty_deployments(self):
        metrics = self.monitor.calculate_dora_metrics([])
        assert metrics["deployment_frequency"] == 0.0
        assert metrics["change_failure_rate"] == 0.0

    def test_dora_metrics_with_deployments(self):
        now = datetime.now(UTC)
        deployments = [
            {"deployed_at": now - timedelta(days=i), "failed": i == 2, "lead_time_hours": 2.0}
            for i in range(10)
        ]
        metrics = self.monitor.calculate_dora_metrics(deployments)
        assert metrics["total_deployments"] == 10
        assert metrics["failed_deployments"] == 1
        assert metrics["change_failure_rate"] == 10.0

    def test_chaos_test_passing(self):
        config = make_slo_config("api", 99.9, 500.0)
        baseline = make_metrics("api", avail=99.95, latency=200.0)
        chaos = make_metrics("api", avail=85.0, latency=600.0)
        recovery = make_metrics("api", avail=99.94, latency=205.0)
        result = self.monitor.validate_chaos_test(
            "pod_failure_test", baseline, chaos, recovery)
        assert result["passed"] is True
        assert len(result["checks"]) == 3

    def test_chaos_test_failing_recovery(self):
        baseline = make_metrics("api", avail=99.95, latency=200.0)
        chaos = make_metrics("api", avail=85.0, latency=600.0)
        bad_recovery = make_metrics("api", avail=50.0, latency=800.0)
        result = self.monitor.validate_chaos_test(
            "failed_recovery_test", baseline, chaos, bad_recovery)
        assert result["passed"] is False

    def test_dashboard_summary_structure(self):
        summary = self.monitor.get_dashboard_summary()
        assert "open_incidents" in summary
        assert "p1_incidents" in summary
        assert "mttr_minutes" in summary
        assert "services_monitored" in summary

    def test_metrics_history_grows_on_evaluate(self):
        m = make_metrics("api")
        initial_len = len(self.monitor.metrics_history)
        self.monitor.evaluate_slo(m)
        assert len(self.monitor.metrics_history) == initial_len + 1
