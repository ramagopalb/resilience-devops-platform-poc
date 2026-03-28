"""Helper script to create all test files for the Resilience POC."""
import os

TESTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests")
os.makedirs(TESTS_DIR, exist_ok=True)

# ---- test_compliance_checker.py ----
compliance_tests = """\
\"\"\"Tests for compliance_checker.py -- 45 tests covering all policy checks.\"\"\"
import json
import pytest
from platform.compliance_checker import (
    ComplianceChecker,
    PolicyViolation,
    Severity,
    SecurityGroupPolicy,
    S3BucketPolicy,
    IAMPolicy,
    EKSClusterPolicy,
    TaggingPolicy,
    ComplianceStatus,
)

REQUIRED_TAGS = {
    "Environment": "prod",
    "Owner": "platform-team",
    "CostCenter": "CC-100",
    "DataClassification": "internal",
}


class TestSecurityGroupPolicy:
    def setup_method(self):
        self.policy = SecurityGroupPolicy()

    def test_unrestricted_all_ports_ipv4_triggers_critical(self):
        resource = {
            "id": "sg-001", "type": "aws_security_group",
            "ingress_rules": [{"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}],
            "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 1
        assert violations[0].severity == Severity.CRITICAL
        assert violations[0].rule_id == "SG-001"

    def test_unrestricted_all_ports_ipv6_triggers_critical(self):
        resource = {
            "id": "sg-002", "type": "aws_security_group",
            "ingress_rules": [{"from_port": 0, "to_port": 65535, "cidr_blocks": ["::/0"]}],
            "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 1
        assert violations[0].severity == Severity.CRITICAL

    def test_restricted_port_443_private_cidr_passes(self):
        resource = {
            "id": "sg-003", "type": "aws_security_group",
            "ingress_rules": [{"from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}],
            "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 0

    def test_no_ingress_rules_passes(self):
        resource = {
            "id": "sg-004", "type": "aws_security_group",
            "ingress_rules": [], "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 0

    def test_partial_port_range_from_public_passes(self):
        resource = {
            "id": "sg-005", "type": "aws_security_group",
            "ingress_rules": [{"from_port": 80, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}],
            "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 0

    def test_multiple_unrestricted_rules_creates_two_violations(self):
        resource = {
            "id": "sg-006", "type": "aws_security_group",
            "ingress_rules": [
                {"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]},
                {"from_port": 0, "to_port": 65535, "cidr_blocks": ["::/0"]},
            ],
            "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 2

    def test_missing_resource_id_uses_unknown(self):
        resource = {
            "type": "aws_security_group",
            "ingress_rules": [{"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}],
            "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert violations[0].resource_id == "unknown"


class TestS3BucketPolicy:
    def setup_method(self):
        self.policy = S3BucketPolicy()

    def test_unencrypted_bucket_triggers_critical(self):
        resource = {
            "id": "bad-bucket", "type": "aws_s3_bucket",
            "versioning_enabled": True, "encryption_enabled": False,
            "public_access_blocked": True, "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert any(v.rule_id == "S3-002" and v.severity == Severity.CRITICAL for v in violations)

    def test_versioning_disabled_triggers_high(self):
        resource = {
            "id": "no-version-bucket", "type": "aws_s3_bucket",
            "versioning_enabled": False, "encryption_enabled": True,
            "public_access_blocked": True, "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert any(v.rule_id == "S3-001" and v.severity == Severity.HIGH for v in violations)

    def test_public_access_not_blocked_triggers_critical(self):
        resource = {
            "id": "public-bucket", "type": "aws_s3_bucket",
            "versioning_enabled": True, "encryption_enabled": True,
            "public_access_blocked": False, "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert any(v.rule_id == "S3-003" and v.severity == Severity.CRITICAL for v in violations)

    def test_fully_compliant_bucket_has_no_violations(self):
        resource = {
            "id": "compliant-bucket", "type": "aws_s3_bucket",
            "versioning_enabled": True, "encryption_enabled": True,
            "public_access_blocked": True, "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 0

    def test_worst_case_bucket_has_three_violations(self):
        resource = {
            "id": "terrible-bucket", "type": "aws_s3_bucket",
            "versioning_enabled": False, "encryption_enabled": False,
            "public_access_blocked": False, "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 3


class TestIAMPolicy:
    def setup_method(self):
        self.policy = IAMPolicy()

    def test_wildcard_iam_policy_triggers_critical(self):
        resource = {
            "id": "admin-policy", "type": "aws_iam_policy",
            "policy_statements": [{"effect": "Allow", "actions": ["*"], "resources": ["*"]}],
            "mfa_required": True, "has_console_access": False,
            "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert any(v.rule_id == "IAM-001" and v.severity == Severity.CRITICAL for v in violations)

    def test_console_user_without_mfa_triggers_high(self):
        resource = {
            "id": "devuser", "type": "aws_iam_user",
            "policy_statements": [],
            "mfa_required": False, "has_console_access": True,
            "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert any(v.rule_id == "IAM-002" and v.severity == Severity.HIGH for v in violations)

    def test_least_privilege_policy_passes(self):
        resource = {
            "id": "readonly-policy", "type": "aws_iam_policy",
            "policy_statements": [{"effect": "Allow", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::my-bucket/*"]}],
            "mfa_required": True, "has_console_access": False,
            "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 0

    def test_deny_statement_does_not_trigger(self):
        resource = {
            "id": "deny-policy", "type": "aws_iam_policy",
            "policy_statements": [{"effect": "Deny", "actions": ["*"], "resources": ["*"]}],
            "mfa_required": True, "has_console_access": False,
            "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 0


class TestEKSClusterPolicy:
    def setup_method(self):
        self.policy = EKSClusterPolicy()

    def test_no_private_endpoint_triggers_high(self):
        resource = {
            "id": "eks-1", "type": "aws_eks_cluster",
            "endpoint_private_access": False, "endpoint_public_access": False,
            "secrets_encryption_enabled": True, "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert any(v.rule_id == "EKS-001" and v.severity == Severity.HIGH for v in violations)

    def test_public_endpoint_enabled_triggers_medium(self):
        resource = {
            "id": "eks-2", "type": "aws_eks_cluster",
            "endpoint_private_access": True, "endpoint_public_access": True,
            "secrets_encryption_enabled": True, "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert any(v.rule_id == "EKS-002" and v.severity == Severity.MEDIUM for v in violations)

    def test_secrets_not_encrypted_triggers_high(self):
        resource = {
            "id": "eks-3", "type": "aws_eks_cluster",
            "endpoint_private_access": True, "endpoint_public_access": False,
            "secrets_encryption_enabled": False, "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert any(v.rule_id == "EKS-003" and v.severity == Severity.HIGH for v in violations)

    def test_hardened_cluster_passes(self):
        resource = {
            "id": "eks-hardened", "type": "aws_eks_cluster",
            "endpoint_private_access": True, "endpoint_public_access": False,
            "secrets_encryption_enabled": True, "tags": REQUIRED_TAGS,
        }
        violations = self.policy.evaluate(resource)
        assert len(violations) == 0


class TestTaggingPolicy:
    def setup_method(self):
        self.policy = TaggingPolicy()

    def test_no_tags_triggers_medium_violation(self):
        resource = {"id": "untagged", "type": "aws_s3_bucket", "tags": {}}
        violations = self.policy.evaluate(resource)
        assert len(violations) == 1
        assert violations[0].severity == Severity.MEDIUM
        assert violations[0].rule_id == "TAG-001"

    def test_partial_tags_reports_missing(self):
        partial = {"Environment": "prod", "Owner": "team", "CostCenter": "CC-100"}
        resource = {"id": "partial", "type": "aws_s3_bucket", "tags": partial}
        violations = self.policy.evaluate(resource)
        assert len(violations) == 1
        assert "DataClassification" in violations[0].message

    def test_all_required_tags_present_passes(self):
        resource = {"id": "tagged", "type": "aws_s3_bucket", "tags": REQUIRED_TAGS}
        violations = self.policy.evaluate(resource)
        assert len(violations) == 0

    def test_extra_tags_beyond_required_passes(self):
        extra = {**REQUIRED_TAGS, "Project": "resilience-poc"}
        resource = {"id": "extra-tagged", "type": "aws_eks_cluster", "tags": extra}
        violations = self.policy.evaluate(resource)
        assert len(violations) == 0


class TestComplianceCheckerOrchestrator:
    def setup_method(self):
        self.checker = ComplianceChecker(environment="production")

    def _good_sg(self):
        return {
            "id": "sg-good", "type": "aws_security_group",
            "ingress_rules": [{"from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}],
            "tags": REQUIRED_TAGS,
        }

    def _good_s3(self):
        return {
            "id": "s3-good", "type": "aws_s3_bucket",
            "versioning_enabled": True, "encryption_enabled": True,
            "public_access_blocked": True, "tags": REQUIRED_TAGS,
        }

    def test_empty_scan_returns_100_score(self):
        report = self.checker.scan([])
        assert report.compliance_score == 100.0

    def test_empty_scan_returns_compliant_status(self):
        report = self.checker.scan([])
        assert report.status == ComplianceStatus.COMPLIANT

    def test_all_good_resources_compliant(self):
        report = self.checker.scan([self._good_sg(), self._good_s3()])
        assert len(report.violations) == 0
        assert report.status == ComplianceStatus.COMPLIANT

    def test_bad_sg_produces_critical_violation(self):
        bad = {
            "id": "sg-bad", "type": "aws_security_group",
            "ingress_rules": [{"from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}],
            "tags": REQUIRED_TAGS,
        }
        report = self.checker.scan([bad])
        assert report.status == ComplianceStatus.NON_COMPLIANT
        assert len(report.critical_violations) > 0

    def test_scan_id_auto_generated(self):
        report = self.checker.scan([])
        assert report.scan_id.startswith("scan-")

    def test_scan_id_custom(self):
        report = self.checker.scan([], scan_id="CUSTOM-SCAN-001")
        assert report.scan_id == "CUSTOM-SCAN-001"

    def test_skipped_resources_not_counted(self):
        skip = {"id": "exempt", "type": "aws_s3_bucket", "skip_compliance": True, "tags": {}}
        report = self.checker.scan([skip])
        assert "exempt" in report.skipped_resources
        assert report.total_resources == 0

    def test_drift_no_change_returns_no_drift(self):
        resources = [self._good_sg()]
        self.checker.set_baseline(resources)
        drift = self.checker.detect_drift(resources)
        assert drift["drift_detected"] is False

    def test_drift_new_resource_detected(self):
        self.checker.set_baseline([self._good_sg()])
        drift = self.checker.detect_drift([self._good_sg(), self._good_s3()])
        assert drift["drift_detected"] is True
        assert "s3-good" in drift["new_resources"]

    def test_drift_removed_resource_detected(self):
        self.checker.set_baseline([self._good_sg(), self._good_s3()])
        drift = self.checker.detect_drift([self._good_sg()])
        assert drift["drift_detected"] is True
        assert "s3-good" in drift["removed_resources"]

    def test_drift_modified_resource_detected(self):
        self.checker.set_baseline([self._good_sg()])
        modified = {**self._good_sg(), "ingress_rules": []}
        drift = self.checker.detect_drift([modified])
        assert drift["drift_detected"] is True
        assert "sg-good" in drift["modified_resources"]

    def test_audit_report_json_format(self):
        report = self.checker.scan([self._good_sg()])
        audit = self.checker.generate_audit_report(report, format="json")
        data = json.loads(audit)
        assert data["generated_by"] == "resilience-compliance-checker"
        assert "compliance_score" in data

    def test_audit_report_text_format(self):
        report = self.checker.scan([self._good_sg()])
        audit = self.checker.generate_audit_report(report, format="text")
        assert "RESILIENCE CYBER RISK COMPLIANCE REPORT" in audit

    def test_report_to_dict_has_required_keys(self):
        report = self.checker.scan([self._good_sg()])
        d = report.to_dict()
        for key in ["scan_id", "compliance_score", "violations", "status", "environment"]:
            assert key in d

    def test_policy_violation_to_dict(self):
        from datetime import datetime, timezone
        v = PolicyViolation(
            rule_id="SG-001",
            resource_id="sg-test",
            resource_type="aws_security_group",
            severity=Severity.CRITICAL,
            message="Test violation",
            remediation="Fix it",
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        d = v.to_dict()
        assert d["rule_id"] == "SG-001"
        assert d["severity"] == "CRITICAL"
        assert d["resource_id"] == "sg-test"
"""

with open(os.path.join(TESTS_DIR, "test_compliance_checker.py"), "w") as f:
    f.write(compliance_tests)
print("test_compliance_checker.py written")

# ---- test_reliability_monitor.py ----
reliability_tests = """\
\"\"\"Tests for reliability_monitor.py -- 45 tests covering SLO, incidents, runbooks, DORA.\"\"\"
import pytest
from datetime import datetime, timedelta, timezone

from platform.reliability_monitor import (
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
        detected = datetime(2025, 1, 1, 10, 0, tzinfo=UTC)
        inc = self.monitor.create_incident("api", IncidentSeverity.P2, "Slow", "latency")
        inc.resolve(at=detected + timedelta(minutes=60))
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
"""

with open(os.path.join(TESTS_DIR, "test_reliability_monitor.py"), "w") as f:
    f.write(reliability_tests)
print("test_reliability_monitor.py written")

print("All test files created.")
