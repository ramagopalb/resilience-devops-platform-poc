"""
Tests for security_monitor.py — 30 test cases covering vulnerability scanning,
threat detection, security posture scoring, CI/CD gate evaluation, and risk reporting.
"""

from datetime import datetime, timezone

import pytest

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from resilience_platform.security_monitor import (
    ScannerType,
    SecurityFinding,
    SecurityMonitor,
    SecurityPostureScore,
    ThreatCategory,
    ThreatEvent,
    Vulnerability,
    VulnerabilityAggregator,
    VulnerabilitySeverity,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def monitor():
    return SecurityMonitor()


@pytest.fixture
def aggregator():
    return VulnerabilityAggregator()


@pytest.fixture
def critical_vuln():
    return Vulnerability(
        vuln_id="CVE-2024-0001",
        package_name="openssl",
        installed_version="1.1.1",
        fixed_version="1.1.2",
        severity=VulnerabilitySeverity.CRITICAL,
        description="Remote code execution via buffer overflow",
        cvss_score=9.8,
        resource_id="image-api:latest",
        scanner=ScannerType.TRIVY,
    )


@pytest.fixture
def high_vuln():
    return Vulnerability(
        vuln_id="CVE-2024-0002",
        package_name="requests",
        installed_version="2.26.0",
        fixed_version="2.28.0",
        severity=VulnerabilitySeverity.HIGH,
        description="SSRF vulnerability",
        cvss_score=7.5,
        resource_id="image-worker:latest",
        scanner=ScannerType.SNYK,
    )


@pytest.fixture
def sample_finding():
    return SecurityFinding(
        finding_id="CKV-001",
        title="S3 bucket not encrypted",
        description="S3 bucket lacks server-side encryption",
        severity=VulnerabilitySeverity.HIGH,
        resource_id="bucket-risk-data",
        resource_type="aws_s3_bucket",
        scanner=ScannerType.CHECKOV,
        check_id="CKV_AWS_19",
        remediation="Enable SSE-KMS on S3 bucket",
    )


@pytest.fixture
def threat_event():
    return ThreatEvent(
        event_id="THREAT-001",
        category=ThreatCategory.UNAUTHORIZED_ACCESS,
        severity=VulnerabilitySeverity.HIGH,
        source_ip="198.51.100.1",
        target_resource="eks-cluster-prod",
        description="Multiple failed kubectl authentication attempts",
        detected_at=datetime.now(timezone.utc),
        indicators=["brute_force", "automated_scanner"],
    )


# ─── Vulnerability tests ─────────────────────────────────────────────────────

class TestVulnerability:
    def test_fixable_vuln(self, critical_vuln):
        assert critical_vuln.is_fixable is True

    def test_unfixable_vuln(self):
        v = Vulnerability(
            vuln_id="CVE-0000-0001", package_name="pkg", installed_version="1.0",
            fixed_version=None, severity=VulnerabilitySeverity.MEDIUM,
            description="No fix available", cvss_score=5.0,
            resource_id="res-001", scanner=ScannerType.TRIVY,
        )
        assert v.is_fixable is False

    def test_vuln_to_dict(self, critical_vuln):
        d = critical_vuln.to_dict()
        assert d["vuln_id"] == "CVE-2024-0001"
        assert d["severity"] == "CRITICAL"
        assert d["is_fixable"] is True


# ─── VulnerabilityAggregator tests ───────────────────────────────────────────

class TestVulnerabilityAggregator:
    def test_ingest_trivy_report(self, aggregator):
        report = {
            "ArtifactName": "api-image:latest",
            "Results": [{
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1001",
                        "PkgName": "libssl",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "CRITICAL",
                        "Description": "Critical SSL vulnerability",
                        "CVSS": {"nvd": {"V3Score": 9.1}},
                    }
                ]
            }]
        }
        vulns = aggregator.ingest_trivy_report(report)
        assert len(vulns) == 1
        assert vulns[0].severity == VulnerabilitySeverity.CRITICAL

    def test_ingest_snyk_report(self, aggregator):
        report = {
            "projectName": "worker-service",
            "vulnerabilities": [
                {
                    "id": "SNYK-001",
                    "packageName": "requests",
                    "version": "2.26.0",
                    "fixedIn": ["2.28.0"],
                    "severity": "high",
                    "title": "SSRF vulnerability",
                    "cvssScore": 7.5,
                }
            ]
        }
        vulns = aggregator.ingest_snyk_report(report)
        assert len(vulns) == 1
        assert vulns[0].scanner == ScannerType.SNYK

    def test_get_summary_by_severity(self, aggregator, critical_vuln, high_vuln):
        aggregator._vulnerabilities = [critical_vuln, high_vuln]
        summary = aggregator.get_summary()
        assert summary["critical"] == 1
        assert summary["high"] == 1

    def test_critical_and_high_filter(self, aggregator, critical_vuln, high_vuln):
        low_vuln = Vulnerability(
            vuln_id="CVE-LOW", package_name="pkg", installed_version="1.0",
            fixed_version=None, severity=VulnerabilitySeverity.LOW,
            description="Low severity", cvss_score=2.0,
            resource_id="res", scanner=ScannerType.TRIVY,
        )
        aggregator._vulnerabilities = [critical_vuln, high_vuln, low_vuln]
        result = aggregator.critical_and_high()
        assert len(result) == 2
        assert all(v.severity in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH) for v in result)

    def test_fixable_count_in_summary(self, aggregator, critical_vuln):
        aggregator._vulnerabilities = [critical_vuln]
        summary = aggregator.get_summary()
        assert summary["fixable"] == 1


# ─── SecurityFinding and ThreatEvent tests ───────────────────────────────────

class TestSecurityFinding:
    def test_finding_to_dict(self, sample_finding):
        d = sample_finding.to_dict()
        assert d["finding_id"] == "CKV-001"
        assert d["suppressed"] is False

    def test_threat_event_to_dict(self, threat_event):
        d = threat_event.to_dict()
        assert d["category"] == "unauthorized_access"
        assert "brute_force" in d["indicators"]


# ─── SecurityPostureScore tests ──────────────────────────────────────────────

class TestSecurityPostureScore:
    def test_no_issues_perfect_score(self):
        score = SecurityPostureScore.calculate([], [], [], total_resources=10)
        assert score.overall_score == 100.0
        assert score.risk_level == "LOW"

    def test_critical_vulns_lower_score(self, critical_vuln):
        score = SecurityPostureScore.calculate([critical_vuln] * 10, [], [], total_resources=10)
        assert score.overall_score <= 70.0

    def test_risk_level_critical(self, critical_vuln):
        score = SecurityPostureScore.calculate([critical_vuln] * 20, [], [], total_resources=10)
        assert score.risk_level in ("CRITICAL", "HIGH", "MEDIUM")

    def test_threat_events_impact_score(self, threat_event):
        score_no_threat = SecurityPostureScore.calculate([], [], [], total_resources=10)
        score_with_threat = SecurityPostureScore.calculate([], [], [threat_event], total_resources=10)
        assert score_with_threat.overall_score < score_no_threat.overall_score

    def test_score_to_dict(self):
        score = SecurityPostureScore.calculate([], [], [], total_resources=5)
        d = score.to_dict()
        assert "overall_score" in d
        assert "risk_level" in d


# ─── SecurityMonitor integration tests ───────────────────────────────────────

class TestSecurityMonitor:
    def test_add_finding(self, monitor, sample_finding):
        monitor.add_finding(sample_finding)
        assert sample_finding in monitor.findings

    def test_add_threat_event(self, monitor, threat_event):
        monitor.add_threat_event(threat_event)
        assert threat_event in monitor.threat_events

    def test_gate_pass_no_vulns(self, monitor):
        result = monitor.evaluate_security_gate(total_resources=10)
        assert result["gate_passed"] is True

    def test_gate_fail_critical_vuln(self, monitor, critical_vuln):
        monitor.aggregator._vulnerabilities = [critical_vuln]
        result = monitor.evaluate_security_gate(total_resources=10)
        assert result["gate_passed"] is False

    def test_gate_fail_too_many_high_vulns(self, monitor, high_vuln):
        monitor.aggregator._vulnerabilities = [high_vuln] * 10  # 10 high vulns > threshold of 5
        result = monitor.evaluate_security_gate(total_resources=10)
        assert result["gate_passed"] is False

    def test_gate_checks_structure(self, monitor):
        result = monitor.evaluate_security_gate(total_resources=10)
        assert "checks" in result
        assert len(result["checks"]) == 3

    def test_suppress_finding(self, monitor, sample_finding):
        monitor.add_finding(sample_finding)
        result = monitor.suppress_finding("CKV-001", reason="False positive — bucket has KMS encryption via Terraform")
        assert result is True
        assert monitor.findings[0].suppressed is True

    def test_suppress_nonexistent_finding(self, monitor):
        result = monitor.suppress_finding("NONEXISTENT-999", reason="test")
        assert result is False

    def test_get_active_threats(self, monitor, threat_event):
        monitor.add_threat_event(threat_event)
        active = monitor.get_active_threats()
        assert threat_event in active

    def test_mitigated_threats_excluded(self, monitor, threat_event):
        threat_event.mitigated = True
        monitor.add_threat_event(threat_event)
        active = monitor.get_active_threats()
        assert threat_event not in active

    def test_risk_report_structure(self, monitor):
        report = monitor.generate_risk_report(total_resources=10)
        assert "posture_score" in report
        assert "vulnerability_summary" in report
        assert "risk_recommendation" in report

    def test_risk_report_accept_recommendation(self, monitor):
        report = monitor.generate_risk_report(total_resources=10)
        assert report["risk_recommendation"] == "ACCEPT"

    def test_risk_report_remediate_recommendation(self, monitor, critical_vuln):
        monitor.aggregator._vulnerabilities = [critical_vuln] * 20
        report = monitor.generate_risk_report(total_resources=10)
        assert report["risk_recommendation"] in ("REMEDIATE", "REVIEW")

    def test_custom_gate_policy(self, monitor, critical_vuln):
        monitor.set_gate_policy({"max_critical_vulns": 1})
        monitor.aggregator._vulnerabilities = [critical_vuln]
        result = monitor.evaluate_security_gate(total_resources=10)
        critical_check = next(c for c in result["checks"] if c["check"] == "critical_vulnerabilities")
        assert critical_check["passed"] is True

    def test_posture_score_available(self, monitor):
        score = monitor.get_posture_score(total_resources=5)
        assert score is not None
        assert 0 <= score.overall_score <= 100
