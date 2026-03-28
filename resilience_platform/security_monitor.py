"""
Security Monitor — Security posture monitoring for the Resilience cyber risk platform.

Provides:
- Vulnerability scanning result aggregation (Trivy, Snyk, Checkov)
- Security posture scoring for cyber insurance risk assessment
- Threat detection and alerting
- CSPM (Cloud Security Posture Management) checks
- Container image scanning and policy enforcement
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEGLIGIBLE = "NEGLIGIBLE"


class ScannerType(str, Enum):
    TRIVY = "trivy"
    SNYK = "snyk"
    CHECKOV = "checkov"
    OPA = "opa"
    CUSTOM = "custom"


class ThreatCategory(str, Enum):
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    CRYPTOMINING = "cryptomining"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"


@dataclass
class Vulnerability:
    vuln_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None
    severity: VulnerabilitySeverity
    description: str
    cvss_score: float
    resource_id: str
    scanner: ScannerType

    @property
    def is_fixable(self) -> bool:
        return self.fixed_version is not None and self.fixed_version != ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "resource_id": self.resource_id,
            "scanner": self.scanner.value,
            "is_fixable": self.is_fixable,
        }


@dataclass
class SecurityFinding:
    finding_id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    resource_id: str
    resource_type: str
    scanner: ScannerType
    check_id: str
    remediation: str
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    suppressed: bool = False
    suppression_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "scanner": self.scanner.value,
            "check_id": self.check_id,
            "remediation": self.remediation,
            "detected_at": self.detected_at.isoformat(),
            "suppressed": self.suppressed,
        }


@dataclass
class ThreatEvent:
    event_id: str
    category: ThreatCategory
    severity: VulnerabilitySeverity
    source_ip: str
    target_resource: str
    description: str
    detected_at: datetime
    indicators: list[str] = field(default_factory=list)
    mitigated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "target_resource": self.target_resource,
            "description": self.description,
            "detected_at": self.detected_at.isoformat(),
            "indicators": self.indicators,
            "mitigated": self.mitigated,
        }


@dataclass
class SecurityPostureScore:
    """Security posture score for cyber risk assessment."""
    overall_score: float  # 0-100
    vulnerability_score: float
    compliance_score: float
    threat_score: float
    configuration_score: float
    risk_level: str
    scored_at: datetime

    @classmethod
    def calculate(
        cls,
        vulnerabilities: list[Vulnerability],
        findings: list[SecurityFinding],
        threat_events: list[ThreatEvent],
        total_resources: int,
    ) -> "SecurityPostureScore":
        now = datetime.now(timezone.utc)

        # Vulnerability score (penalise by severity)
        vuln_penalty = sum(
            {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5, "NEGLIGIBLE": 0.1}
            .get(v.severity.value, 0)
            for v in vulnerabilities
            if not v.severity == VulnerabilitySeverity.NEGLIGIBLE
        )
        vuln_score = max(0.0, 100.0 - min(vuln_penalty, 100.0))

        # Compliance / findings score
        finding_penalty = sum(
            {"CRITICAL": 8, "HIGH": 4, "MEDIUM": 2, "LOW": 0.5, "NEGLIGIBLE": 0.1}
            .get(f.severity.value, 0)
            for f in findings
            if not f.suppressed
        )
        compliance_score = max(0.0, 100.0 - min(finding_penalty, 100.0))

        # Threat score
        active_threats = [t for t in threat_events if not t.mitigated]
        threat_penalty = sum(
            {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1}.get(t.severity.value, 0)
            for t in active_threats
        )
        threat_score = max(0.0, 100.0 - min(threat_penalty, 100.0))

        # Configuration score (based on finding density)
        if total_resources > 0:
            config_finding_rate = len([f for f in findings if not f.suppressed]) / total_resources
            configuration_score = max(0.0, 100.0 - (config_finding_rate * 50))
        else:
            configuration_score = 100.0

        overall = (vuln_score * 0.3 + compliance_score * 0.3 + threat_score * 0.25 + configuration_score * 0.15)

        risk_level = "LOW"
        if overall < 50:
            risk_level = "CRITICAL"
        elif overall < 65:
            risk_level = "HIGH"
        elif overall < 80:
            risk_level = "MEDIUM"

        return cls(
            overall_score=round(overall, 2),
            vulnerability_score=round(vuln_score, 2),
            compliance_score=round(compliance_score, 2),
            threat_score=round(threat_score, 2),
            configuration_score=round(configuration_score, 2),
            risk_level=risk_level,
            scored_at=now,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_score": self.overall_score,
            "vulnerability_score": self.vulnerability_score,
            "compliance_score": self.compliance_score,
            "threat_score": self.threat_score,
            "configuration_score": self.configuration_score,
            "risk_level": self.risk_level,
            "scored_at": self.scored_at.isoformat(),
        }


class VulnerabilityAggregator:
    """Aggregates vulnerability scan results from multiple scanners."""

    def __init__(self) -> None:
        self._vulnerabilities: list[Vulnerability] = []

    def ingest_trivy_report(self, report: dict[str, Any]) -> list[Vulnerability]:
        """Parse and ingest a Trivy vulnerability report."""
        ingested: list[Vulnerability] = []
        resource_id = report.get("ArtifactName", "unknown")

        for result in report.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                severity_str = vuln.get("Severity", "LOW").upper()
                try:
                    severity = VulnerabilitySeverity(severity_str)
                except ValueError:
                    severity = VulnerabilitySeverity.LOW

                v = Vulnerability(
                    vuln_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    package_name=vuln.get("PkgName", "unknown"),
                    installed_version=vuln.get("InstalledVersion", "unknown"),
                    fixed_version=vuln.get("FixedVersion"),
                    severity=severity,
                    description=vuln.get("Description", ""),
                    cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0),
                    resource_id=resource_id,
                    scanner=ScannerType.TRIVY,
                )
                self._vulnerabilities.append(v)
                ingested.append(v)

        return ingested

    def ingest_snyk_report(self, report: dict[str, Any]) -> list[Vulnerability]:
        """Parse and ingest a Snyk vulnerability report."""
        ingested: list[Vulnerability] = []
        resource_id = report.get("projectName", "unknown")

        for vuln in report.get("vulnerabilities", []):
            severity_str = vuln.get("severity", "low").upper()
            try:
                severity = VulnerabilitySeverity(severity_str)
            except ValueError:
                severity = VulnerabilitySeverity.LOW

            v = Vulnerability(
                vuln_id=vuln.get("id", "UNKNOWN"),
                package_name=vuln.get("packageName", "unknown"),
                installed_version=vuln.get("version", "unknown"),
                fixed_version=vuln.get("fixedIn", [None])[0] if vuln.get("fixedIn") else None,
                severity=severity,
                description=vuln.get("title", ""),
                cvss_score=vuln.get("cvssScore", 0.0),
                resource_id=resource_id,
                scanner=ScannerType.SNYK,
            )
            self._vulnerabilities.append(v)
            ingested.append(v)

        return ingested

    def get_summary(self) -> dict[str, Any]:
        """Get a vulnerability summary by severity."""
        total = len(self._vulnerabilities)
        by_severity: dict[str, int] = {}
        fixable = 0

        for v in self._vulnerabilities:
            key = v.severity.value
            by_severity[key] = by_severity.get(key, 0) + 1
            if v.is_fixable:
                fixable += 1

        return {
            "total": total,
            "by_severity": by_severity,
            "fixable": fixable,
            "critical": by_severity.get("CRITICAL", 0),
            "high": by_severity.get("HIGH", 0),
        }

    @property
    def vulnerabilities(self) -> list[Vulnerability]:
        return list(self._vulnerabilities)

    def critical_and_high(self) -> list[Vulnerability]:
        return [v for v in self._vulnerabilities
                if v.severity in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH)]


class SecurityMonitor:
    """
    Central security monitoring for the Resilience cyber risk platform.

    Aggregates findings from multiple scanners, tracks threats,
    calculates posture scores, and enforces security gates in CI/CD.
    """

    def __init__(self) -> None:
        self.aggregator = VulnerabilityAggregator()
        self.findings: list[SecurityFinding] = []
        self.threat_events: list[ThreatEvent] = []
        self._gate_policies: dict[str, int] = {
            "max_critical_vulns": 0,
            "max_high_vulns": 5,
            "min_posture_score": 70,
        }

    def add_finding(self, finding: SecurityFinding) -> None:
        self.findings.append(finding)

    def add_threat_event(self, event: ThreatEvent) -> None:
        self.threat_events.append(event)
        logger.warning("Threat detected [%s]: %s on %s",
                       event.severity.value, event.category.value, event.target_resource)

    def set_gate_policy(self, policy: dict[str, int]) -> None:
        """Configure CI/CD security gate thresholds."""
        self._gate_policies.update(policy)

    def evaluate_security_gate(self, total_resources: int = 10) -> dict[str, Any]:
        """
        Evaluate security gate for CI/CD pipeline.
        Returns pass/fail with details — used to block deployments.
        """
        posture = SecurityPostureScore.calculate(
            self.aggregator.vulnerabilities,
            self.findings,
            self.threat_events,
            total_resources,
        )

        vuln_summary = self.aggregator.get_summary()
        critical_count = vuln_summary.get("critical", 0)
        high_count = vuln_summary.get("high", 0)

        checks = []
        gate_passed = True

        # Check critical vulns
        max_critical = self._gate_policies["max_critical_vulns"]
        critical_pass = critical_count <= max_critical
        checks.append({
            "check": "critical_vulnerabilities",
            "threshold": f"<= {max_critical}",
            "actual": critical_count,
            "passed": critical_pass,
        })
        if not critical_pass:
            gate_passed = False

        # Check high vulns
        max_high = self._gate_policies["max_high_vulns"]
        high_pass = high_count <= max_high
        checks.append({
            "check": "high_vulnerabilities",
            "threshold": f"<= {max_high}",
            "actual": high_count,
            "passed": high_pass,
        })
        if not high_pass:
            gate_passed = False

        # Check posture score
        min_score = self._gate_policies["min_posture_score"]
        score_pass = posture.overall_score >= min_score
        checks.append({
            "check": "security_posture_score",
            "threshold": f">= {min_score}",
            "actual": posture.overall_score,
            "passed": score_pass,
        })
        if not score_pass:
            gate_passed = False

        return {
            "gate_passed": gate_passed,
            "posture": posture.to_dict(),
            "checks": checks,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

    def suppress_finding(self, finding_id: str, reason: str) -> bool:
        """Suppress a finding with a reason (for false positives)."""
        for finding in self.findings:
            if finding.finding_id == finding_id:
                finding.suppressed = True
                finding.suppression_reason = reason
                return True
        return False

    def get_active_threats(self) -> list[ThreatEvent]:
        return [t for t in self.threat_events if not t.mitigated]

    def get_posture_score(self, total_resources: int = 10) -> SecurityPostureScore:
        return SecurityPostureScore.calculate(
            self.aggregator.vulnerabilities,
            self.findings,
            self.threat_events,
            total_resources,
        )

    def generate_risk_report(self, total_resources: int = 10) -> dict[str, Any]:
        """Generate a cyber risk report suitable for insurance underwriting."""
        posture = self.get_posture_score(total_resources)
        vuln_summary = self.aggregator.get_summary()
        active_threats = self.get_active_threats()

        return {
            "report_type": "cyber_risk_assessment",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "posture_score": posture.to_dict(),
            "vulnerability_summary": vuln_summary,
            "active_threats": len(active_threats),
            "threat_categories": list({t.category.value for t in active_threats}),
            "total_findings": len([f for f in self.findings if not f.suppressed]),
            "suppressed_findings": len([f for f in self.findings if f.suppressed]),
            "risk_recommendation": (
                "ACCEPT" if posture.overall_score >= 80
                else "REVIEW" if posture.overall_score >= 60
                else "REMEDIATE"
            ),
        }
