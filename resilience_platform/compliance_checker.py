"""
Compliance Checker — Automated compliance reporting for cyber risk platform.

Validates infrastructure against cyber insurance security standards including:
- OPA policy-as-code evaluation
- AWS security controls drift detection
- CIS benchmark compliance checks
- Automated audit report generation
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ComplianceStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    UNKNOWN = "UNKNOWN"
    SKIPPED = "SKIPPED"


@dataclass
class PolicyViolation:
    rule_id: str
    resource_id: str
    resource_type: str
    severity: Severity
    message: str
    remediation: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "severity": self.severity.value,
            "message": self.message,
            "remediation": self.remediation,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ComplianceReport:
    scan_id: str
    environment: str
    scanned_at: datetime
    total_resources: int
    compliant_resources: int
    violations: list[PolicyViolation] = field(default_factory=list)
    skipped_resources: list[str] = field(default_factory=list)

    @property
    def compliance_score(self) -> float:
        if self.total_resources == 0:
            return 100.0
        return (self.compliant_resources / self.total_resources) * 100

    @property
    def critical_violations(self) -> list[PolicyViolation]:
        return [v for v in self.violations if v.severity == Severity.CRITICAL]

    @property
    def high_violations(self) -> list[PolicyViolation]:
        return [v for v in self.violations if v.severity == Severity.HIGH]

    @property
    def status(self) -> ComplianceStatus:
        if any(v.severity == Severity.CRITICAL for v in self.violations):
            return ComplianceStatus.NON_COMPLIANT
        if len(self.high_violations) > 5:
            return ComplianceStatus.NON_COMPLIANT
        if self.compliance_score >= 90:
            return ComplianceStatus.COMPLIANT
        return ComplianceStatus.NON_COMPLIANT

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "environment": self.environment,
            "scanned_at": self.scanned_at.isoformat(),
            "total_resources": self.total_resources,
            "compliant_resources": self.compliant_resources,
            "compliance_score": round(self.compliance_score, 2),
            "status": self.status.value,
            "violations": [v.to_dict() for v in self.violations],
            "critical_count": len(self.critical_violations),
            "high_count": len(self.high_violations),
            "skipped_resources": self.skipped_resources,
        }


class SecurityGroupPolicy:
    """OPA-equivalent policy for AWS Security Group compliance."""

    RULE_ID = "SG-001"

    def evaluate(self, resource: dict[str, Any]) -> list[PolicyViolation]:
        violations = []
        resource_id = resource.get("id", "unknown")

        for rule in resource.get("ingress_rules", []):
            if rule.get("from_port") == 0 and rule.get("to_port") == 65535:
                for cidr in rule.get("cidr_blocks", []):
                    if cidr in ("0.0.0.0/0", "::/0"):
                        violations.append(PolicyViolation(
                            rule_id=self.RULE_ID,
                            resource_id=resource_id,
                            resource_type="aws_security_group",
                            severity=Severity.CRITICAL,
                            message=f"Security group {resource_id} allows unrestricted ingress on all ports from {cidr}",
                            remediation="Restrict ingress rules to specific ports and CIDR ranges required for business operations.",
                        ))
        return violations


class S3BucketPolicy:
    """Policy for AWS S3 bucket security compliance."""

    def evaluate(self, resource: dict[str, Any]) -> list[PolicyViolation]:
        violations = []
        resource_id = resource.get("id", "unknown")

        if not resource.get("versioning_enabled", False):
            violations.append(PolicyViolation(
                rule_id="S3-001",
                resource_id=resource_id,
                resource_type="aws_s3_bucket",
                severity=Severity.HIGH,
                message=f"S3 bucket {resource_id} does not have versioning enabled",
                remediation="Enable S3 versioning to protect against accidental deletion and support audit requirements.",
            ))

        if not resource.get("encryption_enabled", False):
            violations.append(PolicyViolation(
                rule_id="S3-002",
                resource_id=resource_id,
                resource_type="aws_s3_bucket",
                severity=Severity.CRITICAL,
                message=f"S3 bucket {resource_id} does not have server-side encryption enabled",
                remediation="Enable SSE-KMS encryption on S3 buckets storing sensitive cyber risk data.",
            ))

        if resource.get("public_access_blocked", True) is False:
            violations.append(PolicyViolation(
                rule_id="S3-003",
                resource_id=resource_id,
                resource_type="aws_s3_bucket",
                severity=Severity.CRITICAL,
                message=f"S3 bucket {resource_id} does not block public access",
                remediation="Enable all S3 Block Public Access settings for buckets containing sensitive data.",
            ))

        return violations


class IAMPolicy:
    """Policy for AWS IAM security compliance."""

    def evaluate(self, resource: dict[str, Any]) -> list[PolicyViolation]:
        violations = []
        resource_id = resource.get("id", "unknown")

        for statement in resource.get("policy_statements", []):
            if (statement.get("effect") == "Allow"
                    and statement.get("actions") == ["*"]
                    and statement.get("resources") == ["*"]):
                violations.append(PolicyViolation(
                    rule_id="IAM-001",
                    resource_id=resource_id,
                    resource_type="aws_iam_policy",
                    severity=Severity.CRITICAL,
                    message=f"IAM policy {resource_id} grants wildcard permissions (Action: *, Resource: *)",
                    remediation="Apply principle of least privilege — restrict actions and resources to minimum required.",
                ))

        if resource.get("mfa_required") is False and resource.get("has_console_access"):
            violations.append(PolicyViolation(
                rule_id="IAM-002",
                resource_id=resource_id,
                resource_type="aws_iam_user",
                severity=Severity.HIGH,
                message=f"IAM user {resource_id} has console access without MFA requirement",
                remediation="Enforce MFA for all IAM users with console access.",
            ))

        return violations


class EKSClusterPolicy:
    """Policy for AWS EKS cluster security compliance."""

    def evaluate(self, resource: dict[str, Any]) -> list[PolicyViolation]:
        violations = []
        resource_id = resource.get("id", "unknown")

        if not resource.get("endpoint_private_access", False):
            violations.append(PolicyViolation(
                rule_id="EKS-001",
                resource_id=resource_id,
                resource_type="aws_eks_cluster",
                severity=Severity.HIGH,
                message=f"EKS cluster {resource_id} does not have private endpoint access enabled",
                remediation="Enable private endpoint access for EKS API server to reduce attack surface.",
            ))

        if resource.get("endpoint_public_access", True):
            violations.append(PolicyViolation(
                rule_id="EKS-002",
                resource_id=resource_id,
                resource_type="aws_eks_cluster",
                severity=Severity.MEDIUM,
                message=f"EKS cluster {resource_id} has public endpoint access enabled",
                remediation="Restrict EKS public endpoint or disable it — use VPN/bastion for cluster access.",
            ))

        if not resource.get("secrets_encryption_enabled", False):
            violations.append(PolicyViolation(
                rule_id="EKS-003",
                resource_id=resource_id,
                resource_type="aws_eks_cluster",
                severity=Severity.HIGH,
                message=f"EKS cluster {resource_id} does not have secrets encryption enabled",
                remediation="Enable envelope encryption for Kubernetes secrets using AWS KMS.",
            ))

        return violations


class TaggingPolicy:
    """Policy for resource tagging compliance."""

    REQUIRED_TAGS = {"Environment", "Owner", "CostCenter", "DataClassification"}

    def evaluate(self, resource: dict[str, Any]) -> list[PolicyViolation]:
        violations = []
        resource_id = resource.get("id", "unknown")
        resource_type = resource.get("type", "unknown")
        tags = set(resource.get("tags", {}).keys())
        missing_tags = self.REQUIRED_TAGS - tags

        if missing_tags:
            violations.append(PolicyViolation(
                rule_id="TAG-001",
                resource_id=resource_id,
                resource_type=resource_type,
                severity=Severity.MEDIUM,
                message=f"Resource {resource_id} is missing required tags: {', '.join(sorted(missing_tags))}",
                remediation=f"Add required tags: {', '.join(sorted(self.REQUIRED_TAGS))} to all cloud resources.",
            ))

        return violations


class ComplianceChecker:
    """
    Orchestrates compliance policy evaluation across infrastructure resources.

    Supports:
    - OPA-equivalent policy evaluation
    - Drift detection against baseline
    - Audit report generation
    - Cyber risk compliance scoring
    """

    def __init__(self, environment: str = "production") -> None:
        self.environment = environment
        self.policies = [
            SecurityGroupPolicy(),
            S3BucketPolicy(),
            IAMPolicy(),
            EKSClusterPolicy(),
            TaggingPolicy(),
        ]
        self._baseline: dict[str, Any] = {}

    def evaluate_resource(self, resource: dict[str, Any]) -> list[PolicyViolation]:
        """Evaluate a single resource against all applicable policies."""
        violations: list[PolicyViolation] = []
        resource_type = resource.get("type", "")

        policy_map = {
            "aws_security_group": [SecurityGroupPolicy, TaggingPolicy],
            "aws_s3_bucket": [S3BucketPolicy, TaggingPolicy],
            "aws_iam_policy": [IAMPolicy],
            "aws_iam_user": [IAMPolicy],
            "aws_eks_cluster": [EKSClusterPolicy, TaggingPolicy],
        }

        applicable_policy_types = policy_map.get(resource_type, [TaggingPolicy])

        for policy in self.policies:
            if type(policy) in applicable_policy_types:
                try:
                    violations.extend(policy.evaluate(resource))
                except Exception as exc:
                    logger.warning("Policy %s failed for resource %s: %s",
                                   type(policy).__name__, resource.get("id"), exc)

        return violations

    def scan(self, resources: list[dict[str, Any]], scan_id: str | None = None) -> ComplianceReport:
        """Scan a list of resources and return a compliance report."""
        if scan_id is None:
            scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

        all_violations: list[PolicyViolation] = []
        compliant_count = 0
        skipped: list[str] = []

        for resource in resources:
            if resource.get("skip_compliance"):
                skipped.append(resource.get("id", "unknown"))
                continue

            resource_violations = self.evaluate_resource(resource)
            if not resource_violations:
                compliant_count += 1
            all_violations.extend(resource_violations)

        return ComplianceReport(
            scan_id=scan_id,
            environment=self.environment,
            scanned_at=datetime.now(timezone.utc),
            total_resources=len(resources) - len(skipped),
            compliant_resources=compliant_count,
            violations=all_violations,
            skipped_resources=skipped,
        )

    def set_baseline(self, resources: list[dict[str, Any]]) -> None:
        """Set the compliance baseline for drift detection."""
        self._baseline = {r["id"]: r for r in resources if "id" in r}

    def detect_drift(self, current_resources: list[dict[str, Any]]) -> dict[str, Any]:
        """Detect configuration drift from the established baseline."""
        drift_report: dict[str, Any] = {
            "new_resources": [],
            "removed_resources": [],
            "modified_resources": [],
            "drift_detected": False,
        }

        current_map = {r["id"]: r for r in current_resources if "id" in r}

        for resource_id, baseline_resource in self._baseline.items():
            if resource_id not in current_map:
                drift_report["removed_resources"].append(resource_id)
                drift_report["drift_detected"] = True
            elif current_map[resource_id] != baseline_resource:
                drift_report["modified_resources"].append(resource_id)
                drift_report["drift_detected"] = True

        for resource_id in current_map:
            if resource_id not in self._baseline:
                drift_report["new_resources"].append(resource_id)
                drift_report["drift_detected"] = True

        return drift_report

    def generate_audit_report(
        self,
        report: ComplianceReport,
        format: str = "json",
    ) -> str:
        """Generate a formatted audit report for cyber risk compliance."""
        data = report.to_dict()
        data["generated_by"] = "resilience-compliance-checker"
        data["framework"] = "cyber-risk-platform-v1"

        if format == "json":
            return json.dumps(data, indent=2)

        # Text format
        lines = [
            f"RESILIENCE CYBER RISK COMPLIANCE REPORT",
            f"{'=' * 50}",
            f"Scan ID:      {report.scan_id}",
            f"Environment:  {report.environment}",
            f"Scanned at:   {report.scanned_at.isoformat()}",
            f"Status:       {report.status.value}",
            f"Score:        {report.compliance_score:.1f}%",
            f"",
            f"Resources:    {report.total_resources} total / {report.compliant_resources} compliant",
            f"Violations:   {len(report.violations)} total",
            f"  Critical:   {len(report.critical_violations)}",
            f"  High:       {len(report.high_violations)}",
            f"",
        ]

        if report.violations:
            lines.append("VIOLATIONS:")
            for v in report.violations:
                lines.append(f"  [{v.severity.value}] {v.rule_id}: {v.message}")

        return "\n".join(lines)
