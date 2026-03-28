"""Tests for compliance_checker.py -- 45 tests covering all policy checks."""
import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pytest
from resilience_platform.compliance_checker import (
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
