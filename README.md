# Resilience DevOps Platform POC

A production-grade DevOps platform demonstrating cyber insurance/risk platform infrastructure engineering with Kubernetes, AWS, Terraform, compliance automation, security monitoring, CI/CD, and reliability engineering.

## Overview

This POC demonstrates the core infrastructure engineering capabilities required for a Senior DevOps Engineer role at Resilience — a cyber insurance and risk platform company. It showcases:

- **Multi-cloud IaC** — Terraform modules for AWS EKS, Fargate, and GCP GKE with remote state and OPA policy-as-code
- **CI/CD with security gates** — GitHub Actions pipelines with Nx monorepo caching, Trivy/Checkov/Snyk scanning, and canary deployments
- **Observability platform** — Prometheus + Grafana + Datadog SLO dashboards, CloudWatch alarms, and structured logging
- **Compliance automation** — Automated security controls, drift detection, and cyber risk reporting aligned to insurance standards
- **Reliability engineering** — Chaos engineering tests, SLO tracking, and automated incident runbooks

## Architecture

```
resilience-devops-platform-poc/
├── infrastructure/
│   ├── terraform/
│   │   ├── modules/
│   │   │   ├── eks-cluster/        # AWS EKS cluster module
│   │   │   ├── fargate-profile/    # AWS Fargate serverless containers
│   │   │   ├── vpc-networking/     # VPC, subnets, security groups
│   │   │   └── observability/      # Prometheus, Grafana, Datadog stack
│   │   ├── environments/
│   │   │   ├── dev/
│   │   │   ├── staging/
│   │   │   └── prod/
│   │   └── opa-policies/           # OPA policy-as-code for compliance
├── cicd/
│   ├── github-actions/
│   │   ├── pipeline.yml            # Main CI/CD workflow
│   │   ├── security-gates.yml      # Trivy/Checkov/Snyk scanning
│   │   └── canary-deploy.yml       # Canary deployment with rollback
├── platform/
│   ├── compliance_checker.py       # Automated compliance reporting
│   ├── reliability_monitor.py      # SLO tracking and incident automation
│   └── security_monitor.py         # Security posture monitoring
└── tests/
    ├── test_compliance_checker.py  # 30+ compliance tests
    ├── test_reliability_monitor.py # 30+ reliability tests
    └── test_security_monitor.py    # 30+ security monitoring tests
```

## Tech Stack

| Category | Technologies |
|---|---|
| Cloud | AWS (EKS, Fargate, EC2, S3, RDS, Lambda, VPC, IAM), GCP (GKE, GCS) |
| Container Orchestration | Kubernetes, AWS EKS, AWS Fargate, Helm, Kustomize |
| Infrastructure as Code | Terraform, Terragrunt, OPA Policy-as-Code |
| CI/CD | GitHub Actions, Nx monorepo build caching |
| Security Scanning | Trivy, Checkov, Snyk, OPA |
| Observability | Prometheus, Grafana, Datadog, CloudWatch, OpenTelemetry |
| Languages | Python, Bash, HCL |
| Reliability | Chaos engineering, SLO tracking, automated runbooks |

## Key Features

### 1. Multi-Cloud Infrastructure (Terraform)

Terraform modules for AWS EKS cluster provisioning with Fargate profiles:

```hcl
module "eks_cluster" {
  source = "./modules/eks-cluster"

  cluster_name    = "resilience-platform"
  cluster_version = "1.29"
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets

  fargate_profiles = {
    default = {
      namespace = "default"
      labels    = { workload-type = "serverless" }
    }
  }
}
```

### 2. OPA Policy-as-Code (Compliance)

Automated compliance controls for cyber risk standards:

```rego
package resilience.security

deny[msg] {
  input.resource_type == "aws_security_group"
  rule := input.config.ingress[_]
  rule.from_port == 0
  rule.to_port == 65535
  rule.cidr_blocks[_] == "0.0.0.0/0"
  msg := "DENY: Security group allows unrestricted ingress — violates cyber risk policy"
}
```

### 3. GitHub Actions CI/CD with Monorepo Support

```yaml
# Nx-powered affected builds + parallel security gates
- name: Get affected projects
  run: npx nx affected:apps --base=origin/main

- name: Security scanning (parallel)
  strategy:
    matrix:
      scanner: [trivy, checkov, snyk]
```

### 4. SLO-Based Reliability

```python
# Automated SLO tracking and incident response
slo_config = SLOConfig(
    service="cyber-risk-api",
    availability_target=99.9,
    latency_p99_ms=500,
    error_budget_burn_rate_threshold=5.0
)
```

## Running the Tests

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=platform --cov-report=term-missing -v
```

## Test Coverage

- **Compliance Checker**: 30 tests covering policy validation, drift detection, audit reporting
- **Reliability Monitor**: 30 tests covering SLO tracking, incident detection, runbook automation
- **Security Monitor**: 30 tests covering vulnerability scanning, threat detection, posture scoring

Total: **90+ test cases**

## Demonstration Areas

This POC directly addresses Resilience's engineering requirements:

1. **Cloud-native platform engineering** — AWS EKS + Fargate multi-cloud architecture
2. **CI/CD optimization** — Nx monorepo caching, parallel security gates, canary deployments
3. **Observability** — Prometheus/Grafana/Datadog SLO dashboards, CloudWatch alarms
4. **Compliance automation** — OPA policy-as-code aligned to cyber insurance risk standards
5. **Reliability engineering** — Chaos testing, automated runbooks, SLO-driven operations

## Author

Ram Gopal Reddy Basireddy
Senior DevOps Engineer | AWS · Kubernetes · Terraform · GitHub Actions
[LinkedIn](https://www.linkedin.com/in/ram-ba-29b110261/) | [GitHub](https://github.com/ramagopalb)
