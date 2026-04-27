# Project Charter: AWS Cloud Security Guardrails

## Project Name

AWS Cloud Security Guardrails

## Objective

Build a practical AWS cloud security automation lab that identifies and reduces common AWS security risks through Terraform guardrails, CI/CD checks, lightweight automation scripts, remediation templates, and evidence-ready documentation.

## Target Audience

This project is designed for:

- cloud security teams
- DevSecOps teams
- platform engineering teams
- security automation teams
- startups preparing for SOC 2, HIPAA, NIST, or customer security reviews
- consulting or contract buyers needing a focused AWS security hardening sprint

## Buyer Problem

Cloud environments often grow faster than their security controls. Common gaps include:

- leaked credentials
- excessive IAM permissions
- public exposure of storage or services
- incomplete logging
- weak CI/CD controls
- missing remediation evidence
- cloud cost-abuse exposure from compromised credentials

## Success Criteria

V1 is successful when it demonstrates:

- a documented manual review workflow
- a threat model
- a control matrix
- Terraform guardrail examples
- CI/CD security workflows
- basic Python assessment scripts
- sample findings
- remediation backlog
- executive summary
- audit/evidence checklist

## Out of Scope for V1

V1 does not attempt to build:

- a full enterprise CSPM
- a commercial SOAR platform
- production-grade multi-account AWS landing zone
- full Kubernetes security program
- complete SOC 2/HIPAA/NIST certification package
- auto-remediation without human approval

## V1 Design Principle

Default to explainable, reviewable, low-blast-radius controls before automation that changes live infrastructure.
