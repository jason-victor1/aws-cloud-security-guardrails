# Synthetic Sample Fixtures and Demo Outputs

This directory contains synthetic sample data for demonstrating the AWS Cloud Security Guardrails workflow without connecting to AWS or exposing real account data.

## Safety Notice

All sample data is synthetic.

Do not commit:

- real AWS account IDs
- real access keys
- real secret keys
- real bucket names
- real security group IDs
- real CloudTrail ARNs
- real scan outputs
- normalized findings from real environments
- generated reports from real environments

## Directory Structure

```text
samples/
  raw/
    iam-key-age-findings.json
    security-group-findings.json
    public-s3-findings.json
    cloudtrail-findings.json
  normalized/
    normalized-findings.json
  reports/
    remediation-backlog.md
    remediation-tickets.json
    executive-summary.md
```

## Demo Workflow

The workflow demonstrates:

```text
synthetic raw findings
→ finding normalizer
→ combined normalized findings
→ remediation ticket generator
→ executive summary generator
```

## Regenerate Demo Outputs

From repo root, run:

```bash
mkdir -p /tmp/aws-guardrails-demo
```

Normalize each raw fixture:

```bash
python3 automation/finding-normalizer.py \
  --source iam-key-age-check \
  --input samples/raw/iam-key-age-findings.json \
  --output /tmp/aws-guardrails-demo/iam-normalized.json

python3 automation/finding-normalizer.py \
  --source security-group-risk-check \
  --input samples/raw/security-group-findings.json \
  --output /tmp/aws-guardrails-demo/sg-normalized.json

python3 automation/finding-normalizer.py \
  --source public-s3-check \
  --input samples/raw/public-s3-findings.json \
  --output /tmp/aws-guardrails-demo/s3-normalized.json

python3 automation/finding-normalizer.py \
  --source cloudtrail-coverage-check \
  --input samples/raw/cloudtrail-findings.json \
  --output /tmp/aws-guardrails-demo/cloudtrail-normalized.json
```

Combine normalized findings into one demo file:

```bash
python3 - <<'PY'
import json
from pathlib import Path

inputs = [
    "/tmp/aws-guardrails-demo/iam-normalized.json",
    "/tmp/aws-guardrails-demo/sg-normalized.json",
    "/tmp/aws-guardrails-demo/s3-normalized.json",
    "/tmp/aws-guardrails-demo/cloudtrail-normalized.json",
]

findings = []

for path in inputs:
    payload = json.loads(Path(path).read_text())
    findings.extend(payload.get("findings", []))

combined = {
    "schema_version": "1.0",
    "finding_count": len(findings),
    "findings": findings,
}

Path("samples/normalized/normalized-findings.json").write_text(
    json.dumps(combined, indent=2) + "\n"
)
PY
```

Generate remediation outputs:

```bash
python3 automation/remediation-ticket-generator.py \
  --input samples/normalized/normalized-findings.json \
  --format markdown \
  --output samples/reports/remediation-backlog.md

python3 automation/remediation-ticket-generator.py \
  --input samples/normalized/normalized-findings.json \
  --format json \
  --output samples/reports/remediation-tickets.json
```

Generate executive summary:

```bash
python3 automation/executive-summary-generator.py \
  --input samples/normalized/normalized-findings.json \
  --output samples/reports/executive-summary.md
```

## One-Command Regeneration

From repo root, regenerate all demo outputs with:

```bash
./scripts/regenerate-demo-outputs.sh

The script regenerates:

samples/normalized/normalized-findings.json
samples/reports/remediation-backlog.md
samples/reports/remediation-tickets.json
samples/reports/executive-summary.md

The script is local-only and demo-only. It uses synthetic files under samples/, does not require AWS credentials, does not call AWS APIs, and does not deploy infrastructure.
```

## Expected Demo Outputs

After regeneration, the demo output files should exist:

```text
samples/normalized/normalized-findings.json
samples/reports/remediation-backlog.md
samples/reports/remediation-tickets.json
samples/reports/executive-summary.md
```

## Intended Use

These samples are intended for:

- portfolio demonstration
- local workflow testing
- documentation examples
- future automated tests

They are not evidence from a real AWS account.
