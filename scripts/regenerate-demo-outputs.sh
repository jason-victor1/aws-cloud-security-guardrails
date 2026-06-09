#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

require_file() {
  [[ -f "$1" ]] || fail "Required file not found: $1"
}

require_dir() {
  [[ -d "$1" ]] || fail "Required directory not found: $1"
}

echo "Starting synthetic demo output regeneration..."

require_command python3

# Confirm script is being run from the repository root.
require_dir "automation"
require_dir "samples"
require_file "automation/finding-normalizer.py"
require_file "automation/remediation-ticket-generator.py"
require_file "automation/executive-summary-generator.py"

require_file "samples/raw/iam-key-age-findings.json"
require_file "samples/raw/security-group-findings.json"
require_file "samples/raw/public-s3-findings.json"
require_file "samples/raw/cloudtrail-findings.json"

mkdir -p samples/normalized samples/reports

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Normalizing synthetic IAM key age findings..."
python3 automation/finding-normalizer.py \
  --source iam-key-age-check \
  --input samples/raw/iam-key-age-findings.json \
  --output "$TMP_DIR/iam-normalized.json"

echo "Normalizing synthetic security group findings..."
python3 automation/finding-normalizer.py \
  --source security-group-risk-check \
  --input samples/raw/security-group-findings.json \
  --output "$TMP_DIR/sg-normalized.json"

echo "Normalizing synthetic public S3 findings..."
python3 automation/finding-normalizer.py \
  --source public-s3-check \
  --input samples/raw/public-s3-findings.json \
  --output "$TMP_DIR/s3-normalized.json"

echo "Normalizing synthetic CloudTrail findings..."
python3 automation/finding-normalizer.py \
  --source cloudtrail-coverage-check \
  --input samples/raw/cloudtrail-findings.json \
  --output "$TMP_DIR/cloudtrail-normalized.json"

echo "Combining normalized findings..."
python3 - <<PY
import json
from pathlib import Path

inputs = [
    "$TMP_DIR/iam-normalized.json",
    "$TMP_DIR/sg-normalized.json",
    "$TMP_DIR/s3-normalized.json",
    "$TMP_DIR/cloudtrail-normalized.json",
]

findings = []

for path in inputs:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    findings.extend(payload.get("findings", []))

combined = {
    "schema_version": "1.0",
    "finding_count": len(findings),
    "findings": findings,
}

Path("samples/normalized/normalized-findings.json").write_text(
    json.dumps(combined, indent=2) + "\\n",
    encoding="utf-8",
)
PY

echo "Generating Markdown remediation backlog..."
python3 automation/remediation-ticket-generator.py \
  --input samples/normalized/normalized-findings.json \
  --format markdown \
  --output samples/reports/remediation-backlog.md

echo "Generating JSON remediation tickets..."
python3 automation/remediation-ticket-generator.py \
  --input samples/normalized/normalized-findings.json \
  --format json \
  --output samples/reports/remediation-tickets.json

echo "Generating Markdown executive summary..."
python3 automation/executive-summary-generator.py \
  --input samples/normalized/normalized-findings.json \
  --output samples/reports/executive-summary.md

echo "Validating regenerated JSON outputs..."
python3 -m json.tool samples/normalized/normalized-findings.json > /dev/null
python3 -m json.tool samples/reports/remediation-tickets.json > /dev/null

echo "Synthetic demo outputs regenerated successfully."
echo
echo "Updated files:"
echo "- samples/normalized/normalized-findings.json"
echo "- samples/reports/remediation-backlog.md"
echo "- samples/reports/remediation-tickets.json"
echo "- samples/reports/executive-summary.md"