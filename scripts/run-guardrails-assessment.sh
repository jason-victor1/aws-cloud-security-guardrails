#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

info() {
  echo "==> $*"
}

usage() {
  cat <<'USAGE'
Usage:
  Live mode:
    scripts/run-guardrails-assessment.sh --profile <aws-profile> --output-dir <external-output-dir> [--region <aws-region>]

  Synthetic mode:
    scripts/run-guardrails-assessment.sh --mode synthetic --output-dir <external-output-dir>

Examples:
  scripts/run-guardrails-assessment.sh \
    --profile guardrails-readonly \
    --output-dir ~/aws-guardrails-lab-evidence/orchestrated-run \
    --region us-east-1

  scripts/run-guardrails-assessment.sh \
    --mode synthetic \
    --output-dir ~/aws-guardrails-lab-evidence/synthetic-orchestrator-test

Options:
  --mode         Execution mode: live or synthetic. Default: live.
  --synthetic    Shortcut for --mode synthetic.
  --profile      AWS CLI named profile to use for live read-only assessment. Required in live mode.
  --output-dir   External output directory. Must not be inside this repository.
  --region       AWS region for regional live checks. Default: us-east-1.
  -h, --help     Show this help message.

Safety:
  - Output directory must be outside the repository.
  - Live mode requires an explicit AWS profile.
  - Synthetic mode does not call AWS APIs and does not require AWS credentials.
  - Raw outputs, normalized findings, and generated reports are written outside Git.
  - The script does not run Terraform apply.
  - The script does not perform remediation.
  - The script prints only sanitized workflow-level status.
USAGE
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

resolve_path() {
  python3 - "$1" <<'PY'
import sys
from pathlib import Path
print(Path(sys.argv[1]).expanduser().resolve())
PY
}

is_path_inside() {
  python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path

child = Path(sys.argv[1]).expanduser().resolve()
parent = Path(sys.argv[2]).expanduser().resolve()

try:
    child.relative_to(parent)
    print("yes")
except ValueError:
    print("no")
PY
}

check_python_dependencies() {
  info "Checking Python automation dependencies"

  python3 - <<'PY'
try:
    import boto3
    import botocore
except ModuleNotFoundError as error:
    raise SystemExit(
        f"Missing Python dependency: {error.name}. "
        "Activate the project virtual environment or install automation/requirements.txt."
    )

print("Python dependencies available.")
PY
}

run_assessment_json() {
  local name="$1"
  local output_file="$2"
  local stderr_file="$3"
  shift 3

  info "Running ${name}"

  set +e
  "$@" > "$output_file" 2> "$stderr_file"
  local exit_code=$?
  set -e

  if [[ ! -s "$output_file" ]]; then
    fail "${name} did not produce JSON output. Check stderr log: ${stderr_file}"
  fi

  if ! python3 -m json.tool "$output_file" > /dev/null; then
    fail "${name} did not produce valid JSON. Check output file: ${output_file} and stderr log: ${stderr_file}"
  fi

  if [[ "$exit_code" -ge 2 ]]; then
    fail "${name} failed with exit code ${exit_code}. Check stderr log: ${stderr_file}"
  fi

  echo "${name} exit code: ${exit_code}" >> "$NOTES_DIR/assessment-exit-codes.txt"
}

copy_synthetic_raw_json() {
  info "Copying synthetic raw fixtures"

  cp samples/raw/iam-key-age-findings.json "$RAW_DIR/iam-key-age-findings.json"
  cp samples/raw/security-group-findings.json "$RAW_DIR/security-group-findings.json"
  cp samples/raw/public-s3-findings.json "$RAW_DIR/public-s3-findings.json"
  cp samples/raw/cloudtrail-findings.json "$RAW_DIR/cloudtrail-findings.json"

  python3 -m json.tool "$RAW_DIR/iam-key-age-findings.json" > /dev/null
  python3 -m json.tool "$RAW_DIR/security-group-findings.json" > /dev/null
  python3 -m json.tool "$RAW_DIR/public-s3-findings.json" > /dev/null
  python3 -m json.tool "$RAW_DIR/cloudtrail-findings.json" > /dev/null

  echo "synthetic-input-source: samples/raw" > "$NOTES_DIR/synthetic-mode-notes.txt"
  echo "aws-api-calls-used: no" >> "$NOTES_DIR/synthetic-mode-notes.txt"
  echo "aws-profile-required: no" >> "$NOTES_DIR/synthetic-mode-notes.txt"
}

confirm_live_identity() {
  info "Confirming AWS caller identity with STS"

  aws sts get-caller-identity \
    --profile "$PROFILE" \
    --output json \
    > "$NOTES_DIR/sts-caller-identity.raw.json"

  python3 - "$NOTES_DIR/sts-caller-identity.raw.json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text())
arn = data.get("Arn", "")

principal_type = "unknown"

if ":user/" in arn:
    principal_type = "iam-user"
elif ":role/" in arn:
    principal_type = "iam-role"
elif ":assumed-role/" in arn:
    principal_type = "assumed-role"

print("Sanitized STS confirmation:")
print("  account: <ACCOUNT_ID_REDACTED>")
print(f"  principal_type: {principal_type}")
print("  principal_name: <PRINCIPAL_NAME_REDACTED>")
print("  user_id: <USER_ID_REDACTED>")
PY
}

run_live_assessments() {
  info "Running read-only assessment scripts"

  run_assessment_json \
    "iam-key-age-check" \
    "$RAW_DIR/iam-key-age-findings.json" \
    "$NOTES_DIR/iam-key-age-check.stderr.log" \
    python3 automation/iam-key-age-check.py \
      --profile "$PROFILE" \
      --format json \
      --include-last-used

  run_assessment_json \
    "security-group-risk-check" \
    "$RAW_DIR/security-group-findings.json" \
    "$NOTES_DIR/security-group-risk-check.stderr.log" \
    python3 automation/security-group-risk-check.py \
      --profile "$PROFILE" \
      --region "$REGION" \
      --format json

  run_assessment_json \
    "public-s3-check" \
    "$RAW_DIR/public-s3-findings.json" \
    "$NOTES_DIR/public-s3-check.stderr.log" \
    python3 automation/public-s3-check.py \
      --profile "$PROFILE" \
      --format json

  run_assessment_json \
    "cloudtrail-coverage-check" \
    "$RAW_DIR/cloudtrail-findings.json" \
    "$NOTES_DIR/cloudtrail-coverage-check.stderr.log" \
    python3 automation/cloudtrail-coverage-check.py \
      --profile "$PROFILE" \
      --region "$REGION" \
      --format json
}

normalize_findings() {
  info "Normalizing findings"

  python3 automation/finding-normalizer.py \
    --source iam-key-age-check \
    --input "$RAW_DIR/iam-key-age-findings.json" \
    --output "$NORMALIZED_DIR/iam-key-age-normalized.json"

  python3 automation/finding-normalizer.py \
    --source security-group-risk-check \
    --input "$RAW_DIR/security-group-findings.json" \
    --output "$NORMALIZED_DIR/security-group-normalized.json"

  python3 automation/finding-normalizer.py \
    --source public-s3-check \
    --input "$RAW_DIR/public-s3-findings.json" \
    --output "$NORMALIZED_DIR/public-s3-normalized.json"

  python3 automation/finding-normalizer.py \
    --source cloudtrail-coverage-check \
    --input "$RAW_DIR/cloudtrail-findings.json" \
    --output "$NORMALIZED_DIR/cloudtrail-normalized.json"
}

combine_normalized_findings() {
  info "Combining normalized findings"

  python3 - "$NORMALIZED_DIR" "$MODE" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

base = Path(sys.argv[1])
mode = sys.argv[2]

inputs = [
    base / "iam-key-age-normalized.json",
    base / "security-group-normalized.json",
    base / "public-s3-normalized.json",
    base / "cloudtrail-normalized.json",
]

combined = []

for path in inputs:
    data = json.loads(path.read_text())

    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        combined.extend(data["findings"])
    elif isinstance(data, list):
        combined.extend(data)
    else:
        raise SystemExit(f"Unexpected normalized structure in {path.name}")

payload = {
    "schema_version": "1.0",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "source": f"{mode}-guardrails-assessment-orchestrator",
    "findings": combined,
}

output = base / "combined-normalized-findings.json"
output.write_text(json.dumps(payload, indent=2) + "\n")

print(f"Combined normalized finding count: {len(combined)}")
PY

  python3 -m json.tool "$NORMALIZED_DIR/combined-normalized-findings.json" > /dev/null
}

generate_reports() {
  info "Generating reports outside the repository"

  python3 automation/remediation-ticket-generator.py \
    --input "$NORMALIZED_DIR/combined-normalized-findings.json" \
    --format markdown \
    --output "$REPORTS_DIR/remediation-backlog.md"

  python3 automation/remediation-ticket-generator.py \
    --input "$NORMALIZED_DIR/combined-normalized-findings.json" \
    --format json \
    --output "$REPORTS_DIR/remediation-tickets.json"

  python3 -m json.tool "$REPORTS_DIR/remediation-tickets.json" > /dev/null

  python3 automation/executive-summary-generator.py \
    --input "$NORMALIZED_DIR/combined-normalized-findings.json" \
    --output "$REPORTS_DIR/executive-summary.md"
}

check_stderr_logs() {
  info "Checking stderr logs"

  python3 - "$NOTES_DIR" <<'PY'
from pathlib import Path
import sys

notes = Path(sys.argv[1])
logs = sorted(notes.glob("*.stderr.log"))

if not logs:
    print("No assessment stderr logs created for this mode.")
    raise SystemExit(0)

non_empty = []
for log in logs:
    if log.stat().st_size > 0:
        non_empty.append(log.name)

if non_empty:
    print("Non-empty stderr logs detected:")
    for name in non_empty:
        print(f"  {name}")
else:
    print("All assessment stderr logs are empty.")
PY
}

print_sanitized_summary() {
  info "Sanitized workflow summary"

  python3 - "$NORMALIZED_DIR/combined-normalized-findings.json" "$RESOLVED_OUTPUT_DIR" "$MODE" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

combined_path = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
mode = sys.argv[3]

data = json.loads(combined_path.read_text())
findings = data.get("findings", [])

severity_counts = Counter(str(finding.get("severity", "UNKNOWN")) for finding in findings)

print("Assessment pipeline completed successfully.")
print(f"Mode: {mode}")
print(f"Output directory: {output_dir}")
print(f"Total normalized findings: {len(findings)}")
print("Severity counts:")
for severity in sorted(severity_counts):
    print(f"  {severity}: {severity_counts[severity]}")
print("Generated artifacts:")
print("  raw/*.json")
print("  normalized/*.json")
print("  reports/remediation-backlog.md")
print("  reports/remediation-tickets.json")
print("  reports/executive-summary.md")
print("Security boundary:")
print("  Generated artifacts were written outside the repository.")
print("  Review and sanitize before sharing or committing any evidence.")
PY
}

MODE="live"
PROFILE=""
OUTPUT_DIR=""
REGION="us-east-1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ $# -ge 2 ]] || fail "--mode requires a value"
      MODE="$2"
      shift 2
      ;;
    --synthetic)
      MODE="synthetic"
      shift
      ;;
    --profile)
      [[ $# -ge 2 ]] || fail "--profile requires a value"
      PROFILE="$2"
      shift 2
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || fail "--output-dir requires a value"
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --region)
      [[ $# -ge 2 ]] || fail "--region requires a value"
      REGION="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

case "$MODE" in
  live|synthetic)
    ;;
  *)
    fail "--mode must be one of: live, synthetic"
    ;;
esac

[[ -n "$OUTPUT_DIR" ]] || fail "--output-dir is required"

if [[ "$MODE" == "live" ]]; then
  [[ -n "$PROFILE" ]] || fail "--profile is required in live mode"
else
  [[ -z "$PROFILE" ]] || fail "--profile must not be provided in synthetic mode"
fi

require_command git
require_command python3

if [[ "$MODE" == "live" ]]; then
  require_command aws
fi

check_python_dependencies

REPO_ROOT="$(git rev-parse --show-toplevel)"
CURRENT_DIR="$(pwd)"

[[ "$(resolve_path "$CURRENT_DIR")" == "$(resolve_path "$REPO_ROOT")" ]] || fail "Run this script from the repository root: $REPO_ROOT"

for required_path in \
  "automation/iam-key-age-check.py" \
  "automation/security-group-risk-check.py" \
  "automation/public-s3-check.py" \
  "automation/cloudtrail-coverage-check.py" \
  "automation/finding-normalizer.py" \
  "automation/remediation-ticket-generator.py" \
  "automation/executive-summary-generator.py"
do
  [[ -f "$required_path" ]] || fail "Required file missing: $required_path"
done

if [[ "$MODE" == "synthetic" ]]; then
  for required_path in \
    "samples/raw/iam-key-age-findings.json" \
    "samples/raw/security-group-findings.json" \
    "samples/raw/public-s3-findings.json" \
    "samples/raw/cloudtrail-findings.json"
  do
    [[ -f "$required_path" ]] || fail "Required synthetic fixture missing: $required_path"
  done
fi

RESOLVED_OUTPUT_DIR="$(resolve_path "$OUTPUT_DIR")"
RESOLVED_REPO_ROOT="$(resolve_path "$REPO_ROOT")"

if [[ "$(is_path_inside "$RESOLVED_OUTPUT_DIR" "$RESOLVED_REPO_ROOT")" == "yes" ]]; then
  fail "Output directory must not be inside the repository: $RESOLVED_OUTPUT_DIR"
fi

RAW_DIR="$RESOLVED_OUTPUT_DIR/raw"
NORMALIZED_DIR="$RESOLVED_OUTPUT_DIR/normalized"
REPORTS_DIR="$RESOLVED_OUTPUT_DIR/reports"
NOTES_DIR="$RESOLVED_OUTPUT_DIR/notes"

mkdir -p "$RAW_DIR" "$NORMALIZED_DIR" "$REPORTS_DIR" "$NOTES_DIR"

info "AWS Cloud Security Guardrails local assessment orchestrator"
info "Mode: $MODE"
info "Repository root confirmed"
info "Output directory: $RESOLVED_OUTPUT_DIR"
info "AWS region: $REGION"
info "Raw and generated outputs will remain outside the repository"

if [[ "$MODE" == "live" ]]; then
  info "AWS profile: $PROFILE"
  confirm_live_identity
  run_live_assessments
else
  info "Synthetic mode selected; AWS APIs will not be called"
  copy_synthetic_raw_json
fi

normalize_findings
combine_normalized_findings
generate_reports
check_stderr_logs
print_sanitized_summary

info "Complete"
