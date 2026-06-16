# Tests

This directory contains local unit tests for the AWS Cloud Security Guardrails workflow processors.

## Scope

Current tests cover:

- finding normalization
- remediation ticket generation
- executive summary generation
- deterministic timestamp behavior
- malformed input handling

## Safety Model

The tests use synthetic fixtures only.

They do not:

- require AWS credentials
- call AWS APIs
- deploy infrastructure
- read real scan outputs
- write real environment evidence

## Run Tests

From the repository root:

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```
