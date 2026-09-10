#!/usr/bin/env bash
set -euo pipefail

echo "VALIDATING"

if ! command -v terraform >/dev/null 2>&1; then
  echo "BLOCKED: terraform not installed"
  exit 2
fi

if [[ -d terraform ]]; then
  echo "PASS: terraform directory discovered"
else
  echo "FAIL: terraform directory missing"
  exit 1
fi

echo "PASS: validation gate reached execution stage"
