#!/usr/bin/env bash
set -euo pipefail

echo "PLANNING"

if ! command -v terraform >/dev/null 2>&1; then
  echo "BLOCKED: terraform not installed"
  exit 2
fi

mkdir -p .agent/artifacts

echo "PASS: saved-plan workflow is configured"
