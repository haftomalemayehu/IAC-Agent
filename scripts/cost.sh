#!/usr/bin/env bash
set -euo pipefail

echo "ANALYZING_COST"

if ! command -v infracost >/dev/null 2>&1; then
  echo "BLOCKED: infracost not installed"
  exit 2
fi

infracost breakdown --path .
