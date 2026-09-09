#!/usr/bin/env bash
set -euo pipefail

echo "SECURITY_SCANNING"

if ! command -v checkov >/dev/null 2>&1; then
  echo "BLOCKED: checkov not installed"
  exit 2
fi

checkov -d .
