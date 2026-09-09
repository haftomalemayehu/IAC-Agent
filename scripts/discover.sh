#!/usr/bin/env bash
set -euo pipefail

echo "DISCOVERING"

if ! command -v terraform >/dev/null 2>&1; then
  echo "BLOCKED: terraform not installed"
  exit 2
fi

printf 'Repository root: %s\n' "$(pwd)"
find . -maxdepth 3 \( -path './.git' -o -path './.gradle' -o -path './build' \) -prune -o -type f | sort | head -200

echo "PASS: repository discovery completed"
