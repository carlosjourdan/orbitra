#!/usr/bin/env bash
#
# check-tools.sh — Verify that required development tools are installed.
# Exit code 0 means all tools are present; non-zero means something is missing.

set -euo pipefail

REQUIRED_TOOLS=(git node npm python3 make curl)
MISSING=()

for tool in "${REQUIRED_TOOLS[@]}"; do
  if command -v "$tool" &>/dev/null; then
    version=$("$tool" --version 2>&1 | head -1)
    printf "  %-12s %s\n" "$tool" "$version"
  else
    MISSING+=("$tool")
    printf "  %-12s MISSING\n" "$tool"
  fi
done

echo ""

if [ ${#MISSING[@]} -eq 0 ]; then
  echo "All required tools are installed."
  exit 0
else
  echo "Missing tools: ${MISSING[*]}"
  echo "Please install the missing tools before continuing."
  exit 1
fi
