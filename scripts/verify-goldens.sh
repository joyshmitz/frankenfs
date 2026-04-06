#!/usr/bin/env bash
# Legacy compatibility wrapper.
#
# The canonical golden verification gate is scripts/verify_golden.sh, which
# checks the tracked conformance artifacts and offloads cargo-heavy work via
# rch. Keep this filename as a shim so older notes/scripts do not silently
# diverge onto a separate verification path.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "scripts/verify-goldens.sh is deprecated; forwarding to scripts/verify_golden.sh" >&2
exec "${SCRIPT_DIR}/verify_golden.sh" "$@"
