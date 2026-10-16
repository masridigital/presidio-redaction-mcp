#!/usr/bin/env bash
# Native install entrypoint. Implementation lives in host/install.sh.
set -euo pipefail
exec bash "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/host/install.sh" "$@"
