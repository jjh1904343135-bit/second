#!/usr/bin/env bash
set -euo pipefail
exec bash "$(dirname "$0")/run_core.sh" experiment2 "$@"
