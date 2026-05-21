#!/usr/bin/env bash
#
# systemd ExecStart wrapper: build the daily package, then publish it to the
# GitHub Pages branch. Publishing is skipped (with a warning, not an error) if
# THNC_PAGES_REPO is not configured, so the build still succeeds standalone.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${THNC_PYTHON:-/opt/thnewscaster/.venv/bin/python}"

echo "==> Building hunt package"
"${PYTHON}" -m thnewscaster --from-env

if [[ -n "${THNC_PAGES_REPO:-}" ]]; then
  echo "==> Publishing to GitHub Pages (${THNC_PAGES_BRANCH:-gh-pages})"
  "${HERE}/publish.sh"
else
  echo "==> THNC_PAGES_REPO unset — skipping GitHub Pages publish"
fi
