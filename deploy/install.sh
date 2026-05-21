#!/usr/bin/env bash
#
# Install THNewsCaster as a daily systemd job on Ubuntu.
#
#   sudo ./deploy/install.sh
#
# Idempotent: safe to re-run to pick up code changes. It will (re)create the
# venv, reinstall the package, refresh the systemd units, and (re)enable the
# timer. It will NOT overwrite an existing /etc/thnewscaster/thnewscaster.env.
set -euo pipefail

APP_USER="thnewscaster"
INSTALL_DIR="/opt/thnewscaster"
STATE_DIR="/var/lib/thnewscaster"
CONF_DIR="/etc/thnewscaster"
ENV_FILE="${CONF_DIR}/thnewscaster.env"

# Resolve the repo root (this script lives in deploy/).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root (sudo $0)" >&2
  exit 1
fi

echo "==> Ensuring prerequisites (python3, venv)"
if ! command -v python3 >/dev/null 2>&1; then
  apt-get update && apt-get install -y python3 python3-venv
fi
python3 -m venv --help >/dev/null 2>&1 || apt-get install -y python3-venv

echo "==> Creating service account '${APP_USER}'"
if ! id -u "${APP_USER}" >/dev/null 2>&1; then
  useradd --system --home "${INSTALL_DIR}" --shell /usr/sbin/nologin "${APP_USER}"
fi

echo "==> Syncing application into ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
# Copy the package source and project metadata.
cp -r "${REPO_ROOT}/src" "${REPO_ROOT}/pyproject.toml" "${INSTALL_DIR}/"
cp -r "${REPO_ROOT}/README.md" "${INSTALL_DIR}/" 2>/dev/null || true

echo "==> Building virtualenv and installing package"
python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/.venv/bin/pip" install --quiet "${INSTALL_DIR}"

echo "==> Preparing state directory ${STATE_DIR}"
mkdir -p "${STATE_DIR}/site"
chown -R "${APP_USER}:${APP_USER}" "${INSTALL_DIR}" "${STATE_DIR}"

echo "==> Installing configuration"
mkdir -p "${CONF_DIR}"
if [[ -f "${ENV_FILE}" ]]; then
  echo "    ${ENV_FILE} already exists — leaving it untouched"
else
  cp "${REPO_ROOT}/deploy/thnewscaster.env.example" "${ENV_FILE}"
  chmod 640 "${ENV_FILE}"
  chown root:"${APP_USER}" "${ENV_FILE}"
  echo "    wrote ${ENV_FILE} — EDIT IT to set your OpenAI endpoint + key"
fi

echo "==> Installing systemd units"
cp "${REPO_ROOT}/deploy/thnewscaster.service" /etc/systemd/system/
cp "${REPO_ROOT}/deploy/thnewscaster.timer"   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now thnewscaster.timer

cat <<EOF

==> Done.

Next steps:
  1. Edit your endpoint + key:   sudoedit ${ENV_FILE}
  2. Trigger a run now:          sudo systemctl start thnewscaster.service
  3. Watch logs:                 journalctl -u thnewscaster.service -f
  4. Check the schedule:         systemctl list-timers thnewscaster.timer
  5. Output is written to:       ${STATE_DIR}/site

To serve the site, point any web server at ${STATE_DIR}/site
(e.g. nginx root, or: python3 -m http.server -d ${STATE_DIR}/site 8080).
EOF
