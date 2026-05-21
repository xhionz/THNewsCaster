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
# Copy the package source, project metadata, and deploy scripts.
cp -r "${REPO_ROOT}/src" "${REPO_ROOT}/pyproject.toml" "${REPO_ROOT}/deploy" "${INSTALL_DIR}/"
cp -r "${REPO_ROOT}/README.md" "${INSTALL_DIR}/" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/deploy/run-and-publish.sh" "${INSTALL_DIR}/deploy/publish.sh"

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
  1. Edit endpoint + key + Pages settings:  sudoedit ${ENV_FILE}
  2. (For Pages publish) create a deploy key and add it to the repo:
       sudo -u ${APP_USER} ssh-keygen -t ed25519 -f ${CONF_DIR}/pages_deploy_key -N ''
       sudo cat ${CONF_DIR}/pages_deploy_key.pub
     Repo -> Settings -> Deploy keys -> Add deploy key -> paste, tick "Allow write access".
  3. Trigger a run now:          sudo systemctl start thnewscaster.service
  4. Watch logs:                 journalctl -u thnewscaster.service -f
  5. Check the schedule:         systemctl list-timers thnewscaster.timer
  6. Output is written to:       ${STATE_DIR}/site

GitHub Pages: when THNC_PAGES_REPO is set, each run pushes the rendered site
to the ${PAGES_BRANCH:-gh-pages} branch; the .github/workflows/pages.yml workflow
then publishes it to your custom domain. Keep the repo's Pages source set to
"GitHub Actions" (Settings -> Pages). The CNAME file is written automatically.

To serve the site locally instead, point any web server at ${STATE_DIR}/site
(e.g. nginx root, or: python3 -m http.server -d ${STATE_DIR}/site 8080).
EOF
