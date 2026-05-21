#!/usr/bin/env bash
#
# Publish the locally-built site to the GitHub Pages branch.
#
# The daily build writes static files to THNC_OUT_DIR; this script pushes a
# clean copy of that directory to the Pages branch (default: gh-pages), with a
# CNAME so the custom domain survives every deploy. A deploy workflow on that
# branch then publishes it to GitHub Pages.
#
# Required env (usually set in /etc/thnewscaster/thnewscaster.env):
#   THNC_PAGES_REPO     git remote, e.g. git@github.com:xhionz/thnewscaster.git
# Optional env:
#   THNC_OUT_DIR        site source dir            (default /var/lib/thnewscaster/site)
#   THNC_PAGES_BRANCH   branch to publish to       (default gh-pages)
#   THNC_PAGES_DOMAIN   custom domain for CNAME    (default thnews.wusaapp.net)
#   THNC_PAGES_SSH_KEY  SSH private key path       (default /etc/thnewscaster/pages_deploy_key)
#   THNC_GIT_NAME       commit author name         (default THNewsCaster)
#   THNC_GIT_EMAIL      commit author email        (default thnewscaster@localhost)
set -euo pipefail

SITE_DIR="${THNC_OUT_DIR:-/var/lib/thnewscaster/site}"
PAGES_REPO="${THNC_PAGES_REPO:?set THNC_PAGES_REPO, e.g. git@github.com:xhionz/thnewscaster.git}"
PAGES_BRANCH="${THNC_PAGES_BRANCH:-gh-pages}"
PAGES_DOMAIN="${THNC_PAGES_DOMAIN:-thnews.wusaapp.net}"
SSH_KEY="${THNC_PAGES_SSH_KEY:-/etc/thnewscaster/pages_deploy_key}"
GIT_NAME="${THNC_GIT_NAME:-THNewsCaster}"
GIT_EMAIL="${THNC_GIT_EMAIL:-thnewscaster@localhost}"

if [[ ! -f "${SITE_DIR}/index.html" ]]; then
  echo "error: ${SITE_DIR}/index.html not found — run the build first" >&2
  exit 1
fi

# Use the deploy key for SSH remotes; HTTPS remotes rely on a credential helper.
if [[ "${PAGES_REPO}" == git@* || "${PAGES_REPO}" == ssh://* ]]; then
  if [[ ! -f "${SSH_KEY}" ]]; then
    echo "error: SSH key ${SSH_KEY} not found (set THNC_PAGES_SSH_KEY)" >&2
    exit 1
  fi
  # UserKnownHostsFile=/dev/null avoids needing a writable HOME under the
  # hardened systemd unit (ProtectHome=true / read-only /opt).
  export GIT_SSH_COMMAND="ssh -i ${SSH_KEY} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Clone just the target branch; if it doesn't exist yet, start it orphaned.
if git clone --depth 1 --branch "${PAGES_BRANCH}" "${PAGES_REPO}" "${WORK}" 2>/dev/null; then
  cd "${WORK}"
else
  git clone --depth 1 "${PAGES_REPO}" "${WORK}"
  cd "${WORK}"
  git checkout --orphan "${PAGES_BRANCH}"
  git rm -rf . >/dev/null 2>&1 || true
fi

# Replace tracked content with the freshly built site (keep .git).
find . -mindepth 1 -maxdepth 1 -not -name '.git' -exec rm -rf {} +
cp -r "${SITE_DIR}/." .

# Custom domain + bypass Jekyll processing.
echo "${PAGES_DOMAIN}" > CNAME
touch .nojekyll

git add -A
if git diff --cached --quiet; then
  echo "no site changes since last publish — nothing to push"
  exit 0
fi

git -c user.name="${GIT_NAME}" -c user.email="${GIT_EMAIL}" \
    commit -m "Publish site $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Retry push with exponential backoff on transient network failures.
delay=2
for attempt in 1 2 3 4 5; do
  if git push origin "HEAD:${PAGES_BRANCH}"; then
    echo "published to ${PAGES_BRANCH} (${PAGES_DOMAIN})"
    exit 0
  fi
  echo "push attempt ${attempt} failed; retrying in ${delay}s" >&2
  sleep "${delay}"
  delay=$(( delay * 2 ))
done
echo "error: could not push to ${PAGES_BRANCH} after retries" >&2
exit 1
