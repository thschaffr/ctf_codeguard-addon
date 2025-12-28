#!/bin/bash
set -euo pipefail

WORKSPACE="${WORKSPACE_DIR:-/workspace}"
APP_DIR="${WORKSPACE}/idea_1"
IMAGE_NAME="${APP_IMAGE_NAME:-vuln_app}"
CONTAINER_NAME="${APP_CONTAINER_NAME:-vuln_app}"
PORT_MAPPING="${APP_PORT_MAPPING:-8080:80}"

# Git repo configuration (hardcoded)
GIT_REPO="https://github.com/thschaffr/ctf_codeguard.git"
GIT_BRANCH="${APP_GIT_BRANCH:-main}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker not available on PATH. Mount the Docker socket into the verification container." >&2
  exit 1
fi

echo "[reset] Removing idea_1 folder..."
rm -rf "${APP_DIR}"

echo "[reset] Cloning fresh idea_1 from ${GIT_REPO}..."
git clone --depth 1 --branch "${GIT_BRANCH}" "${GIT_REPO}" "${WORKSPACE}/temp_clone"
mv "${WORKSPACE}/temp_clone/idea_1" "${APP_DIR}"
rm -rf "${WORKSPACE}/temp_clone"

# Fix ownership to match parent directory
HOST_OWNER=$(stat -c '%u:%g' "${WORKSPACE}")
chown -R "${HOST_OWNER}" "${APP_DIR}"

echo "[reset] Rebuilding image '${IMAGE_NAME}' from '${APP_DIR}'..."
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
docker build -t "${IMAGE_NAME}" "${APP_DIR}"

echo "[reset] Launching container '${CONTAINER_NAME}'..."
docker run -d -p "${PORT_MAPPING}" --name "${CONTAINER_NAME}" "${IMAGE_NAME}" >/dev/null

echo "[reset] Done."