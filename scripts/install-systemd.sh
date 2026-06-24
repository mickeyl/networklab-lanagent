#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "This script must be run as root (use sudo)." >&2
    exit 1
fi

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)
SERVICE_DEST=/etc/systemd/system/lanagent.service
ENV_DIR=/etc/lanagent
ENV_FILE=${ENV_DIR}/lanagent.conf
EXAMPLE_ENV=${ENV_FILE}.example

install -d /var/lib/lanagent
install -d "${ENV_DIR}"

if ! id -u lanagent >/dev/null 2>&1; then
    useradd --system --home /var/lib/lanagent --shell /usr/sbin/nologin --comment "LANAgent service user" lanagent
fi

chown lanagent:lanagent /var/lib/lanagent
chmod 0750 /var/lib/lanagent

install -Dm644 "${REPO_ROOT}/systemd/lanagent.service" "${SERVICE_DEST}"

if [[ -f "${ENV_FILE}" ]]; then
    install -m644 "${REPO_ROOT}/systemd/lanagent.env" "${EXAMPLE_ENV}"
    echo "Existing ${ENV_FILE} preserved. Updated defaults written to ${EXAMPLE_ENV}."
else
    install -m644 "${REPO_ROOT}/systemd/lanagent.env" "${ENV_FILE}"
fi

systemctl daemon-reload
systemctl enable --now lanagent.service

echo "LANAgent systemd service installed. Adjust ${ENV_FILE} to change the listening port and scan/presence settings."
