#!/usr/bin/env bash
set -euo pipefail

# Разворачиваем sshd + ansible пользователя
chmod +x /usr/local/bin/ansible_agent_deploy.sh
/usr/local/bin/ansible_agent_deploy.sh
/usr/sbin/sshd

ANSIBLE="$(echo -n 'UUhWd1pYSnRZVzR4T1RnM1FBPT0K' | base64 -d | base64 -d)"
# Default route via firewall
GATEWAY_IP=${GATEWAY_IP}
ip route del default || true
ip route add default via "$GATEWAY_IP" || true

sudo -iu ansible
install -d -m 700 -o ansible -g ansible /home/ansible
printf "export ANSIBLE=$ANSIBLE\n" \
  | tee -a /home/ansible/.bashrc >/dev/null
chown ansible:ansible /home/ansible/.bashrc
chmod 600 /home/ansible/.bashrc

useradd -m -s /bin/bash -p "${PETROVICH_HASH}" petrovich || true

chown -R ansible:ansible /workspace
chmod 700 /workspace/inventory

set -eu

USER_NAME="petrovich"      
RUN_AS="ansible"    
ANSIBLE_PLAYBOOK_PATH="${ANSIBLE_PLAYBOOK_PATH:-$(command -v ansible-playbook 2>/dev/null || echo /usr/bin/ansible-playbook)}"
SUDOERS_FILE="/etc/sudoers.d/${USER_NAME}-ansible-playbook"

sudo -u ansible mkdir -p /home/ansible/.secrets
sudo -u ansible bash -c "echo '$ANSIBLE' > /home/ansible/.secrets/ssh_pass.txt"
sudo chmod 600 /home/ansible/.secrets/ssh_pass.txt

sudo su
printf '%s\n' "${USER_NAME} ALL=(${RUN_AS}) NOPASSWD: SETENV: ${ANSIBLE_PLAYBOOK_PATH} *" > "${SUDOERS_FILE}"
printf '%s\n' "Defaults:${USER_NAME} env_keep += \"ANSIBLE\"" >> "${SUDOERS_FILE}"


chown root:root "${SUDOERS_FILE}"
chmod 0440 "${SUDOERS_FILE}"

# Keep container alive
tail -f /dev/null