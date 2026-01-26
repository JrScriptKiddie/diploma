#!/usr/bin/env bash
set -euo pipefail

# Defaults
SAMBA_USER=${SAMBA_USER}
SAMBA_PASSWORD=${SAMBA_PASSWORD}
SAMBA_SHARE_NAME=${SAMBA_SHARE_NAME:-Share}
SAMBA_SHARE_PATH=${SAMBA_SHARE_PATH:-/share}
WORKGROUP=${WORKGROUP:-WORKGROUP}

# Default route via firewall (optional)
ip route del default || true
ip route add default via "$GATEWAY_IP" || true

# Create local users (system + ansible)
if ! id -u "$SAMBA_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$SAMBA_USER" || true
fi
echo "$SAMBA_USER:$SAMBA_PASSWORD" | chpasswd
echo "$SAMBA_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/90-$SAMBA_USER
chmod 0440 /etc/sudoers.d/90-$SAMBA_USER

mkdir -p "$SAMBA_SHARE_PATH"
chmod -R 0777 "$SAMBA_SHARE_PATH" || true

# Samba configuration
mkdir -p /var/log/samba
cat > /etc/samba/smb.conf <<EOF
[global]
   workgroup = $WORKGROUP
   server role = standalone server
   map to guest = Bad User
   usershare allow guests = yes
   dns proxy = no
   log file = /var/log/samba/log.%m
   max log size = 50
   load printers = no
   printing = bsd
   disable spoolss = yes

[$SAMBA_SHARE_NAME]
   path = $SAMBA_SHARE_PATH
   browseable = yes
   read only = no
   guest ok = yes
   create mask = 0666
   directory mask = 0775
EOF


# Create Samba user (requires system account to exist)
printf '%s\n%s\n' "$SAMBA_PASSWORD" "$SAMBA_PASSWORD" | smbpasswd -s -a "$SAMBA_USER" || true



# Разворачиваем sshd + ansible пользователя
chmod +x /usr/local/bin/ansible_agent_deploy.sh
/usr/local/bin/ansible_agent_deploy.sh
/usr/sbin/sshd

mkdir -p /var/log/supervisor
cat <<'EOF' > /etc/supervisor/conf.d/samba.conf
[program:nmbd]
command=/usr/sbin/nmbd -F --no-process-group
autorestart=true
stdout_logfile=/var/log/supervisor/nmbd.log
stderr_logfile=/var/log/supervisor/nmbd.log
priority=10

[program:smbd]
command=/usr/sbin/smbd -F --no-process-group
autorestart=true
stdout_logfile=/var/log/supervisor/smbd.log
stderr_logfile=/var/log/supervisor/smbd.log
priority=20
EOF

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
