#!/bin/bash

ip route del default
ip route add default via $GATEWAY_IP || true

# Trust PolarProxy CA if mounted
if [ -f /usr/local/share/ca-certificates/proxy_ca.crt ]; then
  update-ca-certificates || true
  for policy_dir in /etc/firefox/policies /etc/firefox-esr/policies /usr/lib/firefox/distribution /usr/lib/firefox-esr/distribution; do
    mkdir -p "$policy_dir"
    cat <<'EOF' > "$policy_dir/policies.json"
{
  "policies": {
    "Certificates": {
      "ImportEnterpriseRoots": true,
      "Install": ["/usr/local/share/ca-certificates/proxy_ca.crt"]
    },
    "Preferences": {
      "network.http.http2.enabled": {
        "Value": false,
        "Status": "locked"
      }
    }    
  }
}
EOF
  done
fi

# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account; then
    echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi

# Create local admin account if needed
if ! id localadmin >/dev/null 2>&1; then
    useradd -m -s /bin/bash localadmin
fi
echo "localadmin:${LOCALADMIN_PASSWORD}" | chpasswd
usermod -aG sudo localadmin

# Access rules: allow root locally, allow bastion admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:localadmin:ALL
# Разрешить членам группы ADMINS (имя группы в Linux, не DN!)
+:SG_ADMINS:ALL
# Разрешить членам группы USERS
+:SG_USERS:ALL
# Запретить всем остальным (важно, иначе смысла нет)
-:ALL:ALL
EOF

sed -i "s|SG_USERS|$SG_PC_USERS|g" /etc/security/access.conf
sed -i "s|SG_ADMINS|$SG_PC_ADMINS|g" /etc/security/access.conf

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' >> /etc/sudoers.d/ldap-sudo
%SG_ADMINS ALL=(ALL:ALL) ALL
localadmin ALL=(ALL:ALL) ALL
EOF
chown root:root /etc/sudoers.d/ldap-sudo
chmod 0440 /etc/sudoers.d/ldap-sudo
sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/sudoers.d/ldap-sudo

# Запускаем демон nslcd (клиент LDAP)
service nslcd start

# Запускаем nscd (кэширование, желательно)
service nscd start

# Выводим диагностику (опционально)
echo "Testing LDAP connection..."
getent passwd test || echo "LDAP user 'test' not found via NSS"

# Запуск rsyslog
/usr/sbin/rsyslogd


# Права на домашние директории: владелец по имени каталога, права 0755
# Нужно если подключалось через volumes и права не сохранились при загрузке
for d in /home/*; do
  [ -d "$d" ] || continue
  user=$(basename "$d")
  if id "$user" >/dev/null 2>&1; then
    chown -R "$user:$user" "$d"
    chmod 0755 "$d"
  fi
done

# SSH
echo "SSH setup..."
mkdir -p /etc/ssh /run/sshd
chmod 755 /run/sshd
if [ ! -f /etc/ssh/sshd_config ]; then
  cat > /etc/ssh/sshd_config <<'EOF'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication yes
PermitRootLogin no
UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
fi
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
ssh-keygen -A >/dev/null 2>&1 || true
/usr/sbin/sshd

# Run scenario if present and optionally schedule via cron
#Каждую минуту: * * * * *
#Каждые 5 минут: */5 * * * *
if [ -f /opt/scenario.sh ]; then
    period="${SCENARIO_PERIOD:-5}"
    echo "Adding scenario to cron (every ${period} min)"
    chmod +x /opt/scenario.sh
    # Use Debian cron layout instead of BusyBox crond paths
    echo "*/${period} * * * * root IP_LDAP_SRV=${IP_LDAP_SRV} LDAP_SUFFIX=${LDAP_SUFFIX} /opt/scenario.sh" > /etc/cron.d/scenario
    chmod 0644 /etc/cron.d/scenario
    cron -f -L 8 &
fi

/var/ossec/bin/wazuh-control start

# Передаем управление оригинальному скрипту entrypoint образа scottyhardy
# (В оригинальном образе entrypoint обычно /usr/bin/entrypoint)
exec /usr/bin/entrypoint "$@"
