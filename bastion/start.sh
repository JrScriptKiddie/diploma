#!/bin/bash

ip route del default
ip route add default via $GATEWAY_IP || true

# Trust PolarProxy CA if mounted
if [ -f /usr/local/share/ca-certificates/proxy_ca.crt ]; then
  update-ca-certificates || true
  mkdir -p /etc/firefox/policies
  cat <<'EOF' > /etc/firefox/policies/policies.json
{
  "policies": {
    "Certificates": {
      "Install": ["/usr/local/share/ca-certificates/proxy_ca.crt"]
    }
  }
}
EOF
fi

# NSLCD config access
chown root:nslcd /etc/nslcd.conf && chmod 640 /etc/nslcd.conf

# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account; then
    echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi

# Create local admin account if needed
if ! id localadmin >/dev/null 2>&1; then
    useradd -u 6666 -m -s /bin/bash localadmin
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

sed -i "s|SG_USERS|$SG_USERS|g" /etc/security/access.conf
sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/security/access.conf

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' >> /etc/sudoers.d/ldap-sudo
%SG_ADMINS ALL=(ALL:ALL) ALL
localadmin ALL=(ALL:ALL) ALL
EOF
chown root:root /etc/sudoers.d/ldap-sudo
chmod 0440 /etc/sudoers.d/ldap-sudo
sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/sudoers.d/ldap-sudo

# Запускаем демон nslcd (клиент LDAP) без OpenRC
if command -v nslcd >/dev/null 2>&1; then
    nslcd
else
    echo "[fw] nslcd not found, skipping"
fi

# Запуск rsyslog
/usr/sbin/rsyslogd

# Выводим диагностику (опционально)
echo "Testing LDAP connection..."
getent passwd test || echo "LDAP user 'test' not found via NSS"

# Права на домашние директории: владелец по имени каталога, права 0755
# Нужно если подключалось через volumes и права не сохранились при загрузке с гита
for d in /home/users/*; do
  [ -d "$d" ] || continue
  user=$(basename "$d")
  if id "$user" >/dev/null 2>&1; then
    chown -R "$user:root" "$d"
    chmod 0755 "$d"
  fi
done

# Run SSH server
mkdir -p /run/sshd
chmod 755 /run/sshd
/usr/sbin/sshd

# WAZUH AGENT START
/var/ossec/bin/wazuh-control start

# Передаем управление оригинальному скрипту entrypoint образа scottyhardy
# (В оригинальном образе entrypoint обычно /usr/bin/entrypoint)
exec /usr/bin/entrypoint "$@"
