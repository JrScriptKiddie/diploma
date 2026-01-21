#!/bin/bash

ip route del default
ip route add default via $GATEWAY_IP || true

echo "Injecting LDAP password into config..."

# Используем sed для замены.
# Мы используем разделитель | вместо /, чтобы пароль мог содержать слеши.
sed -i "s|LDAP_READONLY_USER_USERNAME|$LDAP_READONLY_USER_USERNAME|g" /etc/nslcd.conf
sed -i "s|LDAP_READONLY_USER_PASSWORD|$LDAP_READONLY_USER_PASSWORD|g" /etc/nslcd.conf
sed -i "s|LDAP_SRV_IP|$LDAP_SRV_IP|g" /etc/nslcd.conf

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


# Запускаем демон nslcd (клиент LDAP)
service nslcd start

# Запускаем nscd (кэширование, желательно)
service nscd start

# Запуск rsyslog
/usr/sbin/rsyslogd

# Выводим диагностику (опционально)
echo "Testing LDAP connection..."
getent passwd test || echo "LDAP user 'test' not found via NSS"

# Передаем управление оригинальному скрипту
exec su -s /bin/bash opensearch -c "/usr/share/opensearch/opensearch-docker-entrypoint.sh opensearch"
