#!/bin/bash

ip route del default
ip route add default via $GATEWAY_IP || true

# Проверяем, задана ли переменная (защита от дурака)
if [ -z "$LDAP_READONLY_USER_PASSWORD" ]; then
    echo "ERROR: Variable LDAP_READONLY_USER_PASSWORD is not set!"
    exit 1
fi

# Bring up WireGuard client if config is provided
WG_CONF="/etc/wireguard/wg0.conf"
if [ -f "$WG_CONF" ]; then
    chmod 600 "$WG_CONF"
    if ! wg-quick up wg0; then
        echo "WireGuard bring-up failed; check $WG_CONF and routing"
    else
        echo "WireGuard interface wg0 is up"
    fi
else
    echo "WireGuard config not provided; skipping wg0 bring-up"
fi

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

# Access rules: allow root locally, allow bastion admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
# Разрешить членам группы ADMINS (имя группы в Linux, не DN!)
+:SG_ADMINS:ALL
# локальная учетка пользователя
+:student:ALL
# Запретить всем остальным (важно, иначе смысла нет)
+:ALL:ALL
EOF

sed -i "s|SG_ADMINS|$SG_ADMINS|g" /etc/security/access.conf

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' >> /etc/sudoers.d/ldap-sudo
%SG_ADMINS ALL=(ALL:ALL) ALL
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

# Create local user for PC access if credentials provided
if [ -n "${PC_USERNAME:-}" ] && [ -n "${PC_USERPWD:-}" ]; then
    if ! id "$PC_USERNAME" >/dev/null 2>&1; then
        useradd -m -s /bin/bash "$PC_USERNAME"
    fi
    echo "${PC_USERNAME}:${PC_USERPWD}" | chpasswd
fi

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

# Run scenario if present and optionally schedule via cron
#Каждую минуту: * * * * *
#Каждые 5 минут: */5 * * * *
if [ -f /opt/scenario.sh ]; then
    period="${SCENARIO_PERIOD:-5}"
    echo "Adding scenario to cron (every ${period} min)"
    chmod +x /opt/scenario.sh
    # Use Debian cron layout instead of BusyBox crond paths
    echo "*/${period} * * * * root LDAP_SRV_IP=${LDAP_SRV_IP} LDAP_SUFFIX=${LDAP_SUFFIX} /opt/scenario.sh" > /etc/cron.d/scenario
    chmod 0644 /etc/cron.d/scenario
    cron -f -L 8 &
fi


# WAZUH AGENT INSTALLATION
# Install GPG/curl, add Wazuh key to a dedicated keyring, add repo, then install the agent.
# apt-get update
# DEBIAN_FRONTEND=noninteractive apt-get install -y curl gnupg apt-transport-https
#curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
#chmod 644 /usr/share/keyrings/wazuh.gpg
#echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list
#apt-get update
#DEBIAN_FRONTEND=noninteractive WAZUH_MANAGER="${WAZUH_MANAGER:-wazuh.manager}" apt-get install -y wazuh-agent
#/var/ossec/bin/wazuh-control start

# Передаем управление оригинальному скрипту entrypoint образа scottyhardy
# (В оригинальном образе entrypoint обычно /usr/bin/entrypoint)
exec /usr/bin/entrypoint "$@"
