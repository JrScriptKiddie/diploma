#!/usr/bin/env bash
set -euo pipefail

# Prepare PATH
echo 'export PATH=/usr/sbin:/sbin:$PATH' > /etc/profile.d/00-sbin.sh

echo "[fw] Renaming interfaces by subnet..."
# Default missing subnet vars to avoid set -u failures.
: "${SUBNET_UPLINK:=0.0.0.0}"
: "${SUBNET_DEV:=0.0.0.0}"
: "${SUBNET_USERS:=0.0.0.0}"
: "${SUBNET_DMZ:=0.0.0.0}"
: "${SUBNET_SERVERS:=0.0.0.0}"
: "${SUBNET_ADMIN:=0.0.0.0}"
: "${SUBNET_INFOSEC:=0.0.0.0}"
# Переименовываем все интерфейсы в понятный вид
while read -r line; do
  dev=$(echo "$line" | awk '{print $2}')
  cidr=$(echo "$line" | awk '{print $4}')
  [ "$dev" = "lo" ] && continue
  ip=${cidr%/*}
  # Derive /24 subnet x.y.z.0/24
  subnet=$(echo "$ip" | awk -F. '{printf "%s.%s.%s.0/24\n", $1,$2,$3}')
  new=""
  case "$subnet" in
    $SUBNET_UPLINK.0/24)   new="eth_uplink"  ;;
    $SUBNET_DEV.0/24)   new="eth_dev"  ;;
    $SUBNET_USERS.0/24)  new="eth_users"  ;;
    $SUBNET_DMZ.0/24)  new="eth_dmz" ;;
    $SUBNET_SERVERS.0/24)  new="eth_servers" ;;
    $SUBNET_ADMIN.0/24)  new="eth_admin" ;;
    $SUBNET_INFOSEC.0/24)  new="eth_infosec" ;;
  esac
  [ -z "$new" ] && continue
  [ "$dev" = "$new" ] && continue

  # Skip if target name is already taken
  if ip link show "$new" >/dev/null 2>&1; then
    echo "[fw] Target name '$new' already exists, skipping $dev"
    continue
  fi
  echo "[fw] renaming $dev ($cidr) -> $new"
  ip link set dev "$dev" down || true
  ip link set dev "$dev" name "$new" || true
  ip link set dev "$new" up || true
done < <(ip -o -4 addr show)

# Задаем дефолтный маршрут на NAT
echo "Adding default route via ${GATEWAY_IP} on eth_uplink"
ip route add default via $GATEWAY_IP dev eth_uplink || true
ip route add 10.11.0.0/16 via $SUBNET_DMZ.$VPN_SRV_IP

nft flush table inet fw || true
nft flush chain ip nat PREROUTING || true
nft flush chain ip nat POSTROUTING || true
# Load nftables rules
nft -f /etc/nftables.conf

# SSH setup (avoid noisy errors if config dir missing)
mkdir -p /etc/ssh /run/sshd
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

# Enforce pam_access for group-based login control
if ! grep -q '^account required pam_access.so' /etc/pam.d/common-account; then
    echo 'account required pam_access.so' >> /etc/pam.d/common-account
fi

# Create local admin account if needed (Alpine)
if ! id localadmin >/dev/null 2>&1; then
    adduser -D -s /bin/bash localadmin
fi
if ! getent group wheel >/dev/null 2>&1; then
    addgroup -S wheel
fi
addgroup localadmin wheel || true
echo "localadmin:${LOCALADMIN_PASSWORD}" | chpasswd

# Access rules: allow root locally, allow bastion admins/users groups, deny all else
cat <<'EOF' >> /etc/security/access.conf
+:root:LOCAL
+:localadmin:ALL
# Разрешить членам группы ADMINS (имя группы в Linux, не DN!)
+:SG_ADMINS:ALL
# Запретить всем остальным (важно, иначе смысла нет)
-:ALL:ALL
EOF

sed -i "s|SG_ADMINS|$SG_NET_ADMINS|g" /etc/security/access.conf

touch /etc/sudoers.d/ldap-sudo
cat <<'EOF' >> /etc/sudoers.d/ldap-sudo
%SG_ADMINS ALL=(ALL:ALL) ALL
%wheel ALL=(ALL:ALL) ALL
localadmin ALL=(ALL:ALL) ALL
EOF
chown root:root /etc/sudoers.d/ldap-sudo
chmod 0440 /etc/sudoers.d/ldap-sudo
sed -i "s|SG_ADMINS|$SG_NET_ADMINS|g" /etc/sudoers.d/ldap-sudo


# Запускаем демон nslcd (клиент LDAP) без OpenRC
if command -v nslcd >/dev/null 2>&1; then
    nslcd
else
    echo "[fw] nslcd not found, skipping"
fi

# Запускаем nscd (кэширование, желательно) без OpenRC
if command -v nscd >/dev/null 2>&1; then
    nscd
else
    echo "[fw] nscd not found, skipping"
fi

# Запуск rsyslog
/usr/sbin/rsyslogd

# Выводим диагностику (опционально)
echo "Testing LDAP connection..."
getent passwd test || echo "LDAP user 'test' not found via NSS"

mkdir -p /run/sshd
chmod 755 /run/sshd

# Keep running
exec /usr/sbin/sshd -D
