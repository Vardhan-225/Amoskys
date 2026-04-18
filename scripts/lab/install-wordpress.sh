#!/usr/bin/env bash
# AMOSKYS Lab — Install LEMP + WordPress on a fresh Ubuntu 24.04 instance.
#
# Run this ON THE LAB INSTANCE (not your Mac). After SSH:
#   curl -sSL <raw-url>/install-wordpress.sh | sudo bash
# Or copy and run:
#   scp -i ~/.ssh/amoskys-lab-key.pem install-wordpress.sh ubuntu@lab.amoskys.com:/tmp/
#   ssh ubuntu@lab.amoskys.com 'sudo bash /tmp/install-wordpress.sh'
#
# Installs three WordPress sites at subdirectories:
#   /clean      — vanilla WP, no custom plugins
#   /vulnerable — WP with deliberately old plugins for Argos to find
#   /prod-like  — WP with modern, current stack (like a real customer)
#
# The Aegis plugin is installed to all three so we can measure detection
# rates across vulnerable vs clean under identical attacks.
#
# Idempotent-ish — re-running is safe but may prompt for existing packages.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "error: this script needs to run as root (use sudo)" >&2
  exit 1
fi

MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS:-CHANGE_ME_BEFORE_RUNNING}"
WP_DB_NAME="${WP_DB_NAME:-amoskys_wp}"
WP_DB_USER="${WP_DB_USER:-amoskys_wp}"
WP_DB_PASS="${WP_DB_PASS:-CHANGE_ME_BEFORE_RUNNING}"
WP_ROOT="/var/www/html"

if [ "$MYSQL_ROOT_PASS" = "CHANGE_ME_BEFORE_RUNNING" ] || [ "$WP_DB_PASS" = "CHANGE_ME_BEFORE_RUNNING" ]; then
  echo "error: set MYSQL_ROOT_PASS and WP_DB_PASS env vars before running:" >&2
  echo "  sudo MYSQL_ROOT_PASS='...' WP_DB_PASS='...' ./install-wordpress.sh" >&2
  exit 2
fi

echo "==> apt update + upgrade"
apt update -y
DEBIAN_FRONTEND=noninteractive apt upgrade -y

echo "==> install LEMP stack + tools (incl. certbot)"
DEBIAN_FRONTEND=noninteractive apt install -y \
  nginx \
  mariadb-server mariadb-client \
  php8.3-fpm php8.3-mysql php8.3-curl php8.3-gd php8.3-intl \
  php8.3-mbstring php8.3-soap php8.3-xml php8.3-xmlrpc php8.3-zip \
  php8.3-imagick \
  certbot python3-certbot-nginx \
  curl wget git unzip htop ufw less

echo "==> configure MariaDB root password"
mysql -u root <<SQL
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
FLUSH PRIVILEGES;
SQL

echo "==> create WordPress database and user"
mysql -u root -p"${MYSQL_ROOT_PASS}" <<SQL
CREATE DATABASE IF NOT EXISTS ${WP_DB_NAME} DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP USER IF EXISTS '${WP_DB_USER}'@'localhost';
CREATE USER '${WP_DB_USER}'@'localhost' IDENTIFIED BY '${WP_DB_PASS}';
GRANT ALL PRIVILEGES ON ${WP_DB_NAME}.* TO '${WP_DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

echo "==> download WP-CLI"
if ! command -v wp >/dev/null 2>&1; then
  curl -sS -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
  chmod +x /usr/local/bin/wp
fi

echo "==> prepare web root"
rm -rf "${WP_ROOT}"
mkdir -p "${WP_ROOT}"
chown -R www-data:www-data "${WP_ROOT}"

install_wp_variant() {
  local variant="$1"
  local dir="${WP_ROOT}/${variant}"

  echo "==> installing WP variant: ${variant} at ${dir}"
  sudo -u www-data wp core download --path="${dir}" --locale=en_US
  sudo -u www-data wp config create \
    --path="${dir}" \
    --dbname="${WP_DB_NAME}" \
    --dbuser="${WP_DB_USER}" \
    --dbpass="${WP_DB_PASS}" \
    --dbhost=localhost \
    --dbprefix="wp_${variant}_"

  sudo -u www-data wp core install \
    --path="${dir}" \
    --url="http://lab.amoskys.com/${variant}" \
    --title="AMOSKYS Lab — ${variant}" \
    --admin_user=amoskys_admin \
    --admin_password="${WP_DB_PASS}" \
    --admin_email=lab@amoskys.com \
    --skip-email
}

install_wp_variant clean
install_wp_variant vulnerable
install_wp_variant prod-like

echo "==> nginx vhost"
cat >/etc/nginx/sites-available/amoskys-lab <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name lab.amoskys.com _;

    root /var/www/html;
    index index.php index.html;

    # Redirect root to the clean variant by default
    location = / {
        return 302 /clean/;
    }

    # Three variants
    location ~ ^/(clean|vulnerable|prod-like)/ {
        try_files $uri $uri/ /$1/index.php?$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    # Don't serve .ht files
    location ~ /\.ht { deny all; }

    # Don't log robots/favicon
    location = /favicon.ico { access_log off; log_not_found off; }
    location = /robots.txt  { access_log off; log_not_found off; }
}
NGINX
ln -sf /etc/nginx/sites-available/amoskys-lab /etc/nginx/sites-enabled/amoskys-lab
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx php8.3-fpm

# HTTPS via Let's Encrypt — skip if LAB_SKIP_TLS=1 (e.g., before DNS is pointed)
if [ "${LAB_SKIP_TLS:-0}" != "1" ]; then
  echo "==> Let's Encrypt cert for lab.amoskys.com"
  certbot --nginx \
    -d lab.amoskys.com \
    --non-interactive \
    --agree-tos \
    --email "${LAB_CERT_EMAIL:-lab@amoskys.com}" \
    --redirect
fi

echo "==> install Aegis plugin into all three variants"
# NOTE: this assumes the Aegis plugin source is at /tmp/amoskys-aegis/
# Run: scp -r amoskys-aegis ubuntu@lab.amoskys.com:/tmp/ before running this.
if [ -d "/tmp/amoskys-aegis" ]; then
  for variant in clean vulnerable prod-like; do
    dest="${WP_ROOT}/${variant}/wp-content/plugins/amoskys-aegis"
    rm -rf "$dest"
    cp -r /tmp/amoskys-aegis "$dest"
    chown -R www-data:www-data "$dest"
    sudo -u www-data wp plugin activate amoskys-aegis --path="${WP_ROOT}/${variant}"
  done
else
  echo "   NOTE: /tmp/amoskys-aegis not found — skipping Aegis install."
  echo "   scp the plugin up and rerun, or install it from wp admin."
fi

echo ""
echo "==> DONE"
echo "   http://lab.amoskys.com/clean/       — vanilla WP"
echo "   http://lab.amoskys.com/vulnerable/  — will host deliberately vulnerable plugins"
echo "   http://lab.amoskys.com/prod-like/   — modern realistic stack"
echo ""
echo "   admin user: amoskys_admin"
echo "   admin pass: (same as WP_DB_PASS you set)"
