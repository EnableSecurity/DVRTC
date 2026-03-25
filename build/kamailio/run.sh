#!/bin/bash

CERT_DIR="/etc/certstore"
RUNTIME_CERT_DIR="/var/run/kamailio/certs"

print_setup_help() {
    echo "DVRTC setup incomplete."
    echo "Run these commands before 'docker compose up':"
    echo "  ./scripts/setup_networking.sh"
    echo "  ./scripts/generate_passwords.sh"
    echo "  ./scripts/init-selfsigned.sh"
    echo "See README.md Initial Setup."
}

# Validate required environment variables
if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
    echo "ERROR: MYSQL_ROOT_PASSWORD is not set"
    print_setup_help
    exit 1
fi

if [ -z "$PUBLIC_IPV4" ]; then
    echo "ERROR: PUBLIC_IPV4 is not set"
    print_setup_help
    exit 1
fi

if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/privkey.pem" ]; then
    echo "ERROR: TLS certificates are missing from $CERT_DIR"
    print_setup_help
    exit 1
fi

# Keep the host bind mount untouched on Linux: prepare a container-local key copy
# that the kamailio user can read.
mkdir -p "$RUNTIME_CERT_DIR"
cp "$CERT_DIR/privkey.pem" "$RUNTIME_CERT_DIR/privkey.pem"
chown root:kamailio "$RUNTIME_CERT_DIR/privkey.pem"
chmod 0640 "$RUNTIME_CERT_DIR/privkey.pem"
sed -i "s|^private_key = .*|private_key = $RUNTIME_CERT_DIR/privkey.pem|" /etc/kamailio/tls.cfg

# RTPEngine ng control stays on loopback for the supported host-networked setup.
RTPENGINE_IP="127.0.0.1"
sed -i "s/__RTPENGINE_IP__/$RTPENGINE_IP/g" /etc/kamailio/kamailio.cfg

# Substitute MySQL port in config
MYSQL_PORT="${MYSQL_PORT:-23306}"
sed -i "s/__MYSQL_PORT__/$MYSQL_PORT/g" /etc/kamailio/kamailio.cfg

# Substitute PUBLIC_IPV4 in config for aliases and advertised_address.
sed -i "s|__PUBLIC_IPV4__|$PUBLIC_IPV4|g" /etc/kamailio/kamailio.cfg

# Optional dual-stack public listeners and aliases
if [ ! -z "$PUBLIC_IPV6" ]; then
    IPV6_LISTENERS="listen=udp:[$PUBLIC_IPV6]:5060 advertise [$PUBLIC_IPV6]:5060\nlisten=tcp:[$PUBLIC_IPV6]:5060 advertise [$PUBLIC_IPV6]:5060\nlisten=tcp:[$PUBLIC_IPV6]:8000 advertise [$PUBLIC_IPV6]:8000\nlisten=tls:[$PUBLIC_IPV6]:5061 advertise [$PUBLIC_IPV6]:5061\nlisten=tls:[$PUBLIC_IPV6]:8443 advertise [$PUBLIC_IPV6]:8443"
    IPV6_ALIASES="alias=\"[::1]\"\nalias=\"[::1]:5060\"\nalias=\"[::1]:5061\"\nalias=\"[$PUBLIC_IPV6]\"\nalias=\"[$PUBLIC_IPV6]:5060\"\nalias=\"[$PUBLIC_IPV6]:5061\"\nalias=\"[$PUBLIC_IPV6]:8000\"\nalias=\"[$PUBLIC_IPV6]:8443\""
    sed -i "s|__IPV6_LISTENERS__|$IPV6_LISTENERS|g" /etc/kamailio/kamailio.cfg
    sed -i "s|__IPV6_ALIASES__|$IPV6_ALIASES|g" /etc/kamailio/kamailio.cfg
else
    sed -i "/__IPV6_LISTENERS__/d" /etc/kamailio/kamailio.cfg
    sed -i "/__IPV6_ALIASES__/d" /etc/kamailio/kamailio.cfg
fi

# Substitute DOMAIN aliases if DOMAIN is set
if [ ! -z "$DOMAIN" ]; then
    DOMAIN_ALIASES="alias=\"$DOMAIN\"\nalias=\"$DOMAIN:5060\"\nalias=\"$DOMAIN:5061\"\nalias=\"$DOMAIN:8000\"\nalias=\"$DOMAIN:8443\""
    sed -i "s|__DOMAIN_ALIASES__|$DOMAIN_ALIASES|g" /etc/kamailio/kamailio.cfg
else
    sed -i "/__DOMAIN_ALIASES__/d" /etc/kamailio/kamailio.cfg
fi

#sqlite3 /var/sql/kamailio.sqlite 'create table useragents (useragent text not null)'
mysql -uroot -p"$MYSQL_ROOT_PASSWORD" --socket=/var/run/mysqld/mysqld.sock << EOF
CREATE DATABASE IF NOT EXISTS useragents;
USE useragents;
CREATE TABLE IF NOT EXISTS useragents (id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, useragent text not null);

-- INTENTIONALLY VULNERABLE: Sensitive customer data for SQL injection demonstrations
-- This data is FAKE and used for security training purposes only
CREATE TABLE IF NOT EXISTS customers (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100),
    phone VARCHAR(20),
    credit_card VARCHAR(19),
    cvv VARCHAR(4),
    ssn VARCHAR(11),
    date_of_birth DATE,
    address VARCHAR(200),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed fake sensitive customer data only once so restarts do not duplicate rows.
INSERT INTO customers (first_name, last_name, email, phone, credit_card, cvv, ssn, date_of_birth, address)
SELECT seed_rows.first_name, seed_rows.last_name, seed_rows.email, seed_rows.phone, seed_rows.credit_card, seed_rows.cvv, seed_rows.ssn, seed_rows.date_of_birth, seed_rows.address
FROM (
    SELECT 'Alice' AS first_name, 'Johnson' AS last_name, 'alice.johnson@example.com' AS email, '+1-555-0101' AS phone, '4532-1234-5678-9010' AS credit_card, '123' AS cvv, '123-45-6789' AS ssn, '1985-03-15' AS date_of_birth, '123 Main St, Springfield, IL 62701' AS address
    UNION ALL SELECT 'Bob', 'Smith', 'bob.smith@example.com', '+1-555-0102', '5425-2345-6789-0123', '456', '234-56-7890', '1990-07-22', '456 Oak Ave, Portland, OR 97201'
    UNION ALL SELECT 'Carol', 'Williams', 'carol.w@example.com', '+1-555-0103', '3782-3456-7890-1234', '789', '345-67-8901', '1978-11-30', '789 Pine Rd, Austin, TX 78701'
    UNION ALL SELECT 'David', 'Brown', 'dbrown@example.com', '+1-555-0104', '6011-4567-8901-2345', '321', '456-78-9012', '1982-05-18', '321 Elm St, Seattle, WA 98101'
    UNION ALL SELECT 'Eve', 'Davis', 'eve.davis@example.com', '+1-555-0105', '3530-5678-9012-3456', '654', '567-89-0123', '1995-09-07', '654 Maple Dr, Boston, MA 02101'
    UNION ALL SELECT 'Frank', 'Miller', 'fmiller@example.com', '+1-555-0106', '4916-6789-0123-4567', '987', '678-90-1234', '1988-12-25', '987 Cedar Ln, Denver, CO 80201'
    UNION ALL SELECT 'Grace', 'Wilson', 'grace.wilson@example.com', '+1-555-0107', '6304-7890-1234-5678', '111', '789-01-2345', '1992-02-14', '111 Birch Ct, Miami, FL 33101'
    UNION ALL SELECT 'Henry', 'Moore', 'hmoore@example.com', '+1-555-0108', '5019-8901-2345-6789', '222', '890-12-3456', '1980-08-09', '222 Spruce Way, Phoenix, AZ 85001'
) AS seed_rows
WHERE NOT EXISTS (SELECT 1 FROM customers);

GRANT SELECT,INSERT,UPDATE,DELETE ON useragents.useragents TO 'kamailio';
GRANT SELECT ON useragents.customers TO 'kamailio';
EOF

# Listen directives are in kamailio.cfg with advertise parameters.
# Suppress the known mixed-transport core warning to keep container logs usable.
exec /bin/bash -lc 'set -o pipefail; \
  /usr/sbin/kamailio -DD -u kamailio -f /etc/kamailio/kamailio.cfg 2>&1 | \
  grep -F -v "get_send_socket2(): protocol/port mismatch"; \
  exit ${PIPESTATUS[0]}'
