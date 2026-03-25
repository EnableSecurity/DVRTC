#!/bin/bash
# Validate environment configuration before starting DVRTC
# Run this before docker compose up to catch configuration issues early

set -e

ENV_FILE=".env"
ERRORS=0

echo "Validating DVRTC environment configuration..."
echo ""

# Check if .env exists
if [ ! -f "$ENV_FILE" ]; then
    echo "❌ ERROR: .env file not found"
    echo "   Create it by copying .env.example:"
    echo "   cp .env.example .env"
    echo ""
    exit 1
fi

get_value() {
    local var_name="$1"
    grep "^${var_name}=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2-
}

# Function to check if a variable is set and non-empty
check_required() {
    local var_name="$1"
    local description="$2"
    local help_text="$3"

    local value
    value=$(get_value "$var_name")

    if [ -z "$value" ]; then
        echo "❌ ERROR: $var_name is not set"
        echo "   Description: $description"
        if [ -n "$help_text" ]; then
            echo "   Fix: $help_text"
        fi
        echo ""
        ERRORS=$((ERRORS + 1))
        return 1
    else
        echo "✅ $var_name is set"
        return 0
    fi
}

# Function to check and provide warnings
check_optional_warning() {
    local var_name="$1"
    local description="$2"

    local value
    value=$(get_value "$var_name")

    if [ -z "$value" ]; then
        echo "⚠️  WARNING: $var_name is not set"
        echo "   Description: $description"
        echo ""
    else
        echo "✅ $var_name is set"
    fi
}

check_optional_public_ipv6() {
    local value
    value=$(get_value "PUBLIC_IPV6")

    if [ -z "$value" ]; then
        echo "⚠️  WARNING: PUBLIC_IPV6 is not set"
        echo "   Description: IPv6 address for opt-in external dual-stack support"
        echo ""
        return 0
    fi

    echo "✅ PUBLIC_IPV6 is set"

    case "$value" in
        *"["*|*"]"*)
            echo "❌ ERROR: PUBLIC_IPV6 must be set to a raw IPv6 address without brackets"
            echo "   Fix: Use PUBLIC_IPV6=2001:db8::1 (not [2001:db8::1])"
            echo ""
            ERRORS=$((ERRORS + 1))
            return 1
            ;;
        ""|::|::1|localhost|fe80:*|FE80:*)
            echo "❌ ERROR: PUBLIC_IPV6 is set to $value"
            echo "   This will not work for external dual-stack access"
            echo "   Fix: Set PUBLIC_IPV6 to a routable or lab-routable IPv6 address"
            echo ""
            ERRORS=$((ERRORS + 1))
            return 1
            ;;
    esac

    if [ "${value#*:}" = "$value" ]; then
        echo "❌ ERROR: PUBLIC_IPV6 does not look like an IPv6 address"
        echo "   Fix: Set PUBLIC_IPV6 to a raw IPv6 literal such as 2001:db8::1"
        echo ""
        ERRORS=$((ERRORS + 1))
        return 1
    fi

    return 0
}

check_public_ipv4() {
    local value
    value=$(get_value "PUBLIC_IPV4")

    if [ -z "$value" ]; then
        return 0
    fi

    case "$value" in
        localhost|0.0.0.0|127.*|*"["*|*"]"*|*:*|*[^0-9.]*)
            echo "❌ ERROR: PUBLIC_IPV4 is set to $value"
            echo "   This must be a routable IPv4 address for SIP/RTP"
            echo "   Fix: Set PUBLIC_IPV4 to your actual network IPv4 address"
            echo ""
            ERRORS=$((ERRORS + 1))
            return 1
            ;;
    esac

    if ! awk -F. '
        NF != 4 { exit 1 }
        {
            for (i = 1; i <= 4; i++) {
                if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) {
                    exit 1
                }
            }
        }
    ' <<< "$value"; then
        echo "❌ ERROR: PUBLIC_IPV4 is set to $value"
        echo "   This does not look like a valid IPv4 address"
        echo "   Fix: Set PUBLIC_IPV4 to a dotted-quad IPv4 address such as 192.168.1.100"
        echo ""
        ERRORS=$((ERRORS + 1))
        return 1
    fi

    return 0
}

check_letsencrypt_settings() {
    local domain email
    domain=$(get_value "DOMAIN")
    email=$(get_value "EMAIL")

    if [ -n "$domain" ] && [ -z "$email" ]; then
        echo "❌ ERROR: DOMAIN is set but EMAIL is not set"
        echo "   LetsEncrypt requires both DOMAIN and EMAIL"
        echo "   Fix: Set EMAIL in .env or leave DOMAIN empty and use ./scripts/init-selfsigned.sh"
        echo ""
        ERRORS=$((ERRORS + 1))
        return 1
    fi

    if [ -z "$domain" ] && [ -n "$email" ]; then
        echo "⚠️  WARNING: EMAIL is set but DOMAIN is not set"
        echo "   LetsEncrypt will not be used unless DOMAIN is also set"
        echo ""
    fi

    return 0
}

check_optional_mysql_port() {
    local value
    value=$(get_value "MYSQL_PORT")

    if [ -z "$value" ]; then
        return 0
    fi

    echo "✅ MYSQL_PORT is set"

    case "$value" in
        *[!0-9]*)
            echo "❌ ERROR: MYSQL_PORT is set to $value"
            echo "   This must be a numeric TCP port"
            echo "   Fix: Set MYSQL_PORT to a value such as 23306"
            echo ""
            ERRORS=$((ERRORS + 1))
            return 1
            ;;
    esac

    if [ "$value" -lt 1 ] || [ "$value" -gt 65535 ]; then
        echo "❌ ERROR: MYSQL_PORT is set to $value"
        echo "   This must be between 1 and 65535"
        echo "   Fix: Set MYSQL_PORT to a valid TCP port such as 23306"
        echo ""
        ERRORS=$((ERRORS + 1))
        return 1
    fi

    return 0
}

echo "=== Required Variables ==="
echo ""

# Check PUBLIC_IPV4
check_required "PUBLIC_IPV4" \
    "Your server's IPv4 address (required for SIP/RTP)" \
    "Set PUBLIC_IPV4 in .env (use 'ip addr' or 'curl ifconfig.me' to find it)" || true

check_public_ipv4 || true

# Check generated passwords
check_required "MYSQL_ROOT_PASSWORD" \
    "MySQL root password (auto-generated)" \
    "Run: ./scripts/generate_passwords.sh" || true

check_required "SIPCALLER1_PASSWORD" \
    "Internal SIP caller password (auto-generated)" \
    "Run: ./scripts/generate_passwords.sh" || true

echo ""
echo "=== Optional Variables ==="
echo ""

# Optional checks (warnings only)
check_optional_warning "DOMAIN" "Domain name for LetsEncrypt certificates"
check_optional_warning "EMAIL" "Email for LetsEncrypt notifications"
check_letsencrypt_settings || true
check_optional_public_ipv6 || true
check_optional_mysql_port || true

echo ""
echo "=== Certificate Check ==="
echo ""

# Check if TLS material exists
if [ -f "data/certs/fullchain.pem" ] && [ -f "data/certs/privkey.pem" ] && [ -f "data/certs/ssl-dhparams.pem" ]; then
    echo "✅ TLS material found in data/certs/"
else
    echo "❌ ERROR: TLS material not found in data/certs/"
    echo "   Kamailio and Nginx will not start without certificates and DH params"
    echo "   Fix: Run ./scripts/init-selfsigned.sh (recommended for lab use)"
    echo "        OR ./scripts/init-letsencrypt.sh (if DOMAIN is set)"
    echo ""
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "=== Summary ==="
echo ""

if [ $ERRORS -eq 0 ]; then
    echo "✅ Validation passed! Your environment is properly configured."
    echo ""
    echo "You can now start DVRTC with:"
    echo "  docker compose up -d"
    echo ""
    echo "If you want to refresh published images first, run:"
    echo "  docker compose pull"
    echo ""
    exit 0
else
    echo "❌ Validation failed with $ERRORS error(s)"
    echo ""
    echo "Please fix the errors above before starting DVRTC."
    echo ""
    echo "Quick fix for missing passwords:"
    echo "  ./scripts/generate_passwords.sh"
    echo ""
    echo "Quick fix for missing networking/certs:"
    echo "  ./scripts/setup_networking.sh"
    echo "  ./scripts/init-selfsigned.sh"
    echo ""
    exit 1
fi
