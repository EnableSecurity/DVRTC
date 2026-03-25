#!/bin/bash
# Auto-detect public IP addresses and set them in .env
# Run this script before generate_passwords.sh during initial setup

set -eu

ENV_FILE=".env"

extract_route_src() {
    sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n 1
}

colima_running() {
    command -v colima >/dev/null 2>&1 && colima status >/dev/null 2>&1
}

# Create .env from .env.example if it doesn't exist
if [ ! -f "$ENV_FILE" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example "$ENV_FILE"
        echo "📄 Created .env from .env.example"
    else
        touch "$ENV_FILE"
        echo "📄 Created empty .env"
    fi
fi

detect_ipv4() {
    local ip=""
    # On macOS with Colima, prefer the VM's advertised reachable address rather than
    # host-side route inspection, which can return the host IP instead of the VM IP.
    if colima_running; then
        ip=$(colima status -j 2>/dev/null | sed -n 's/.*"ip_address":"\([^"]*\)".*/\1/p' | head -n 1 || true)
        if [ -z "$ip" ]; then
            ip=$(colima list -j 2>/dev/null | sed -n 's/.*"address":"\([^"]*\)".*/\1/p' | head -n 1 || true)
        fi
    fi
    # Try ip route first (most reliable on Linux)
    if [ -z "$ip" ] && command -v ip >/dev/null 2>&1; then
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null | extract_route_src || true)
    fi
    # Fallback to hostname -I (Linux)
    if [ -z "$ip" ] && command -v hostname >/dev/null 2>&1; then
        ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    fi
    echo "$ip"
}

detect_ipv6() {
    local ip=""
    if colima_running; then
        ip=$(colima ssh -- ip -6 route get 2606:4700::1 2>/dev/null | extract_route_src || true)
        if [ -z "$ip" ]; then
            ip=$(colima ssh -- sh -c "ip -6 addr show scope global up | awk '/inet6 / {print \$2}' | cut -d/ -f1 | head -n 1" 2>/dev/null || true)
        fi
    fi
    if [ -z "$ip" ] && command -v ip >/dev/null 2>&1; then
        ip=$(ip -6 route get 2606:4700::1 2>/dev/null | extract_route_src || true)
    fi
    echo "${ip%%/*}"
}

is_usable_ipv6() {
    local ip="${1%%/*}"
    case "$ip" in
        ""|::|::1|localhost|fe80:*|FE80:*|'['*|*']'*)
            return 1
            ;;
    esac
    return 0
}

# IPv4
if grep -q "^PUBLIC_IPV4=.\+" "$ENV_FILE" 2>/dev/null; then
    echo "✅ PUBLIC_IPV4 already set"
else
    ipv4=$(detect_ipv4)
    if [ -z "$ipv4" ]; then
        echo "⚠️  Could not detect IPv4 address - set PUBLIC_IPV4 manually in .env"
    elif [ "$ipv4" = "127.0.0.1" ]; then
        echo "⚠️  Detected 127.0.0.1 which won't work - set PUBLIC_IPV4 manually in .env"
    else
        # Replace existing empty PUBLIC_IPV4= or append
        if grep -q "^PUBLIC_IPV4=" "$ENV_FILE" 2>/dev/null; then
            sed -i.bak "s/^PUBLIC_IPV4=.*/PUBLIC_IPV4=$ipv4/" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
        else
            echo "PUBLIC_IPV4=$ipv4" >> "$ENV_FILE"
        fi
        echo "✅ PUBLIC_IPV4=$ipv4"
    fi
fi

# IPv6
if grep -q "^PUBLIC_IPV6=.\+" "$ENV_FILE" 2>/dev/null; then
    echo "✅ PUBLIC_IPV6 already set"
else
    ipv6=$(detect_ipv6)
    if is_usable_ipv6 "$ipv6"; then
        if grep -q "^PUBLIC_IPV6=" "$ENV_FILE" 2>/dev/null; then
            sed -i.bak "s/^PUBLIC_IPV6=.*/PUBLIC_IPV6=$ipv6/" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
        else
            echo "PUBLIC_IPV6=$ipv6" >> "$ENV_FILE"
        fi
        echo "✅ PUBLIC_IPV6=$ipv6"
    elif [ -n "$ipv6" ]; then
        echo "⚠️  Detected IPv6 $ipv6 which is not usable as an external address - set PUBLIC_IPV6 manually if needed"
    fi
fi
