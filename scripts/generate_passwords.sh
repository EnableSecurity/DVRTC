#!/bin/bash
# Generate secure passwords and append to .env
# Run this script before starting docker compose for the first time

set -e

ENV_FILE=".env"

# Create .env if it doesn't exist
touch "$ENV_FILE"

generate_password() {
    openssl rand -base64 24 | tr -dc 'a-zA-Z0-9'
}

add_password() {
    local var_name="$1"
    local description="$2"

    if grep -q "^${var_name}=.\+" "$ENV_FILE" 2>/dev/null; then
        echo "$var_name already set"
    else
        local password=$(generate_password)
        # Replace empty value or append if not present
        if grep -q "^${var_name}=" "$ENV_FILE" 2>/dev/null; then
            sed -i.bak "s/^${var_name}=.*/${var_name}=$password/" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
        else
            echo "# $description" >> "$ENV_FILE"
            echo "${var_name}=$password" >> "$ENV_FILE"
        fi
        echo "Generated $var_name"
    fi
}

echo "Generating passwords..."

add_password "MYSQL_ROOT_PASSWORD" "MySQL root password"
add_password "SIPCALLER1_PASSWORD" "Internal SIP caller password"

echo ""
echo "Passwords added to $ENV_FILE"
