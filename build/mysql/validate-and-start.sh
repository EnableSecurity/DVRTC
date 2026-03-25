#!/bin/bash
# Validate MySQL environment before starting

# Check if MYSQL_ROOT_PASSWORD is set
if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
    echo "======================================================================="
    echo "ERROR: MYSQL_ROOT_PASSWORD is not set"
    echo "======================================================================="
    echo ""
    echo "The MySQL database requires MYSQL_ROOT_PASSWORD to be set."
    echo ""
    echo "Fix this by running:"
    echo "  ./scripts/generate_passwords.sh"
    echo ""
    echo "This will generate secure random passwords for:"
    echo "  - MYSQL_ROOT_PASSWORD"
    echo "  - SIPCALLER1_PASSWORD"
    echo ""
    echo "======================================================================="
    exit 1
fi

# Validation passed, start MySQL with original entrypoint
exec docker-entrypoint.sh "$@"
