#!/bin/bash
# SENTINEL Ultimate - Production Deployment Script
# Run as root on target server

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $*"; }

# Configuration
INSTALL_DIR="/opt/sentinel"
SERVICE_USER="sentinel"
VENV_DIR="${INSTALL_DIR}/.venv"
ENV_FILE="/etc/sentinel/environment"
REPO_URL="${REPO_URL:-https://github.com/yourorg/sentinel-ultimate.git}"
BRANCH="${BRANCH:-main}"

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

install_dependencies() {
    log_step "Installing system dependencies..."
    apt-get update
    apt-get install -y --no-install-recommends \
        python3.13 python3.13-venv python3.13-dev \
        gcc libffi-dev libssl-dev \
        redis-server \
        nginx \
        suricata \
        curl jq \
        ca-certificates
}

create_user() {
    log_step "Creating service user..."
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" -c "SENTINEL Service" "$SERVICE_USER"
    fi
}

deploy_application() {
    log_step "Deploying application..."

    # Create directory structure
    mkdir -p "$INSTALL_DIR"/{data,logs,tmp}
    mkdir -p /etc/sentinel
    mkdir -p /var/log/sentinel

    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" /var/log/sentinel
    chmod 700 "$INSTALL_DIR"/data "$INSTALL_DIR"/logs "$INSTALL_DIR"/tmp

    # Create virtual environment
    if [[ ! -d "$VENV_DIR" ]]; then
        python3.13 -m venv "$VENV_DIR"
    fi

    # Install Python dependencies
    "$VENV_DIR/bin/pip" install --upgrade pip
    "$VENV_DIR/bin/pip" install --no-cache-dir -r "$INSTALL_DIR/requirements.txt"

    # Set ownership
    chown -R "$SERVICE_USER:$SERVICE_USER" "$VENV_DIR"
}

configure_environment() {
    log_step "Configuring environment..."

    if [[ ! -f "$ENV_FILE" ]]; then
        cp "$INSTALL_DIR/deploy/environment.example" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
        chown root:"$SERVICE_USER" "$ENV_FILE"
        log_warn "Created $ENV_FILE - YOU MUST EDIT IT with your secrets!"
        log_warn "Required: SENTINEL_MASTER_KEY, SENTINEL_OIDC_ISSUER, SENTINEL_OIDC_AUDIENCE"
    fi
}

configure_nginx() {
    log_step "Configuring NGINX..."

    cp "$INSTALL_DIR/deploy/nginx.conf.example" /etc/nginx/sites-available/sentinel
    ln -sf /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default

    # TLS certificates - use certbot in production
    mkdir -p /etc/ssl/sentinel
    if [[ ! -f /etc/ssl/sentinel/fullchain.pem ]]; then
        log_warn "Generating self-signed certificates for testing..."
        openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
            -nodes -keyout /etc/ssl/sentinel/privkey.pem \
            -out /etc/ssl/sentinel/fullchain.pem \
            -subj "/CN=sentinel.example.internal"
        chmod 600 /etc/ssl/sentinel/privkey.pem
        chmod 644 /etc/ssl/sentinel/fullchain.pem
        log_warn "Replace with Let's Encrypt certificates for production!"
    fi

    nginx -t
    systemctl enable nginx
    systemctl restart nginx
}

configure_suricata() {
    log_step "Configuring Suricata..."

    mkdir -p /etc/suricata/rules
    cp "$INSTALL_DIR/layer2/suricata/suricata.yaml.example" /etc/suricata/suricata.yaml

    # Enable and start
    systemctl enable suricata
    systemctl restart suricata
}

configure_redis() {
    log_step "Configuring Redis..."

    # Basic hardening
    sed -i 's/^# requirepass .*/requirepass '"${REDIS_PASSWORD}"'/' /etc/redis/redis.conf
    sed -i 's/^bind 127.0.0.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf
    sed -i 's/^protected-mode yes/protected-mode yes/' /etc/redis/redis.conf

    systemctl enable redis-server
    systemctl restart redis-server
}

install_systemd() {
    log_step "Installing systemd services..."

    cp "$INSTALL_DIR/deploy/systemd/sentinel-api.service" /etc/systemd/system/
    cp "$INSTALL_DIR/deploy/systemd/sentinel-suricata-forwarder.service" /etc/systemd/system/

    systemctl daemon-reload
    systemctl enable sentinel-api
    systemctl enable sentinel-suricata-forwarder
}

start_services() {
    log_step "Starting services..."

    systemctl restart sentinel-api
    sleep 3
    systemctl restart sentinel-suricata-forwarder

    # Verify
    if systemctl is-active --quiet sentinel-api; then
        log_info "SENTINEL API started successfully"
    else
        log_error "SENTINEL API failed to start"
        systemctl status sentinel-api
        exit 1
    fi

    if systemctl is-active --quiet sentinel-suricata-forwarder; then
        log_info "Suricata forwarder started successfully"
    else
        log_warn "Suricata forwarder failed to start (may need Suricata running first)"
    fi
}

verify_deployment() {
    log_step "Verifying deployment..."

    # Health check
    if curl -sf http://localhost:8080/health >/dev/null; then
        log_info "Health check passed"
    else
        log_error "Health check failed"
        exit 1
    fi

    # Readiness check
    if curl -sf http://localhost:8080/ready >/dev/null; then
        log_info "Readiness check passed"
    else
        log_warn "Readiness check failed (may be degraded mode)"
    fi

    # Metrics endpoint
    if curl -sf http://localhost:8080/metrics | grep -q sentinel_; then
        log_info "Metrics endpoint working"
    else
        log_warn "Metrics endpoint not returning expected metrics"
    fi

    # API test
    if curl -sf -X POST http://localhost:8080/v1/authorize \
        -H "Content-Type: application/json" \
        -d '{"identity":"test","role":"user","method":"GET","path":"/","body_size":0,"zone":"user"}' \
        | grep -q "action"; then
        log_info "Authorization API working"
    else
        log_warn "Authorization API test failed"
    fi
}

main() {
    echo
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     SENTINEL ULTIMATE - PRODUCTION DEPLOYMENT               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo

    check_root
    install_dependencies
    create_user
    deploy_application
    configure_environment
    configure_nginx
    configure_redis
    configure_suricata
    install_systemd
    start_services
    verify_deployment

    echo
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║     DEPLOYMENT COMPLETE                                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo
    log_info "Next steps:"
    log_info "  1. Edit $ENV_FILE with production secrets"
    log_info "  2. Configure OIDC provider (Keycloak/Auth0/Azure AD)"
    log_info "  3. Obtain Let's Encrypt TLS certificates: certbot --nginx -d sentinel.example.com"
    log_info "  4. Configure Suricata rules in /etc/suricata/rules/"
    log_info "  5. Set up monitoring: docker compose -f docker-compose.yml --profile monitoring up -d"
    log_info "  6. Test all endpoints and verify logs"
    echo
    log_warn "IMPORTANT: This is a security gateway. Test thoroughly before production use!"
}

# Command handling
case "${1:-deploy}" in
    deploy)
        main
        ;;
    verify)
        verify_deployment
        ;;
    start)
        systemctl start sentinel-api sentinel-suricata-forwarder
        ;;
    stop)
        systemctl stop sentinel-api sentinel-suricata-forwarder
        ;;
    restart)
        systemctl restart sentinel-api sentinel-suricata-forwarder
        ;;
    logs)
        journalctl -u sentinel-api -f
        ;;
    status)
        systemctl status sentinel-api sentinel-suricata-forwarder
        ;;
    update)
        log_step "Updating application..."
        cd "$INSTALL_DIR"
        git pull origin "$BRANCH"
        "$VENV_DIR/bin/pip" install --no-cache-dir -r requirements.txt
        systemctl restart sentinel-api sentinel-suricata-forwarder
        verify_deployment
        ;;
    *)
        echo "Usage: $0 {deploy|verify|start|stop|restart|logs|status|update}"
        exit 1
        ;;
esac