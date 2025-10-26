#!/bin/bash
"""
Production WAF Deployment Script
================================
Complete deployment automation for production WAF system
"""

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WAF_HOME="/Users/moturisaisushanth/Downloads/samplewar"
VENV_PATH="$WAF_HOME/venv_new"
CONFIG_FILE="$WAF_HOME/production_config.json"
LOG_DIR="$WAF_HOME/waf_logs"

# Functions
print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check if we're in the right directory
    if [ ! -f "$WAF_HOME/production_waf_service.py" ]; then
        print_error "WAF service file not found. Please run from the correct directory."
        exit 1
    fi
    
    # Check virtual environment
    if [ ! -d "$VENV_PATH" ]; then
        print_error "Virtual environment not found at $VENV_PATH"
        exit 1
    fi
    
    # Check Python and packages
    source "$VENV_PATH/bin/activate"
    
    python -c "import fastapi, uvicorn, requests, psutil" 2>/dev/null || {
        print_error "Required Python packages not installed"
        print_info "Installing required packages..."
        python -m pip install fastapi uvicorn requests psutil watchdog
    }
    
    print_success "Prerequisites checked"
}

# Setup directories
setup_directories() {
    print_header "Setting up Directories"
    
    # Create log directories
    mkdir -p "$LOG_DIR"
    mkdir -p "$LOG_DIR/threats"
    mkdir -p "$LOG_DIR/metrics"
    mkdir -p "$LOG_DIR/access"
    
    # Create data directories
    mkdir -p "$WAF_HOME/data"
    mkdir -p "$WAF_HOME/config"
    
    print_success "Directories created"
}

# Build WAR applications
build_applications() {
    print_header "Building WAR Applications"
    
    cd "$WAF_HOME"
    
    # Check for Maven
    if ! command -v mvn &> /dev/null; then
        print_warning "Maven not found. Skipping WAR builds."
        return
    fi
    
    # Build each application
    for app_dir in blog-cms-app ecommerce-app rest-api-app; do
        if [ -d "$app_dir" ] && [ -f "$app_dir/pom.xml" ]; then
            print_info "Building $app_dir..."
            cd "$app_dir"
            mvn clean package -DskipTests -q || {
                print_warning "Failed to build $app_dir"
            }
            cd ..
        else
            print_warning "Application $app_dir not found or not a Maven project"
        fi
    done
    
    print_success "Application builds completed"
}

# Start WAF service
start_waf_service() {
    print_header "Starting WAF Service"
    
    cd "$WAF_HOME"
    source "$VENV_PATH/bin/activate"
    
    # Check if WAF is already running
    if pgrep -f "production_waf_service.py" > /dev/null; then
        print_warning "WAF service is already running"
        return
    fi
    
    # Start WAF service in background
    print_info "Starting WAF service on port 8000..."
    nohup python production_waf_service.py > "$LOG_DIR/waf_service.log" 2>&1 &
    WAF_PID=$!
    
    # Wait for service to start
    sleep 5
    
    # Health check
    if curl -s http://localhost:8000/health > /dev/null; then
        print_success "WAF service started successfully (PID: $WAF_PID)"
        echo $WAF_PID > "$LOG_DIR/waf.pid"
    else
        print_error "WAF service failed to start"
        exit 1
    fi
}

# Start log ingestion
start_log_ingestion() {
    print_header "Starting Log Ingestion"
    
    cd "$WAF_HOME"
    source "$VENV_PATH/bin/activate"
    
    # Check if log ingester is already running
    if pgrep -f "live_application_log_ingester.py" > /dev/null; then
        print_warning "Log ingester is already running"
        return
    fi
    
    # Start log ingestion in background
    print_info "Starting live log ingestion..."
    nohup python live_application_log_ingester.py > "$LOG_DIR/log_ingestion.log" 2>&1 &
    INGESTER_PID=$!
    
    print_success "Log ingestion started (PID: $INGESTER_PID)"
    echo $INGESTER_PID > "$LOG_DIR/ingester.pid"
}

# Generate test traffic
generate_test_traffic() {
    print_header "Generating Test Traffic"
    
    cd "$WAF_HOME"
    source "$VENV_PATH/bin/activate"
    
    # Start traffic generator
    print_info "Starting traffic generator..."
    python -c "
import time
import requests
import random

# Test URLs with different risk levels
test_requests = [
    {'path': '/', 'method': 'GET', 'risk': 'low'},
    {'path': '/admin', 'method': 'GET', 'risk': 'medium'},
    {'path': '/login', 'method': 'POST', 'risk': 'low'},
    {'path': '/search?q=test', 'method': 'GET', 'risk': 'low'},
    {'path': '/search?q=\' OR 1=1--', 'method': 'GET', 'risk': 'high'},
    {'path': '/<script>alert(1)</script>', 'method': 'GET', 'risk': 'high'},
    {'path': '/../../etc/passwd', 'method': 'GET', 'risk': 'high'},
    {'path': '/api/users', 'method': 'GET', 'risk': 'low'},
    {'path': '/wp-admin', 'method': 'GET', 'risk': 'medium'},
]

waf_url = 'http://localhost:8000/detect'

for i in range(20):
    req = random.choice(test_requests)
    
    test_data = {
        'ip': f'192.168.1.{100 + i}',
        'method': req['method'],
        'path': req['path'],
        'user_agent': 'Mozilla/5.0 (Test Traffic Generator)',
        'timestamp': str(time.time())
    }
    
    try:
        response = requests.post(waf_url, json=test_data, timeout=5)
        result = response.json()
        
        status = '🚨 BLOCKED' if result.get('blocked') else '✅ ALLOWED'
        print(f'{status} {req[\"path\"]} (Score: {result.get(\"anomaly_score\", 0):.3f})')
        
    except Exception as e:
        print(f'❌ Error testing {req[\"path\"]}: {e}')
    
    time.sleep(0.5)

print('\\n📊 Test traffic generation completed')
"
    
    print_success "Test traffic generated"
}

# Show status
show_status() {
    print_header "System Status"
    
    # WAF Service
    if curl -s http://localhost:8000/health > /dev/null; then
        print_success "WAF Service: Running (http://localhost:8000)"
        
        # Get metrics
        echo -e "${BLUE}📊 WAF Metrics:${NC}"
        curl -s http://localhost:8000/metrics | python -m json.tool 2>/dev/null || echo "Unable to fetch metrics"
    else
        print_error "WAF Service: Not running"
    fi
    
    # Check processes
    echo -e "\n${BLUE}🔍 Running Processes:${NC}"
    pgrep -f "production_waf_service.py" > /dev/null && print_success "WAF Service Process: Running" || print_error "WAF Service Process: Not running"
    pgrep -f "live_application_log_ingester.py" > /dev/null && print_success "Log Ingester Process: Running" || print_warning "Log Ingester Process: Not running"
    
    # Check log files
    echo -e "\n${BLUE}📋 Log Files:${NC}"
    if [ -d "$LOG_DIR" ]; then
        find "$LOG_DIR" -name "*.log" -type f | while read log_file; do
            size=$(du -h "$log_file" | cut -f1)
            print_info "$(basename "$log_file"): $size"
        done
    fi
    
    # Show recent threats
    if [ -d "$LOG_DIR/threats" ]; then
        threat_files=$(find "$LOG_DIR/threats" -name "*.log" -type f)
        if [ -n "$threat_files" ]; then
            echo -e "\n${BLUE}🚨 Recent Threats:${NC}"
            tail -5 $threat_files 2>/dev/null | head -10
        fi
    fi
}

# Stop services
stop_services() {
    print_header "Stopping Services"
    
    # Stop WAF service
    if [ -f "$LOG_DIR/waf.pid" ]; then
        WAF_PID=$(cat "$LOG_DIR/waf.pid")
        if kill $WAF_PID 2>/dev/null; then
            print_success "WAF service stopped"
        fi
        rm -f "$LOG_DIR/waf.pid"
    fi
    
    # Stop log ingester
    if [ -f "$LOG_DIR/ingester.pid" ]; then
        INGESTER_PID=$(cat "$LOG_DIR/ingester.pid")
        if kill $INGESTER_PID 2>/dev/null; then
            print_success "Log ingester stopped"
        fi
        rm -f "$LOG_DIR/ingester.pid"
    fi
    
    # Kill any remaining processes
    pkill -f "production_waf_service.py" 2>/dev/null || true
    pkill -f "live_application_log_ingester.py" 2>/dev/null || true
    
    print_success "All services stopped"
}

# Main deployment function
deploy_production() {
    print_header "🚀 PRODUCTION WAF DEPLOYMENT"
    
    check_prerequisites
    setup_directories
    build_applications
    start_waf_service
    start_log_ingestion
    
    # Wait a moment for services to stabilize
    sleep 3
    
    generate_test_traffic
    show_status
    
    print_header "🎉 DEPLOYMENT COMPLETED"
    echo -e "${GREEN}WAF System is now operational!${NC}"
    echo -e "${BLUE}Access Points:${NC}"
    echo -e "  • WAF API: http://localhost:8000"
    echo -e "  • Health Check: http://localhost:8000/health"
    echo -e "  • Metrics: http://localhost:8000/metrics"
    echo -e "  • Logs: $LOG_DIR"
    echo -e "\n${BLUE}Commands:${NC}"
    echo -e "  • Status: $0 --status"
    echo -e "  • Stop: $0 --stop"
    echo -e "  • Test: $0 --test"
}

# Command line interface
case "${1:-deploy}" in
    "deploy"|"start"|"")
        deploy_production
        ;;
    "stop")
        stop_services
        ;;
    "status")
        show_status
        ;;
    "test")
        generate_test_traffic
        ;;
    "restart")
        stop_services
        sleep 2
        deploy_production
        ;;
    "help"|"--help"|"-h")
        echo "Production WAF Deployment Script"
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  deploy, start  - Deploy and start WAF system (default)"
        echo "  stop          - Stop all services"
        echo "  status        - Show system status"
        echo "  test          - Generate test traffic"
        echo "  restart       - Restart all services"
        echo "  help          - Show this help"
        ;;
    *)
        print_error "Unknown command: $1"
        echo "Use '$0 help' for available commands"
        exit 1
        ;;
esac
