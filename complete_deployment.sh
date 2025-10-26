#!/bin/bash
# Complete LogBERT Security Monitoring System Deployment Script
# This script sets up the entire real-time monitoring system with enhanced UI

set -e

echo "🛡️  LogBERT Security Monitoring System - Complete Deployment"
echo "=============================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[ℹ]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}$1${NC}"
}

# Check if we're in the correct directory
if [[ ! -f "integrated_monitoring_system.py" ]]; then
    print_error "Please run this script from the samplewar directory"
    exit 1
fi

print_header "📋 Step 1: Environment Setup"

# Check Python version
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d ' ' -f 2)
    print_info "Python version: $PYTHON_VERSION"
else
    print_error "Python 3 is required but not installed"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [[ ! -d "venv" ]]; then
    print_info "Creating Python virtual environment..."
    python3 -m venv venv
    print_status "Virtual environment created"
else
    print_info "Virtual environment already exists"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate

print_header "📦 Step 2: Installing Dependencies"

# Install dependencies
print_info "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
print_status "Dependencies installed"

print_header "📁 Step 3: Directory Structure Setup"

# Create necessary directories
print_info "Creating directory structure..."
mkdir -p models logs data exports temp
print_status "Directory structure created"

print_header "🧪 Step 4: Quick System Test"

# Test basic imports
python3 -c "
try:
    from monitoring_config import config
    from enhanced_realtime_analyzer import EnhancedRealTimeLogAnalyzer
    from integrated_monitoring_system import IntegratedMonitoringDashboard
    print('✓ All components imported successfully')
except Exception as e:
    print(f'✗ Import error: {e}')
    exit(1)
"

print_status "System components tested"

print_header "🎉 Deployment Complete!"

echo ""
print_info "🌐 To start the dashboard:"
echo "   source venv/bin/activate"
echo "   streamlit run integrated_monitoring_system.py"
echo ""
print_info "🔗 Dashboard will be available at: http://localhost:8501"
echo ""
print_status "🚀 System ready for real-time security monitoring!"
