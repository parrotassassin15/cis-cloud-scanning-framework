#!/bin/bash

################################################################################
# Cloud Security CIS Controls Audit Script
# Runs multiple security tools against cloud environments (AWS, Azure, GCP)
# Tools: Prowler, ScoutSuite, CloudSploit, Steampipe, Checkov
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="./security_reports_${TIMESTAMP}"
CLOUD_PROVIDER=""
PARALLEL_SCANS=false

# Banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║     Cloud Security CIS Controls Audit Script              ║"
echo "║     Multi-Tool Security Assessment Framework              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

################################################################################
# Functions
################################################################################

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_dependencies() {
    print_status "Checking dependencies..."
    
    local missing_deps=()
    
    # Check for basic utilities
    command -v jq >/dev/null 2>&1 || missing_deps+=("jq")
    command -v git >/dev/null 2>&1 || missing_deps+=("git")
    command -v python3 >/dev/null 2>&1 || missing_deps+=("python3")
    command -v pip3 >/dev/null 2>&1 || missing_deps+=("pip3")
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing dependencies: ${missing_deps[*]}"
        print_status "Install them with: sudo apt install ${missing_deps[*]}"
        exit 1
    fi
    
    print_success "All basic dependencies installed"
}

setup_environment() {
    print_status "Setting up environment..."
    
    mkdir -p "$REPORT_DIR"/{prowler,scoutsuite,cloudsploit,steampipe,checkov,pacu}
    mkdir -p "$REPORT_DIR"/logs
    
    print_success "Report directory created: $REPORT_DIR"
}

install_prowler() {
    if ! command -v prowler >/dev/null 2>&1; then
        print_status "Installing Prowler..."
        pip3 install prowler --quiet
        print_success "Prowler installed"
    else
        print_success "Prowler already installed"
    fi
}

install_scoutsuite() {
    if ! command -v scout >/dev/null 2>&1; then
        print_status "Installing ScoutSuite..."
        pip3 install scoutsuite --quiet
        print_success "ScoutSuite installed"
    else
        print_success "ScoutSuite already installed"
    fi
}

install_checkov() {
    if ! command -v checkov >/dev/null 2>&1; then
        print_status "Installing Checkov..."
        pip3 install checkov --quiet
        print_success "Checkov installed"
    else
        print_success "Checkov already installed"
    fi
}

################################################################################
# AWS Security Audits
################################################################################

audit_aws() {
    print_status "Starting AWS Security Audit..."
    
    # Check AWS credentials
    if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
        print_error "AWS credentials not set. Export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
        return 1
    fi
    
    print_success "AWS credentials detected"
    
    # Run Prowler
    run_prowler_aws
    
    # Run ScoutSuite
    run_scoutsuite_aws
    
    # Run CloudSploit (if installed)
    run_cloudsploit_aws
}

run_prowler_aws() {
    print_status "Running Prowler for AWS..."
    
    local prowler_output="$REPORT_DIR/prowler"
    
    # Run Prowler with CIS benchmark
    prowler aws \
        --compliance cis_2.0_aws \
        --output-formats json html csv \
        --output-directory "$prowler_output" \
        --verbose \
        2>&1 | tee "$REPORT_DIR/logs/prowler_aws.log"
    
    if [ $? -eq 0 ]; then
        print_success "Prowler AWS scan completed"
        print_status "Reports saved to: $prowler_output"
    else
        print_error "Prowler AWS scan failed"
    fi
}

run_scoutsuite_aws() {
    print_status "Running ScoutSuite for AWS..."
    
    scout aws \
        --report-dir "$REPORT_DIR/scoutsuite/aws" \
        --force \
        2>&1 | tee "$REPORT_DIR/logs/scoutsuite_aws.log"
    
    if [ $? -eq 0 ]; then
        print_success "ScoutSuite AWS scan completed"
    else
        print_error "ScoutSuite AWS scan failed"
    fi
}

run_cloudsploit_aws() {
    if [ ! -d "./cloudsploit" ]; then
        print_status "Cloning CloudSploit..."
        git clone https://github.com/aquasecurity/cloudsploit.git
        cd cloudsploit && npm install && cd ..
    fi
    
    print_status "Running CloudSploit for AWS..."
    
    cd cloudsploit
    node index.js \
        --cloud aws \
        --compliance cis \
        --json "../$REPORT_DIR/cloudsploit/aws_results.json" \
        2>&1 | tee "../$REPORT_DIR/logs/cloudsploit_aws.log"
    cd ..
    
    print_success "CloudSploit AWS scan completed"
}

################################################################################
# Azure Security Audits
################################################################################

audit_azure() {
    print_status "Starting Azure Security Audit..."
    
    # Check Azure credentials
    if [ -z "$AZURE_CLIENT_ID" ] || [ -z "$AZURE_CLIENT_SECRET" ] || [ -z "$AZURE_TENANT_ID" ]; then
        print_error "Azure credentials not set."
        print_error "Export: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID"
        return 1
    fi
    
    print_success "Azure credentials detected"
    
    # Run Prowler
    run_prowler_azure
    
    # Run ScoutSuite
    run_scoutsuite_azure
}

run_prowler_azure() {
    print_status "Running Prowler for Azure..."
    
    prowler azure \
        --compliance cis_2.0_azure \
        --sp-env-auth \
        --output-formats json html csv \
        --output-directory "$REPORT_DIR/prowler" \
        --verbose \
        2>&1 | tee "$REPORT_DIR/logs/prowler_azure.log"
    
    if [ $? -eq 0 ]; then
        print_success "Prowler Azure scan completed"
    else
        print_error "Prowler Azure scan failed"
    fi
}

run_scoutsuite_azure() {
    print_status "Running ScoutSuite for Azure..."
    
    scout azure \
        --report-dir "$REPORT_DIR/scoutsuite/azure" \
        --force \
        --client-id "$AZURE_CLIENT_ID" \
        --client-secret "$AZURE_CLIENT_SECRET" \
        --tenant-id "$AZURE_TENANT_ID" \
        2>&1 | tee "$REPORT_DIR/logs/scoutsuite_azure.log"
    
    if [ $? -eq 0 ]; then
        print_success "ScoutSuite Azure scan completed"
    else
        print_error "ScoutSuite Azure scan failed"
    fi
}

################################################################################
# GCP Security Audits
################################################################################

audit_gcp() {
    print_status "Starting GCP Security Audit..."
    
    # Check GCP credentials
    if [ -z "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
        print_error "GCP credentials not set. Export GOOGLE_APPLICATION_CREDENTIALS"
        return 1
    fi
    
    print_success "GCP credentials detected"
    
    # Run Prowler
    run_prowler_gcp
    
    # Run ScoutSuite
    run_scoutsuite_gcp
}

run_prowler_gcp() {
    print_status "Running Prowler for GCP..."
    
    prowler gcp \
        --compliance cis_2.0_gcp \
        --output-formats json html csv \
        --output-directory "$REPORT_DIR/prowler" \
        --verbose \
        2>&1 | tee "$REPORT_DIR/logs/prowler_gcp.log"
    
    if [ $? -eq 0 ]; then
        print_success "Prowler GCP scan completed"
    else
        print_error "Prowler GCP scan failed"
    fi
}

run_scoutsuite_gcp() {
    print_status "Running ScoutSuite for GCP..."
    
    scout gcp \
        --report-dir "$REPORT_DIR/scoutsuite/gcp" \
        --force \
        --service-account "$GOOGLE_APPLICATION_CREDENTIALS" \
        2>&1 | tee "$REPORT_DIR/logs/scoutsuite_gcp.log"
    
    if [ $? -eq 0 ]; then
        print_success "ScoutSuite GCP scan completed"
    else
        print_error "ScoutSuite GCP scan failed"
    fi
}

################################################################################
# Infrastructure as Code Scanning
################################################################################

scan_iac() {
    print_status "Scanning Infrastructure as Code with Checkov..."
    
    if [ -d "./terraform" ] || [ -d "./cloudformation" ] || [ -d "./kubernetes" ]; then
        checkov -d . \
            --framework terraform cloudformation kubernetes \
            --output json \
            --output-file "$REPORT_DIR/checkov/iac_results.json" \
            2>&1 | tee "$REPORT_DIR/logs/checkov.log"
        
        print_success "Checkov IaC scan completed"
    else
        print_warning "No IaC directories found (terraform/cloudformation/kubernetes)"
    fi
}

################################################################################
# Report Generation
################################################################################

generate_summary() {
    print_status "Generating summary report..."
    
    local summary_file="$REPORT_DIR/SECURITY_SUMMARY.txt"
    
    {
        echo "==============================================="
        echo "Cloud Security Audit Summary"
        echo "==============================================="
        echo "Timestamp: $TIMESTAMP"
        echo "Cloud Provider: $CLOUD_PROVIDER"
        echo ""
        echo "Reports Generated:"
        echo "  - Prowler: $REPORT_DIR/prowler/"
        echo "  - ScoutSuite: $REPORT_DIR/scoutsuite/"
        echo "  - CloudSploit: $REPORT_DIR/cloudsploit/"
        echo "  - Checkov: $REPORT_DIR/checkov/"
        echo ""
        echo "Logs: $REPORT_DIR/logs/"
        echo "==============================================="
    } > "$summary_file"
    
    cat "$summary_file"
    print_success "Summary report generated: $summary_file"
}

################################################################################
# Main Execution
################################################################################

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Cloud Security CIS Controls Audit Script

OPTIONS:
    -p, --provider    Cloud provider (aws|azure|gcp|all)
    -i, --install     Install security tools
    -s, --scan-iac    Scan Infrastructure as Code
    -h, --help        Show this help message

ENVIRONMENT VARIABLES:
    AWS:
        AWS_ACCESS_KEY_ID
        AWS_SECRET_ACCESS_KEY
        AWS_SESSION_TOKEN (optional)
        AWS_DEFAULT_REGION (optional)
    
    Azure:
        AZURE_CLIENT_ID
        AZURE_CLIENT_SECRET
        AZURE_TENANT_ID
        AZURE_SUBSCRIPTION_ID
    
    GCP:
        GOOGLE_APPLICATION_CREDENTIALS

EXAMPLES:
    # Audit AWS environment
    export AWS_ACCESS_KEY_ID="your_key"
    export AWS_SECRET_ACCESS_KEY="your_secret"
    $0 --provider aws
    
    # Audit all cloud providers
    $0 --provider all
    
    # Install tools first
    $0 --install

EOF
}

main() {
    local install_mode=false
    local scan_iac=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--provider)
                CLOUD_PROVIDER="$2"
                shift 2
                ;;
            -i|--install)
                install_mode=true
                shift
                ;;
            -s|--scan-iac)
                scan_iac=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Check dependencies
    check_dependencies
    
    # Install mode
    if [ "$install_mode" = true ]; then
        print_status "Installing security tools..."
        install_prowler
        install_scoutsuite
        install_checkov
        print_success "All tools installed successfully"
        exit 0
    fi
    
    # Validate provider
    if [ -z "$CLOUD_PROVIDER" ]; then
        print_error "Cloud provider not specified"
        show_usage
        exit 1
    fi
    
    # Setup environment
    setup_environment
    
    # Run audits based on provider
    case $CLOUD_PROVIDER in
        aws)
            audit_aws
            ;;
        azure)
            audit_azure
            ;;
        gcp)
            audit_gcp
            ;;
        all)
            print_status "Running audits for all cloud providers..."
            audit_aws || true
            audit_azure || true
            audit_gcp || true
            ;;
        *)
            print_error "Invalid cloud provider: $CLOUD_PROVIDER"
            print_error "Valid options: aws, azure, gcp, all"
            exit 1
            ;;
    esac
    
    # Scan IaC if requested
    if [ "$scan_iac" = true ]; then
        scan_iac
    fi
    
    # Generate summary
    generate_summary
    
    print_success "Security audit completed!"
    print_status "All reports saved to: $REPORT_DIR"
}

# Run main function
main "$@"
