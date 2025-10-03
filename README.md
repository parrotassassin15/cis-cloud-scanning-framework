# Cloud Security CIS Controls Audit Framework

A comprehensive bash-based security assessment framework that runs multiple industry-standard security tools against cloud environments to audit CIS (Center for Internet Security) controls compliance.

## 🎯 Overview

This automated security audit script integrates multiple security scanning tools to provide comprehensive security assessments across AWS, Azure, and GCP cloud environments. It generates detailed compliance reports based on CIS benchmarks and best practices.

## 🔧 Supported Tools

- **Prowler** - AWS, Azure, and GCP security best practices scanner
- **ScoutSuite** - Multi-cloud security auditing tool
- **CloudSploit** - Cloud security configuration scanner
- **Checkov** - Infrastructure as Code (IaC) security scanner
- **Steampipe** - Cloud infrastructure query tool

## ☁️ Supported Cloud Providers

- Amazon Web Services (AWS)
- Microsoft Azure
- Google Cloud Platform (GCP)

## 📋 Prerequisites

### System Requirements

- Linux/macOS/WSL environment
- Bash 4.0 or higher
- Python 3.8 or higher
- pip3
- Node.js and npm (for CloudSploit)
- Git
- jq (JSON processor)

### Installation

Install basic dependencies:

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y python3 python3-pip jq git nodejs npm

# macOS
brew install python3 jq git node
```

## 🚀 Quick Start

### 1. Install Security Tools

```bash
./cloud_security_audit.sh --install
```

This will automatically install:
- Prowler
- ScoutSuite
- Checkov

### 2. Configure Cloud Credentials

#### AWS

```bash
export AWS_ACCESS_KEY_ID="your_access_key"
export AWS_SECRET_ACCESS_KEY="your_secret_key"
export AWS_DEFAULT_REGION="us-east-1"  # Optional
export AWS_SESSION_TOKEN="your_token"   # Optional, for temporary credentials
```

#### Azure

```bash
export AZURE_CLIENT_ID="your_client_id"
export AZURE_CLIENT_SECRET="your_client_secret"
export AZURE_TENANT_ID="your_tenant_id"
export AZURE_SUBSCRIPTION_ID="your_subscription_id"
```

#### GCP

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
```

### 3. Run Security Audit

```bash
# Audit AWS environment
./cloud_security_audit.sh --provider aws

# Audit Azure environment
./cloud_security_audit.sh --provider azure

# Audit GCP environment
./cloud_security_audit.sh --provider gcp

# Audit all cloud providers
./cloud_security_audit.sh --provider all

# Include Infrastructure as Code scanning
./cloud_security_audit.sh --provider aws --scan-iac
```

## 📖 Usage

```
Usage: ./cloud_security_audit.sh [OPTIONS]

OPTIONS:
    -p, --provider    Cloud provider (aws|azure|gcp|all)
    -i, --install     Install security tools
    -s, --scan-iac    Scan Infrastructure as Code
    -h, --help        Show help message
```

### Examples

```bash
# First-time setup
./cloud_security_audit.sh --install

# Run AWS audit with IaC scanning
./cloud_security_audit.sh --provider aws --scan-iac

# Comprehensive multi-cloud audit
./cloud_security_audit.sh --provider all --scan-iac
```

## 📊 Output Reports

The script generates timestamped reports in the following structure:

```
security_reports_YYYYMMDD_HHMMSS/
├── prowler/
│   ├── compliance/
│   ├── output.html
│   ├── output.json
│   └── output.csv
├── scoutsuite/
│   ├── aws/
│   ├── azure/
│   └── gcp/
├── cloudsploit/
│   └── aws_results.json
├── checkov/
│   └── iac_results.json
├── logs/
│   ├── prowler_aws.log
│   ├── scoutsuite_aws.log
│   └── cloudsploit_aws.log
└── SECURITY_SUMMARY.txt
```

## 🔍 What Gets Scanned

### AWS Audits
- CIS AWS Foundations Benchmark 2.0
- IAM configurations
- S3 bucket security
- EC2 security groups
- CloudTrail logging
- VPC configurations
- KMS encryption
- And 200+ additional checks

### Azure Audits
- CIS Microsoft Azure Foundations Benchmark 2.0
- Azure Active Directory
- Storage accounts
- Network security groups
- SQL databases
- Key vaults
- Monitoring and logging

### GCP Audits
- CIS Google Cloud Platform Foundation Benchmark 2.0
- IAM and service accounts
- Cloud Storage buckets
- Compute Engine instances
- VPC networks
- Cloud SQL
- Logging and monitoring

### Infrastructure as Code
- Terraform configurations
- CloudFormation templates
- Kubernetes manifests
- Dockerfile security
- Helm charts

## 🔐 Security Best Practices

1. **Credentials Management**
   - Never hardcode credentials in the script
   - Use environment variables or credential files
   - Rotate credentials regularly
   - Use read-only credentials when possible

2. **Permissions Required**
   - AWS: ReadOnlyAccess or SecurityAudit policy
   - Azure: Reader role at subscription level
   - GCP: Viewer role at project/organization level

3. **Running the Audits**
   - Run from a secure, trusted environment
   - Review reports on encrypted storage
   - Don't commit reports to version control
   - Delete old reports after review

## 🛠️ Troubleshooting

### Common Issues

**Issue: "AWS credentials not set"**
```bash
# Solution: Export AWS credentials
export AWS_ACCESS_KEY_ID="your_key"
export AWS_SECRET_ACCESS_KEY="your_secret"
```

**Issue: "Permission denied" errors**
```bash
# Solution: Make script executable
chmod +x cloud_security_audit.sh
```

**Issue: Tools not found after installation**
```bash
# Solution: Add Python bin to PATH
export PATH="$HOME/.local/bin:$PATH"
```

**Issue: Prowler fails with authentication error**
```bash
# Solution: Verify credentials
aws sts get-caller-identity  # For AWS
az account show              # For Azure
gcloud auth list             # For GCP
```

## 📝 Adding to .gitignore

Add these lines to your `.gitignore`:

```
# Security reports
security_reports_*/

# Credentials
.env
*.credentials
*.key.json

# Tool directories
cloudsploit/
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is provided as-is for security assessment purposes.

## ⚠️ Disclaimer

This tool is for authorized security assessments only. Always ensure you have proper authorization before scanning any cloud environment. Unauthorized scanning may violate terms of service and applicable laws.

## 🔗 Additional Resources

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Prowler Documentation](https://github.com/prowler-cloud/prowler)
- [ScoutSuite Documentation](https://github.com/nccgroup/ScoutSuite)
- [Checkov Documentation](https://www.checkov.io/)

## 📧 Support

For issues, questions, or contributions, please open an issue on the GitHub repository.