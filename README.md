# 🔥 FireBae - Firebase Misconfiguration Security Scanner
### *Created by NodeRisk*

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.6+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-red.svg" alt="License">
  <img src="https://img.shields.io/badge/Security-Tool-orange.svg" alt="Security">
</p>

```
▄████  ▄█ █▄▄▄▄ ▄███▄   ███   ██   ▄███▄   
█▀   ▀ ██ █  ▄▀ █▀   ▀  █  █  █ █  █▀   ▀  
█▀▀    ██ █▀▀▌  ██▄▄    █ ▀ ▄ █▄▄█ ██▄▄    
█      ▐█ █  █  █▄   ▄▀ █  ▄▀ █  █ █▄   ▄▀ 
 █      ▐   █   ▀███▀   ███      █ ▀███▀   
  ▀        ▀                    █          
                               ▀           
```

FireBae is a comprehensive Firebase misconfiguration scanner designed for security researchers and penetration testers. It automatically detects common Firebase security misconfigurations including public database access, exposed storage buckets, and leaked configuration data.

** For educational purposes and authorized pentest engagements only**

##  Features

###  **Read-Only Security Checks** (Safe)
- **Realtime Database** - Test for public read access
- **Firestore** - Check for public document listing
- **Storage Buckets** - Detect publicly listable buckets
- **Firebase Hosting** - Probe for live sites and exposed configs
- **Cloud Functions** - Discover accessible function endpoints
- **Configuration Endpoints** - Find exposed Firebase config files

###  **Smart Target Extraction**
- Extract targets from Firebase configuration JSON
- Parse project IDs from API endpoints
- Auto-detect projects from `databaseURL`, `storageBucket`, etc.
- Support for config files and text snippets

###  **Optional Write Tests** (Dangerous - Authorization Required)
- Realtime Database write/delete operations
- Firestore document creation/deletion
- Storage bucket file upload/deletion
- Automatic cleanup of test artifacts

###  **Professional Reporting**
- Color-coded severity levels
- Comprehensive findings summary
- JSON and CSV export options
- Actionable security recommendations

##  Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/firebae.git
cd firebae

# Install dependencies
pip install requests

# Make executable (optional)
chmod +x firebae.py
```

##  Usage Examples

### Basic Target Scanning
```bash
# Scan specific Firebase projects
python3 firebae.py --targets project-id-1 project-id-2

# Quick scan with faster timing
python3 firebae.py --targets my-project --sleep 0.2
```

### Smart Config Extraction
```bash
# Extract targets from Firebase config snippet
python3 firebae.py --config-text '{"projectId": "vulnerable-app", "databaseURL": "https://vulnerable-app.firebaseio.com"}'

# Extract from saved config file
python3 firebae.py --config-file firebase-config.json

# When you discover API endpoints like:
# /v1alpha/projects/-/apps/1:123456:web:abc123/webConfig
python3 firebae.py --config-text '/v1alpha/projects/target-project/apps/1:123456:web:abc123/webConfig'
```

### Advanced Security Testing
```bash
# Read-only comprehensive scan with reporting
python3 firebae.py --targets my-target \
  --out-json results.json \
  --out-csv summary.csv

# DANGEROUS: Write tests (only with explicit authorization)
python3 firebae.py --targets authorized-target \
  --confirm-write \
  --upload-file proof.txt \
  --upload-name "security-test.txt" \
  --upload-folder "pentest-evidence" \
  --cleanup
```

##  Sample Output

```
🔍 SCAN RESULTS SUMMARY
================================================================================
📊 Scanned 2 target(s)

🚨 CRITICAL: Realtime Database Public Read Access
   ⚠️  vulnerable-app -> https://vulnerable-app.firebaseio.com/.json

⚠️  HIGH: Firebase Configuration Exposed
   📄 vulnerable-app -> https://vulnerable-app.firebaseapp.com/__/firebase/init.json

🔥 CRITICAL: Storage Bucket Write Access
   ✍️  vulnerable-app -> vulnerable-app.firebasestorage.app

--------------------------------------------------------------------------------
🚨 SECURITY ISSUES FOUND: 3 critical finding(s)
   🔧 Recommendation: Review Firebase security rules immediately
================================================================================
```

## 🛠️ Command Line Options

| Option | Description |
|--------|-------------|
| `--targets` | Project IDs, hostnames, or bucket names to scan |
| `--config-file` | Extract targets from Firebase config JSON file |
| `--config-text` | Extract targets from config text/snippet |
| `--confirm-write` | Enable dangerous write tests (requires explicit flag) |
| `--upload-file` | Local file to upload during storage tests |
| `--upload-name` | Name for uploaded test file |
| `--upload-folder` | Folder/prefix for uploaded files |
| `--cleanup` | Attempt to delete test artifacts after upload |
| `--out-json` | Save detailed results to JSON file |
| `--out-csv` | Save summary to CSV file |
| `--sleep` | Delay between requests (default: 0.4s) |

##  What FireBae Detects

###  Critical Vulnerabilities
- **Public Database Access** - Realtime Database or Firestore readable by anyone
- **Public Storage Buckets** - Listable or writable storage buckets
- **Write Permissions** - Unauthorized write access to databases/storage

###  High Severity Issues
- **Exposed API Keys** - Firebase configuration files accessible publicly
- **Configuration Leakage** - Project details exposed via config endpoints

###  Informational Findings
- **Live Hosting Sites** - Active Firebase hosting deployments
- **Accessible Functions** - Discoverable Cloud Function endpoints

## 🔧 Configuration Extraction Patterns

FireBae automatically extracts Firebase targets from:

```javascript
// Firebase Web Config
{
  "projectId": "my-project",
  "apiKey": "AIza...",
  "authDomain": "my-project.firebaseapp.com",
  "databaseURL": "https://my-project.firebaseio.com",
  "storageBucket": "my-project.firebasestorage.app"
}

// API Endpoints
/v1alpha/projects/-/apps/1:123:web:abc/webConfig
/v1beta1/projects/my-project/webApps

// URLs in Source Code
https://my-project.firebaseio.com
https://my-project.firebasestorage.app
```

##  Legal & Ethical Use

** IMPORTANT DISCLAIMER:**

FireBae is intended for:
- **Authorized security testing** of your own applications
- **Bug bounty programs** with explicit permission
- **Educational purposes** in controlled environments
- **Security research** with proper authorization

**DO NOT USE** against targets you don't own or lack explicit written permission to test.

### Responsible Disclosure
If you discover vulnerabilities using FireBae:
1. Report to the application owner immediately
2. Do not access or modify sensitive data
3. Clean up any test artifacts created
4. Follow responsible disclosure practices

##  Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.

### Development Setup
```bash
git clone https://github.com/yourusername/firebae.git
cd firebae

# Install development dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/
```

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Acknowledgments

- Firebase security research community
- Bug bounty hunters and security researchers
- Open source security tools ecosystem

##  Support

-  **Bug Reports**: [GitHub Issues](https://github.com/yourusername/firebae/issues)
-  **Feature Requests**: [GitHub Discussions](https://github.com/yourusername/firebae/discussions)
-  **Documentation**: [Wiki](https://github.com/yourusername/firebae/wiki)

---

<p align="center">
  <strong>🔥 FireBae by NodeRisk - Securing Firebase, One Scan at a Time 🔥</strong>
</p>

<p align="center">
  Made with ❤️ for the security community
</p>
