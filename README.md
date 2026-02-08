# 🔒 SecureFlow-Scanner

**CI/CD Pipeline Security Scanner to Detect Secrets, Vulnerabilities, and Misconfigurations**

SecureFlow-Scanner is a Python-based DevSecOps security tool being built step-by-step to help developers detect:

- Hardcoded secrets  
- Vulnerable dependencies  
- Unsafe Docker configurations  
- Infrastructure-as-Code misconfigurations  

This project is under active development and designed to become a production-ready CI/CD security scanner.

---

## 🚀 Current Status (MVP)

✅ CLI tool working (`secureflow scan`)  
✅ Core Finding + Location model implemented  
✅ Secrets Scanner implemented (AWS + GitHub token detection)  
✅ Exclusion support added (`--exclude`)  
🔜 JSON output reporting coming next  
🔜 SARIF output for GitHub Security tab planned  

---

## ✨ Current Features

### 🔑 Secrets Detection (MVP)

SecureFlow-Scanner can currently detect:

- AWS Access Keys  
- GitHub Personal Access Tokens  

Each finding includes:

- Severity level  
- Rule ID  
- File path + line number  
- Description  

---

## 📦 Installation (Development)

Clone the repository:

```bash
git clone https://github.com/chiakiichan/secureflow-scanner.git
cd secureflow-scanner
```

Create a virtual environment and install:

```bash
python -m venv venv
venv\Scripts\activate   # Windows
pip install -e .
```

## 🚀 Usage
Run the CLI:

```bash
secureflow scan .
```

Scan With Exclusions:
```bash
secureflow scan . --exclude venv --exclude .git
```

📌 Example Output

⚠️ Found 2 possible secrets:

[CRITICAL] AWS Access Key
 Rule: SF-SEC-001
 Location: testfile.py:1
 Description: Possible secret detected: AWS Access Key

------------------------------------------------------------

[CRITICAL] GitHub Token
 Rule: SF-SEC-002
 Location: testfile.py:2
 Description: Possible secret detected: GitHub Token


### ⚠️ Security Notice
Test secrets are included only for scanner development and demonstration.
Never commit real credentials into any repository.