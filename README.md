# 🔒 SecureFlow-Scanner

**CI/CD Pipeline Security Scanner to Detect Secrets, Vulnerabilities, and Misconfigurations**

SecureFlow-Scanner is a Python-based DevSecOps security tool being built step-by-step to help developers detect:

- Hardcoded secrets
- Vulnerable dependencies
- Unsafe Docker configurations
- Infrastructure-as-Code misconfigurations

This project is under active development.

---

## 🚀 Current Status

✅ CLI framework working  
✅ Core Finding model implemented  
🔜 Secrets scanner coming next  
🔜 JSON + SARIF reporting planned  

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

Run the CLI:

```bash
secureflow scan .
```