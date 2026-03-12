# 🛡️ Python Host-Based Intrusion Detection System (HIDS)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](#)

A professional, lightweight, and modular **Host-Based Intrusion Detection System (HIDS)** designed to monitor critical system files and processes for unauthorized modifications or suspicious activity.

---

## 🚀 Features

- **🔍 File Integrity Monitoring (FIM)**: 
  - Real-time SHA-256 baseline hashing.
  - Monitors modifications, creations, and deletions in critical directories.
  - Default coverage: `C:\Windows\System32` (Windows) and `/etc` (Linux).
- **📉 Process Monitoring**:
  - Detects high CPU usage (customizable threshold).
  - Flags suspicious external network connections.
- **📜 Structured Logging**:
  - Saves security events in `security_log.txt` and `security_log.json`.
- **🚨 Real-Time Alert System**:
  - High-visibility colored terminal output for critical security events.
- **🛡️ Cross-Platform**: Fully compatible with both Windows and Linux.

---

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/HIDS.git
   cd HIDS
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 📖 Usage

### 1. Initialize Baseline
Generate a trusted baseline of hashes for the monitored files. Run this before starting the monitor.
```bash
python hids.py --init
```

### 2. Start Monitoring
Launch the real-time protection engine.
```bash
python hids.py --monitor
```

### 3. Custom Directories & Thresholds
Monitor specific folders or adjust the CPU alert threshold:
```bash
python hids.py --monitor --dirs ./my_docs ./conf --cpu-threshold 75.0
```

---

## 📂 Project Structure

```text
HIDS/
├── core/
│   ├── __init__.py
│   ├── config.py       # OS-specific defaults & settings
│   ├── fim.py          # File Integrity Monitoring engine
│   ├── logger.py       # Structured logging & alerts
│   ├── monitor_fs.py   # Real-time filesystem observer
│   └── monitor_proc.py # Process activity scanner
├── db/                 # Baseline hash database
├── logs/               # Security logs (TXT & JSON)
├── hids.py             # Main entry point (CLI)
├── requirements.txt    # Python dependencies
└── LICENSE             # GPLv3 License
```

---

## ⚖️ License

Distributed under the **GNU GPLv3** License. See `LICENSE` for more information.

---

## 👨‍💻 Developed By

**Computer Techinical Engineer & Senior Developer**

---
*Disclaimer: This tool is intended for defensive security monitoring. Ensure you have the necessary permissions to monitor system files on your target machine.*
