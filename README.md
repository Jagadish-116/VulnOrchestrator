# VulnOrchestrator 🛡️

[![Python Version](https://img.shields.io/badge/python-3.12%2B-gold)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask-teal)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Security](https://img.shields.io/badge/VAPT-Pipeline-red)]()

**VulnOrchestrator** is a lightweight, high-concurrency VAPT (Vulnerability Assessment and Penetration Testing) automation framework. It bridges the gap between low-level infrastructure scanning and web application security auditing by chaining tools together into a unified data engineering pipeline. 

The framework programmatically controls external binaries, uses custom regular expressions to normalize unstructured scan logs into structured JSON metadata, executes a fast, multi-threaded directory path fuzzer, and displays live metrics inside an executive-ready, glassmorphic dark web dashboard.

---

## 🌟 Key Features

* **Zero-Touch Tool Chaining:** Runs network reconnaissance and dynamically extracts open web targets to feed downstream testing modules without any manual copy-pasting.
* **Native High-Concurrency Fuzzer:** Uses an internal, multi-threaded path fuzzer engineered with Python's `ThreadPoolExecutor` to handle concurrent network requests rapidly and bypass legacy package dependency bugs.
* **Deterministic Process Control:** Manages external system lifecycles safely on Windows using decoupled `subprocess.Popen` streams and rigid timeout safety gates to prevent application hangs and memory leaks.
* **Context-Aware Threat Matrix:** Automatically analyzes and tags discovered web assets by severity (High, Medium, Low) based on payload size parameters and specific URL string rules.
* **Ultra-Luxury Analytical UI:** Features a modern glassmorphic web dashboard powered by a local Flask micro-server that dynamically aggregates workspace findings on page refresh.

---

## 📐 System Architecture & Data Flow

VulnOrchestrator rejects broken monolithic security software structures in favor of a highly modular, decoupled pipeline model:

    [ Input Target Hostname / IP ]
                  │
                  ▼
        +───────────────────+
        |  core/scanner.py  | <── Asynchronously forks Windows Popen Nmap process
        +───────────────────+
                  │
                  ▼ Writes raw logs to disk
         ( nmap_result.gnmap )
                  │
                  ▼
        +───────────────────+
        |   core/parser.py  | <── Extracts active web protocols and open ports via RegEx
        +───────────────────+
                  │
                  ▼ Normalizes fully-qualified URLs
        +───────────────────+
        |   core/brute.py   | <── Boots ThreadPoolExecutor (10 Parallel Workers)
        +───────────────────+
                  │
                  ▼ Serializes vulnerabilities to structured JSON
       ( dirsearch_[target].json )
                  │
                  ▼
        +───────────────────+
        |      app.py       | <── Flask micro-server reads JSON payload on-demand
        +───────────────────+
                  │
                  ▼ Renders interface variables via Jinja2
        +───────────────────+
        |    report.html    | <── Visualizes glassmorphic UI dashboard in browser
        +───────────────────+

---

## 📂 Repository Structure

```
VulnOrchestrator/
│
├── core/
│   ├── __init__.py
│   ├── brute.py         # Multi-threaded Custom Directory Fuzzer Engine
│   ├── parser.py        # Log Extraction & Threat Classification Filter
│   └── scanner.py       # Asynchronous Operating System Process Controller
│
├── templates/
│   └── report.html      # Responsive Glassmorphic Dashboard UI Template
│
├── outputs/             # Volatile Local Workspace Directory for Scan Analytics
├── app.py               # Flask Micro-Server Web Router Entry-Point
└── test_run.py          # Backend VAPT Pipeline Automation Controller
```

## 🚀 Getting Started
### Prerequisites
Python 3.12+ installed on the host operating system.

<br> Nmap installed and correctly registered in your system's Environment PATH variables.

## Installation & Setup

1. Clone the Repository:
```
git clone [https://github.com/Jagadish-116/VulnOrchestrator.git]( https://github.com/Jagadish-116/VulnOrchestrator.git)
```

<br> `cd VulnOrchestrator`

3. Install Required Python Dependencies:
`pip install requests flask`

4. Verify Directory Structure: Ensure an empty outputs/ folder is present in the root directory to store workspace session files.

### 💻 Usage Guide
1. Execute the VAPT Automation Suite
Open your main automation script `(test_run.py)` and set your target configuration parameter to a domain or network IP you have authorized permission to audit:
target = "testphp.vulnweb.com"
<br> Fire up your administrator shell and execute the automated backend orchestration pipeline:
`python test_run.py`

2. Boot the Dashboard User Interface
Launch the local web visualization server to monitor and track your asset infrastructure intelligence:

`python app.py`

<br> Open your favorite web browser and navigate to the local loopback server URL:

`[http://127.0.0.1:5000]`(http://127.0.0.1:5000)

### 📊 Technical Performance Specifications

```
Architectural Metric                   Engine Core Implementation Details
Concurrency Pattern                    Native concurrent.futures.ThreadPoolExecutor worker nodes
Thread Pool Allocation                 10 Parallel Worker Threads (Dynamically scalable)
Timeout Safety Gates                   Absolute 5-second connection read timeout per individual request path
I/O Bound Protection                   Global Interpreter Lock (GIL) yielding on asynchronous socket waits
Process Bridge Mode                    Kernel-level stream communication via explicit subprocess.Popen
```

### 🔮 Strategic Future Roadmap

CI/CD Build Pipeline Gates: Integrate specific termination codes (Exit Code 1 on High Severity leaks) to allow developers to drop bad compilation updates automatically inside GitHub Actions pipelines.

 Template-Driven Auditing: Transition the static fuzzer list into a dynamic template processor that reads YAML-formatted vulnerability definitions to flag complex CVE patterns.

 Static Analysis Integration: Add lightweight SAST (Static Application Security Testing) tools into the workflow loop to audit code files alongside active network infrastructure audits.

##📜 License
Distributed under the MIT License. See LICENSE for more information.

🤝 Contributing
Contributions are welcome! Please fork this repository, open a descriptive feature branch, make your commits, and submit a clean Pull Request. For major structural changes, please open an issue first to discuss what you would like to modify.

