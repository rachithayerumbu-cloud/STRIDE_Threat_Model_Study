# STRIDE Threat Model study

A beginner-friendly web application that helps users identify, analyse, and mitigate security threats using the **STRIDE** threat modelling methodology. Built with Python Flask, HTML, CSS, and JavaScript — no paid APIs, no databases, no machine-learning models required.

---

## Problem Statement

Software systems are routinely deployed without a structured security review because threat modelling is perceived as complex and requires specialist knowledge. This tool makes the STRIDE methodology accessible to students, junior developers, and educators by providing an interactive, guided threat analysis experience.

---

## Objectives

1. Educate users on the six STRIDE threat categories with concrete examples.
2. Allow users to describe a system (components, data flows, trust boundaries) and receive a structured threat analysis.
3. Provide risk ratings (Low / Medium / High) for each identified threat using a transparent 3×3 risk matrix.
4. Recommend practical security controls for every threat.
5. Generate downloadable reports (TXT and CSV) for documentation and academic submission.

---

## Features

| Feature | Description |
|---|---|
| **Dashboard** | Overview of STRIDE categories, quick-start buttons, and current assessment summary. |
| **New Assessment** | Form to describe a system; rule-based STRIDE engine analyses threats automatically. |
| **Load Sample** | Pre-built online-shopping system ready for immediate demonstration. |
| **Threat Cards** | Each threat shows ID, category, affected components, description, likelihood, impact, risk level, mitigation, and security control. |
| **Category Filter** | Filter the threat list by any STRIDE category with one click. |
| **Threat Diagram** | Canvas-rendered system architecture diagram showing components, data flows, and trust boundaries. |
| **Full Report** | Tabular view of all threats with a category bar chart and security recommendations. |
| **Download TXT** | Plain-text threat model report. |
| **Download CSV** | Spreadsheet-compatible threat export. |
| **About Page** | Explains STRIDE, the risk matrix, the technology stack, and limitations. |

---

## Technology Stack

- **Backend:** Python 3.10+ with Flask 3
- **Frontend:** HTML5, CSS3, Vanilla JavaScript (ES5 compatible)
- **Diagram:** HTML5 Canvas API (no external chart libraries)
- **Data:** JSON file (`data/sample_system.json`) + Python in-memory structures
- **Testing:** pytest

---

## Project Folder Structure

```
stride-threat-analyzer/
│
├── app.py                      # Flask application — all routes
├── requirements.txt            # Python dependencies (Flask only)
├── README.md                   # This file
│
├── data/
│   └── sample_system.json      # Built-in sample: Online Shopping App
│
├── modules/
│   ├── __init__.py
│   ├── stride_engine.py        # Rule-based STRIDE threat knowledge base
│   ├── risk_calculator.py      # 3×3 risk matrix + summary builder
│   └── report_generator.py     # TXT and CSV report generators
│
├── templates/
│   ├── base.html               # Base layout (navbar, footer, flash messages)
│   ├── index.html              # Dashboard
│   ├── assessment.html         # New assessment form + results
│   ├── diagram.html            # System architecture diagram
│   ├── report.html             # Full threat report view
│   ├── about.html              # About / methodology page
│   ├── 404.html                # 404 error page
│   └── 500.html                # 500 error page
│
├── static/
│   ├── css/
│   │   └── style.css           # Dark cybersecurity dashboard theme
│   └── js/
│       ├── main.js             # Navigation toggle, flash messages, STRIDE card toggle
│       └── diagram.js          # Canvas diagram renderer
│
└── tests/
    └── test_stride.py          # 25 pytest test cases
```

---

## Installation Instructions (Windows)

### Prerequisites

- Python 3.10 or newer — download from https://www.python.org/downloads/
- During installation, check **"Add Python to PATH"**

### Step 1 — Open a terminal

Press `Win + R`, type `cmd`, press Enter.  
Navigate to the folder where you want to place the project:

```cmd
cd C:\Users\YourName\Documents
```

### Step 2 — Create a virtual environment

```cmd
cd stride-threat-analyzer
python -m venv venv
```

### Step 3 — Activate the virtual environment

```cmd
venv\Scripts\activate
```

Your prompt will change to `(venv) C:\...>`

### Step 4 — Install dependencies

```cmd
pip install -r requirements.txt
```

---

## Running the Application

```cmd
python app.py
```

You should see:

```
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

Open your browser and go to **http://127.0.0.1:5000**

To stop the server: press `Ctrl + C` in the terminal.

---

## Running the Tests

Make sure the virtual environment is activated, then:

```cmd
python -m pytest tests/ -v
```

Expected output (all 25 tests should pass):

```
tests/test_stride.py::TestAssessmentCreation::test_analyse_sample_system_returns_threats PASSED
tests/test_stride.py::TestAssessmentCreation::test_analyse_minimal_system PASSED
tests/test_stride.py::TestAssessmentCreation::test_analyse_empty_components PASSED
...
25 passed in X.XXs
```

---

## How to Use

### Option A — Load the Sample System (fastest for demonstration)

1. Click **"Load Sample System"** on the Dashboard or Assessment page.
2. The tool will automatically run STRIDE analysis on a pre-built Online Shopping Application.
3. Browse the threat cards, filter by category, view the diagram, and download the report.

### Option B — Enter Your Own System

1. Click **"New Assessment"** in the navigation bar.
2. Fill in the system name and description.
3. Add components (e.g. Web Server, Database, Mobile App).
4. Optionally add data flows and trust boundaries.
5. Click **"Analyse Threats"**.
6. Review the results and download reports as needed.

---

## Sample Output

**System:** Online Shopping Application  
**Total Threats Identified:** 17  
**High Risk:** 10 | **Medium Risk:** 5 | **Low Risk:** 2

| ID | Threat | Category | Risk |
|---|---|---|---|
| S1 | User Identity Spoofing | Spoofing | High |
| T1 | SQL Injection | Tampering | High |
| I1 | Sensitive Data Exposure in DB | Information Disclosure | High |
| E1 | Broken Access Control | Elevation of Privilege | High |
| D1 | HTTP Flood / DDoS | Denial of Service | High |
| R1 | Insufficient Audit Logging | Repudiation | Medium |
| ... | ... | ... | ... |

---

## API Endpoint (JSON)

The application also exposes a REST endpoint for programmatic access:

```
POST /api/analyse
Content-Type: application/json

{
  "system": {
    "name": "My App",
    "description": "...",
    "components": [ {"id": "u1", "name": "User", "type": "user", "description": ""} ],
    "data_flows": [],
    "trust_boundaries": []
  }
}
```

Response:

```json
{
  "threats": [ { "id": "S1", "category": "Spoofing", ... } ],
  "summary": { "total_threats": 3, "risk_counts": { "High": 1, "Medium": 1, "Low": 1 }, ... }
}
```

---

## STRIDE Methodology Implementation

The threat engine (`modules/stride_engine.py`) contains a **knowledge base of 17 threat rules**. Each rule specifies:

- The STRIDE category (S / T / R / I / D / E)
- Which component types trigger the rule (e.g. `["web_application", "database"]`)
- A realistic attack description
- Pre-assigned likelihood and impact ratings
- A recommended mitigation and security control

When a user submits a system, the engine:

1. Extracts the component types present in the system.
2. Iterates through every rule and checks whether the rule's target component types overlap with the system's component types.
3. For every match, generates a threat entry enriched with the affected component names.
4. The risk calculator then applies a 3×3 risk matrix (Likelihood × Impact → Risk Level).

This approach is **fully transparent** — every decision is traceable to a specific rule and no black-box model is involved.

---

## Limitations

- The rule set is finite; not every possible threat for every architecture is covered.
- Threat ratings (likelihood, impact) are fixed per rule, not dynamically adapted to the specific system context.
- The tool does not perform real vulnerability scanning or connect to external services.
- Not a replacement for a professional security assessment or penetration test.

---

## Future Enhancements

- User-editable threat likelihood and impact to override rule defaults.
- Persistent storage using SQLite so assessments can be saved and retrieved.
- CVSS score integration for standardised severity ratings.
- Export to PDF using WeasyPrint or ReportLab.
- MITRE ATT&CK technique mapping for each threat.
- Import/export of system definitions in OWASP Threat Dragon JSON format.

---

## References

- Microsoft STRIDE Threat Modelling: https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
- OWASP Threat Dragon: https://owasp.org/www-project-threat-dragon/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- NIST SP 800-30 Risk Management: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
