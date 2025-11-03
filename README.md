# HERA — Human Engineered Risk Analysis  

## 1. Executive Summary
**HERA** is a lightweight, reproducible pipeline that quantifies **human-centric security risk** from user behavior and produces **OMEO-contextualized insights** and visuals the results that a threat modelling team can act on.

- **What it does:** Ingests activity signals → engineers features → scores risk (HTI) → maps behaviours to **OMEO** (Origin, Method, Exposure, Outcome) → generates charts and report.  
- **Why it matters:** Turns fragmented “people-risk” data into clear, explainable metrics and scenarios aligned to business impact.  
- **How it runs:** One command (`make all`) in a local, VS Code-friendly repo. Outputs are Markdown + PNGs viewable on GitHub or in a slide deck.

---

## 🎯 2. Goals & Success Criteria

**Goals**
- Quantify user-level human-risk with a transparent formula (**HTI**).  
- Summarize risk by department/role with **OMEO context** (explainability).  
- Deliver manager-readable **reports and visuals** with zero external dependencies.

**Success Criteria**
- Pipeline runs end-to-end and produces:  
  - `outputs/risk_scores.csv`,  
  - `outputs/risk_scores_mapped.csv`,  
  - charts in `outputs/charts/`,  
  - and `docs/report.md`.  
- Report highlights top risky users, departments, and prevalent OMEO methods.  
- Steps are reproducible on a clean workstation with the provided Makefile.

---

## 🔍 3. Scope & Assumptions

**In Scope**
- Synthetic dataset for 100 users.  
- Feature engineering from access logs, phishing simulations, and policy violations.  
- Risk scoring (**HTI**) and OMEO mapping logic.  
- Baseline visuals and a manager report.

**Out of Scope**
- Real-time ingestion, SIEM connectors, identity governance hooks.  
- Automated remediation or SOAR playbooks.  
- Formal validation on production telemetry.

**Assumptions**
- Python 3.11+ environment and **VS Code** used for development.  
- Runs locally; no external network dependencies.  
- OMEO is the sole framework name used.

---
## 🏗️ 4. High-Level Architecture

+--------------------+ +--------------------+ +--------------------+
| Data Sources | ----> | Feature Engineering| ----> | Risk Scoring |
| (synthetic CSVs) | | (Phase 3) | | (Phase 4 HTI) |
+--------------------+ +--------------------+ +--------------------+
| | |
v v v
data/.csv outputs/user_features.csv outputs/risk_scores.csv
|
v
+------------------------+
| OMEO Mapping (Phase 4)|
+------------------------+
|
v
outputs/risk_scores_mapped.csv
|
+--------------------------+-------------------------+
| |
v v
+----------------------------+ +----------------------------+
| Visuals (Phase 6) | | Report Builder (Phase 8) |
+----------------------------+ +----------------------------+
outputs/charts/.png docs/report.md

---

## 📊 5. Data Model (Synthetic)

| File | Purpose | Key Fields |
|------|----------|------------|
| `data/user_directory.csv` | User roster | `user_id`, `department`, `role`, `privilege_level`, `critical_asset_access` |
| `data/access_logs.csv` | Access activity logs | `user_id`, `action`, `data_gb`, `after_hours`, `anomalous_geo` |
| `data/phishing_simulation.csv` | Phishing simulation results | `user_id`, `opened`, `clicked`, `reported`, `creds_submitted` |
| `data/policy_violations.csv` | Policy incidents | `user_id`, `violation_type`, `severity`, `repeat_count` |

> Synthetic generation is deterministic with a fixed random seed for reproducibility.

---

## 🔢 6. Risk Methodology

### 6.1 Human Threat Index (HTI)

**Components**
- **Likelihood:** click rate, after-hours rate, anomalous geo, credential submission.  
- **Impact:** critical asset access, elevated/admin privilege.  
- **Detectability:** inverse of reporting and violation signals.

**Formula (scaled 0–100):**
HTI = 100 × Likelihood × max(Impact, 0.1) × (1 − 0.5 × Detectability)


**Risk Bands**
| Band | Range |
|------|--------|
| Very Low | 0–20 |
| Low | 21–40 |
| Medium | 41–60 |
| High | 61–80 |
| Critical | 81–100 |

---

### 6.2 OMEO Mapping (Explainability)

| Field | Description | Example |
|--------|--------------|----------|
| **Origin** | Who caused the behavior | Employee, Contractor |
| **Method** | Attack or action vector | Social Engineering, Data Exfiltration |
| **Exposure** | Asset at risk | HR Data, Source Code, Finance Records |
| **Outcome** | Impact on business | Data Breach, Brand Impact |

---

## 📦 7. Deliverables

| Type | File | Description |
|------|------|-------------|
| **Data Tables** | `outputs/user_features.csv` | Engineered features |
|  | `outputs/risk_scores.csv` | Risk scores + HTI |
|  | `outputs/risk_scores_mapped.csv` | Scores with OMEO mapping |
| **Visuals** | `outputs/charts/*.png` | Charts and graphs |
| **Reports** | `docs/report.md` | Risk summary with charts |
|  | `docs/data_preview.md` | Quick view of key data tables |

---

## ⚙️ 8. Step-by-Step Runbook

### Environment Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

