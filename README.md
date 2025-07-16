# 🔐 AutoForge Security Orchestration

AutoForge is a modular security orchestration engine inspired by tools like **Checkov**, built to scan and enforce compliance across infrastructure-as-code environments. While its current implementation targets **Terraform**, AutoForge is evolving into a broader platform capable of supporting multi-cloud IAC formats with dynamic orchestration.

---

## 🧩 Project Overview

AutoForge doesn’t just scan — it orchestrates.

- ✅ **Pre-Scan Setup:** Choose folders, rule profiles, and enforcement policies before analysis.
- 📊 **Live Dashboard:** Launch scans and monitor violation results in real time.
- 🗂️ **Profile Manager:** Customize severity levels, override exclusions, and apply environment tags (e.g. dev/staging/prod).
- 🧠 **Security Graph Engine (in progress):** Visualize trust paths and IAM relationships as annotated graphs to understand risk with clarity.

AutoForge places orchestration, modularity, and visibility at the heart of cloud compliance — bridging human-readable policy with visual intelligence.

---

## ⚙️ Tech Stack

- Python 3.11
- FastAPI
- Jinja2 Templates
- YAML Rule Engine
- Matplotlib (Graph Visualization)

---

## 🚀 Running Locally (Port 8001)

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8001