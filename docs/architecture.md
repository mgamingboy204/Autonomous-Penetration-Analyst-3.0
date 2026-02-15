# Architecture

- `orchestrator.py` enforces whitelist, mode gates, status/logging, and pipeline orchestration.
- `recon_engine/` runs safe recon tools and parses nmap XML.
- `ai_brain/` maps services to local CVE dataset and ranks candidates with RandomForest.
- `exploit_engine/` simulates by default and only runs benign validation in gated full-run.
- `post_exploit/` hashes and records evidence artifacts.
- `learning_db/` stores attempts and computes historical success rates.
- `reporting/` writes HTML report from template.
- `dashboard/` exposes run APIs and current status.
