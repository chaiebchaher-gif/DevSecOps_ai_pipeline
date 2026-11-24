# DevSecOps AI Security Pipeline

Automated DevSecOps CI/CD pipeline for a containerized **FastAPI** service, combining multi-layer security scanning with an **AI Security Triage Engine** powered by **Gemini**.

## Pipeline Architecture
1. **Unit & Integration Testing (`Pytest`):** Validates API endpoints and triage engine parsers.
2. **Secret Scanning (`Gitleaks`):** Blocks hardcoded API keys, tokens, and credentials across Git history.
3. **SAST Code Analysis (`Semgrep`):** Detects insecure Python and security-audit patterns before container build.
4. **Hardened Container Build (`Docker`):** Builds a slim Python image running under a dedicated non-root user (`appuser`).
5. **Container & Dependency Scanning (`Trivy`):** Scans OS packages and Python dependencies for fixable `CRITICAL` and `HIGH` CVEs (`--ignore-unfixed`).
6. **AI Security Triage (`security/ai_triage.py`):** Parses JSON reports from Gitleaks, Semgrep, and Trivy, prioritizes actionable fixes over unpatched upstream advisories, and posts remediation guidance directly on Pull Requests.

## Local Usage
```bash
# Run unit tests
.venv/bin/python -m pytest -v

# Run AI triage engine against scanner JSON reports
.venv/bin/python security/ai_triage.py reports/ triage-summary.md
```
