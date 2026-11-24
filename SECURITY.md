# Security Policy & Pipeline Threat Model

## Architecture Overview
This repository implements an automated DevSecOps pipeline for a containerized FastAPI service, backed by a Python AI Triage Engine that parses JSON scanner reports and posts plain-English remediation guidance on Pull Requests.

## Threat Model & Enforcement Gates
| Threat Vector | Automated Control | Enforcement Gate |
| :--- | :--- | :--- |
| Hardcoded API keys, tokens, and credentials | **Gitleaks** (Secret Scanning) | Fail pipeline on any detected secret |
| Injection, insecure code patterns, misconfigurations | **Semgrep** (SAST) | Fail pipeline on High / `ERROR` findings |
| Vulnerable OS packages & Python libraries in image | **Trivy** (Container & SCA Scan) | Fail pipeline on `CRITICAL` / `HIGH` CVEs |
| Container root privilege escalation | Non-root `appuser` in `Dockerfile` | Enforced in container image definition |

## Reporting a Vulnerability
Please report suspected vulnerabilities privately to the repository maintainer before public disclosure.
