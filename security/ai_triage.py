import json
import os
import sys
from pathlib import Path
import httpx


def load_json(path: Path):
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def parse_gitleaks(report_dir: Path) -> list[dict]:
    data = load_json(report_dir / "gitleaks-report.json") or []
    return [
        {
            "scanner": "Gitleaks",
            "severity": "CRITICAL",
            "id": item.get("RuleID", "secret-detected"),
            "target": f"{item.get('File', 'unknown')}:{item.get('StartLine', 0)}",
            "fix": "Revoke credential immediately and move secret to GitHub Secrets / env vars.",
            "detail": item.get("Description", "Hardcoded secret detected"),
        }
        for item in data
    ]


def parse_semgrep(report_dir: Path) -> list[dict]:
    data = load_json(report_dir / "semgrep-report.json") or {}
    findings = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        findings.append(
            {
                "scanner": "Semgrep",
                "severity": extra.get("severity", "WARNING").upper(),
                "id": item.get("check_id", "sast-rule"),
                "target": f"{item.get('path', 'unknown')}:{item.get('start', {}).get('line', 0)}",
                "fix": extra.get("fix") or "Refactor code pattern according to SAST rule guidance.",
                "detail": extra.get("message", "Insecure code pattern detected"),
            }
        )
    return findings


def parse_trivy(report_dir: Path) -> list[dict]:
    data = load_json(report_dir / "trivy-report.json") or {}
    findings = []
    for result in data.get("Results", []):
        target = result.get("Target", "container-image")
        for v in result.get("Vulnerabilities", []):
            fixed = v.get("FixedVersion", "")
            pkg = f"{v.get('PkgName')}@{v.get('InstalledVersion')}"
            findings.append(
                {
                    "scanner": "Trivy",
                    "severity": v.get("Severity", "UNKNOWN").upper(),
                    "id": v.get("VulnerabilityID", "CVE-UNKNOWN"),
                    "target": f"{pkg} ({target})",
                    "fix": f"Upgrade {v.get('PkgName')} to >= {fixed}" if fixed else "No upstream patch available yet (monitor base image)",
                    "detail": v.get("Title", "Container package vulnerability"),
                    "has_fix": bool(fixed),
                }
            )
    return findings


def build_fallback_markdown(findings: list[dict]) -> str:
    if not findings:
        return "## DevSecOps Security Triage\n\nAll security gates passed with **0 actionable findings**."

    actionable = [f for f in findings if f.get("has_fix", True)]
    unfixed = [f for f in findings if not f.get("has_fix", True)]

    lines = [
        "## DevSecOps AI Security Triage Report",
        f"- **Total Findings:** {len(findings)} ({len(actionable)} actionable, {len(unfixed)} unpatched upstream)",
        "",
    ]

    if actionable:
        lines.append("### Priority Actionable Fixes")
        lines.append("| Scanner | Severity | ID | Target | Recommended Remediation |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in actionable[:20]:
            lines.append(
                f"| {f['scanner']} | **{f['severity']}** | `{f['id']}` | `{f['target']}` | {f['fix']} |"
            )
        lines.append("")

    if unfixed:
        lines.append(f"### Upstream / Unfixed Base OS Advisories ({len(unfixed)})")
        lines.append("These findings currently have no vendor patch (`FixedVersion` empty) and are tracked for future base-image rebuilds.")
        lines.append("")

    return "\n".join(lines)


def generate_ai_summary(findings: list[dict], api_key: str) -> str:
    if not findings:
        return "## DevSecOps AI Security Triage\n\nAll scanners reported **0 findings**. Safe to merge."

    compact = findings[:30]
    prompt = (
        "You are a senior DevSecOps security engineer reviewing CI scanner findings for a Python FastAPI Docker service. "
        "Analyze the JSON findings below and output a concise Markdown PR comment with:\n"
        "1. Risk Summary (distinguishing immediate fixable vulnerabilities from unpatched upstream OS packages)\n"
        "2. Step-by-Step Remediation Commands or Code Patches\n"
        "3. Merge Gate Recommendation (Block vs. Approve with tracking)\n\n"
        f"Findings JSON:\n{json.dumps(compact, indent=2)}"
    )

    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    headers = {"x-goog-api-key": api_key, "Content-Type": "application/json"}
    last_err = None

    for model in ("gemini-3.5-flash-lite", "gemini-3.8-flash"):
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        try:
            resp = httpx.post(url, headers=headers, json=payload, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as exc:
            last_err = exc

    fallback = build_fallback_markdown(findings)
    return f"{fallback}\n\n> *AI API fallback triggered ({last_err.__class__.__name__}); generated deterministic triage table.*"


def main():
    report_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("triage-summary.md")

    findings = (
        parse_gitleaks(report_dir)
        + parse_semgrep(report_dir)
        + parse_trivy(report_dir)
    )

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    summary = generate_ai_summary(findings, api_key) if api_key else build_fallback_markdown(findings)

    output_file.write_text(summary, encoding="utf-8")
    print(summary)


if __name__ == "__main__":
    main()
