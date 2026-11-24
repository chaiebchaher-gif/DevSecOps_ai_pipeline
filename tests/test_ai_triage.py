import json
from security.ai_triage import (
    build_fallback_markdown,
    parse_gitleaks,
    parse_semgrep,
    parse_trivy,
)


def test_parse_scanner_reports_and_triage_output(tmp_path):
    (tmp_path / "gitleaks-report.json").write_text(
        json.dumps([{"RuleID": "generic-api-key", "File": "app/config.py", "StartLine": 12, "Description": "Hardcoded key"}]),
        encoding="utf-8",
    )
    (tmp_path / "semgrep-report.json").write_text(
        json.dumps({
            "results": [
                {
                    "check_id": "python.lang.security.audit.eval-detected",
                    "path": "app/main.py",
                    "start": {"line": 25},
                    "extra": {"severity": "ERROR", "message": "Avoid eval()", "fix": "Use ast.literal_eval"},
                }
            ]
        }),
        encoding="utf-8",
    )
    (tmp_path / "trivy-report.json").write_text(
        json.dumps({
            "Results": [
                {
                    "Target": "Python",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-54283",
                            "PkgName": "starlette",
                            "InstalledVersion": "0.38.6",
                            "FixedVersion": "1.3.1",
                            "Severity": "HIGH",
                            "Title": "Starlette vulnerability",
                        },
                        {
                            "VulnerabilityID": "CVE-2026-99999",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.5.9",
                            "Severity": "HIGH",
                            "Title": "Unpatched OS advisory",
                        },
                    ],
                }
            ]
        }),
        encoding="utf-8",
    )

    findings = parse_gitleaks(tmp_path) + parse_semgrep(tmp_path) + parse_trivy(tmp_path)
    report = build_fallback_markdown(findings)

    assert len(findings) == 4
    assert "3 actionable, 1 unpatched upstream" in report
    assert "generic-api-key" in report
    assert "python.lang.security.audit.eval-detected" in report
    assert "Upgrade starlette to >= 1.3.1" in report


def test_clean_pipeline_triage_message():
    report = build_fallback_markdown([])
    assert "0 actionable findings" in report
