"""SARIF v2.1.0 Exporter for GitHub Advanced Security & Pull Request Code Scanning.

Allows `mcpguard scan --emit-sarif reports/mcpguard.sarif.json` to upload findings
directly into GitHub's Security tab via `github/codeql-action/upload-sarif@v3`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcpguard_adk.schemas import AuditReport, FindingSeverity

SARIF_LEVEL_MAP = {
    FindingSeverity.CRITICAL: "error",
    FindingSeverity.HIGH: "error",
    FindingSeverity.MEDIUM: "warning",
    FindingSeverity.LOW: "note",
    FindingSeverity.INFO: "note",
}


def build_sarif_report(report: AuditReport) -> dict[str, Any]:
    """Convert an `AuditReport` into a standard SARIF v2.1.0 JSON structure."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    base_path = Path(report.target_path).resolve()

    for finding in report.findings:
        if finding.rule_id not in rules_by_id:
            rules_by_id[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.category.value,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "help": {"text": finding.remediation},
                "defaultConfiguration": {
                    "level": SARIF_LEVEL_MAP.get(finding.severity, "warning")
                },
            }

        try:
            rel_uri = str(Path(finding.file_path).resolve().relative_to(base_path)).replace("\\", "/")
        except Exception:
            rel_uri = Path(finding.file_path).name

        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
                "message": {"text": f"{finding.title} — Fix: {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": rel_uri},
                            "region": {"startLine": max(1, finding.line_number)},
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPGuard-ADK",
                        "version": "0.2.0",
                        "informationUri": "https://github.com/example/mcpguard-adk",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
