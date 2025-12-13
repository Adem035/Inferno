"""
Report generator for Inferno.

This module provides report generation in multiple formats
including JSON, Markdown, and HTML.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from inferno.reporting.models import Finding, Report, ReportMetadata, Severity

if TYPE_CHECKING:
    from inferno.quality.candidate import FindingCandidate
    from inferno.quality.pipeline import QualityGatePipeline

logger = structlog.get_logger(__name__)


class ReportGenerator:
    """
    Generate security assessment reports in multiple formats.

    Supports JSON, Markdown, and HTML output formats.
    Optionally integrates with QualityGatePipeline for finding validation.
    """

    def __init__(
        self,
        output_dir: Path | None = None,
        quality_pipeline: QualityGatePipeline | None = None,
    ) -> None:
        """
        Initialize the report generator.

        Args:
            output_dir: Directory for report output.
            quality_pipeline: Optional quality gate pipeline for finding validation.
        """
        self._output_dir = output_dir or Path.cwd()
        self._quality_pipeline = quality_pipeline
        self._rejected_findings: list[tuple[str, str]] = []  # (title, reason) pairs

    def generate(
        self,
        report: Report,
        output_format: str = "markdown",
        output_path: Path | None = None,
    ) -> str:
        """
        Generate a report in the specified format.

        Args:
            report: Report data.
            output_format: Output format (json, markdown, html).
            output_path: Optional output file path.

        Returns:
            Generated report content.
        """
        if output_format == "json":
            content = self._generate_json(report)
        elif output_format == "html":
            content = self._generate_html(report)
        else:
            content = self._generate_markdown(report)

        # Save to file if path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
            logger.info("report_saved", path=str(output_path), format=output_format)

        return content

    def _generate_json(self, report: Report) -> str:
        """Generate JSON report."""
        return json.dumps(report.to_dict(), indent=2, default=str)

    def _generate_markdown(self, report: Report) -> str:
        """Generate Markdown report."""
        lines = []

        # Header
        lines.append("# Security Assessment Report")
        lines.append("")
        lines.append(f"**Target:** {report.metadata.target}")
        lines.append(f"**Operation ID:** {report.metadata.operation_id}")
        lines.append(f"**Date:** {report.metadata.started_at.strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"**Assessor:** {report.metadata.assessor}")
        lines.append("")

        # Risk Summary
        lines.append("## Risk Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Critical | {report.critical_count} |")
        lines.append(f"| High | {report.high_count} |")
        lines.append(f"| Medium | {report.medium_count} |")
        lines.append(f"| Low | {report.low_count} |")
        lines.append(f"| Info | {report.info_count} |")
        lines.append(f"| **Total** | **{report.total_findings}** |")
        lines.append("")
        lines.append(f"**Overall Risk Score:** {report.risk_score:.1f}/100")
        lines.append("")

        # Executive Summary
        if report.executive_summary:
            lines.append("## Executive Summary")
            lines.append("")
            lines.append(report.executive_summary)
            lines.append("")

        # Technical Summary
        if report.technical_summary:
            lines.append("## Technical Summary")
            lines.append("")
            lines.append(report.technical_summary)
            lines.append("")

        # Findings
        lines.append("## Findings")
        lines.append("")

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            findings = report.get_findings_by_severity(severity)
            if findings:
                lines.append(f"### {severity.value.upper()} Severity")
                lines.append("")

                for i, finding in enumerate(findings, 1):
                    lines.append(f"#### {i}. {finding.title}")
                    lines.append("")
                    lines.append(f"**Affected Asset:** {finding.affected_asset}")
                    lines.append("")
                    lines.append("**Description:**")
                    lines.append(finding.description)
                    lines.append("")
                    lines.append("**Evidence:**")
                    lines.append("```")
                    lines.append(finding.evidence)
                    lines.append("```")
                    lines.append("")

                    if finding.proof_of_concept:
                        lines.append("**Proof of Concept:**")
                        lines.append("```")
                        lines.append(finding.proof_of_concept)
                        lines.append("```")
                        lines.append("")

                    lines.append("**Remediation:**")
                    lines.append(finding.remediation)
                    lines.append("")

                    if finding.cvss_score:
                        lines.append(f"**CVSS Score:** {finding.cvss_score}")

                    if finding.cve_ids:
                        lines.append(f"**CVE IDs:** {', '.join(finding.cve_ids)}")

                    if finding.cwe_ids:
                        lines.append(f"**CWE IDs:** {', '.join(finding.cwe_ids)}")

                    if finding.references:
                        lines.append("**References:**")
                        for ref in finding.references:
                            lines.append(f"- {ref}")

                    lines.append("")
                    lines.append("---")
                    lines.append("")

        # Recommendations
        if report.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        # Assessment Details
        lines.append("## Assessment Details")
        lines.append("")
        lines.append(f"- **Scope:** {report.metadata.scope}")
        lines.append(f"- **Objective:** {report.metadata.objective}")
        lines.append(f"- **Duration:** {report.metadata.duration_seconds:.1f} seconds")
        lines.append(f"- **Methodology:** {report.metadata.methodology}")
        lines.append("")

        # Artifacts
        if report.artifacts:
            lines.append("## Artifacts")
            lines.append("")
            for artifact in report.artifacts:
                lines.append(f"- {artifact}")
            lines.append("")

        # Footer
        lines.append("---")
        lines.append(f"*Report generated by Inferno AI at {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}*")

        return "\n".join(lines)

    def _generate_html(self, report: Report) -> str:
        """Generate HTML report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {report.metadata.target}</title>
    <style>
        :root {{
            --critical: #FF0000;
            --high: #FF6600;
            --medium: #FFCC00;
            --low: #00CC00;
            --info: #0066FF;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{ color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }}
        h2 {{ color: #444; margin-top: 30px; }}
        h3 {{ color: #555; }}
        .meta {{ color: #666; margin-bottom: 20px; }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-card {{
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }}
        .summary-card.critical {{ background: var(--critical); }}
        .summary-card.high {{ background: var(--high); }}
        .summary-card.medium {{ background: var(--medium); color: #333; }}
        .summary-card.low {{ background: var(--low); color: #333; }}
        .summary-card.info {{ background: var(--info); }}
        .summary-card .count {{ font-size: 2em; font-weight: bold; }}
        .finding {{
            border-left: 4px solid;
            padding: 15px;
            margin: 15px 0;
            background: #fafafa;
            border-radius: 0 8px 8px 0;
        }}
        .finding.critical {{ border-color: var(--critical); }}
        .finding.high {{ border-color: var(--high); }}
        .finding.medium {{ border-color: var(--medium); }}
        .finding.low {{ border-color: var(--low); }}
        .finding.info {{ border-color: var(--info); }}
        .finding h4 {{ margin-top: 0; }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
        }}
        .badge.critical {{ background: var(--critical); }}
        .badge.high {{ background: var(--high); }}
        .badge.medium {{ background: var(--medium); color: #333; }}
        .badge.low {{ background: var(--low); color: #333; }}
        .badge.info {{ background: var(--info); }}
        pre {{
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }}
        code {{ font-family: 'Fira Code', 'Consolas', monospace; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f0f0f0; }}
        .risk-score {{
            font-size: 2em;
            font-weight: bold;
            padding: 20px;
            text-align: center;
            border-radius: 8px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Assessment Report</h1>
        <div class="meta">
            <strong>Target:</strong> {report.metadata.target}<br>
            <strong>Operation ID:</strong> {report.metadata.operation_id}<br>
            <strong>Date:</strong> {report.metadata.started_at.strftime('%Y-%m-%d %H:%M UTC')}<br>
            <strong>Assessor:</strong> {report.metadata.assessor}
        </div>

        <h2>Risk Summary</h2>
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="count">{report.critical_count}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{report.high_count}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{report.medium_count}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{report.low_count}</div>
                <div>Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{report.info_count}</div>
                <div>Info</div>
            </div>
        </div>

        <div class="risk-score">
            Overall Risk Score: {report.risk_score:.1f}/100
        </div>
"""

        if report.executive_summary:
            html += f"""
        <h2>Executive Summary</h2>
        <p>{report.executive_summary}</p>
"""

        if report.technical_summary:
            html += f"""
        <h2>Technical Summary</h2>
        <p>{report.technical_summary}</p>
"""

        html += """
        <h2>Findings</h2>
"""

        for finding in sorted(report.findings, key=lambda f: list(Severity).index(f.severity)):
            severity_class = finding.severity.value
            html += f"""
        <div class="finding {severity_class}">
            <h4><span class="badge {severity_class}">{finding.severity.value.upper()}</span> {finding.title}</h4>
            <p><strong>Affected Asset:</strong> {finding.affected_asset}</p>
            <p><strong>Description:</strong> {finding.description}</p>
            <p><strong>Evidence:</strong></p>
            <pre><code>{finding.evidence}</code></pre>
"""
            if finding.proof_of_concept:
                html += f"""
            <p><strong>Proof of Concept:</strong></p>
            <pre><code>{finding.proof_of_concept}</code></pre>
"""
            html += f"""
            <p><strong>Remediation:</strong> {finding.remediation}</p>
"""
            if finding.cvss_score:
                html += f"            <p><strong>CVSS Score:</strong> {finding.cvss_score}</p>\n"
            if finding.cve_ids:
                html += f"            <p><strong>CVE IDs:</strong> {', '.join(finding.cve_ids)}</p>\n"
            if finding.cwe_ids:
                html += f"            <p><strong>CWE IDs:</strong> {', '.join(finding.cwe_ids)}</p>\n"

            html += "        </div>\n"

        if report.recommendations:
            html += """
        <h2>Recommendations</h2>
        <ol>
"""
            for rec in report.recommendations:
                html += f"            <li>{rec}</li>\n"
            html += "        </ol>\n"

        html += f"""
        <h2>Assessment Details</h2>
        <table>
            <tr><th>Scope</th><td>{report.metadata.scope}</td></tr>
            <tr><th>Objective</th><td>{report.metadata.objective}</td></tr>
            <tr><th>Duration</th><td>{report.metadata.duration_seconds:.1f} seconds</td></tr>
            <tr><th>Methodology</th><td>{report.metadata.methodology}</td></tr>
        </table>

        <div class="footer">
            Report generated by Inferno AI at {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}
        </div>
    </div>
</body>
</html>
"""
        return html

    def create_report(
        self,
        operation_id: str,
        target: str,
        objective: str,
        scope: str = "as provided",
    ) -> Report:
        """
        Create a new report instance.

        Args:
            operation_id: Operation identifier.
            target: Target URL or IP.
            objective: Assessment objective.
            scope: Assessment scope.

        Returns:
            New Report instance.
        """
        metadata = ReportMetadata(
            operation_id=operation_id,
            target=target,
            objective=objective,
            scope=scope,
        )
        return Report(metadata=metadata)

    async def add_finding_candidate(
        self,
        candidate: FindingCandidate,
        target: str,
        report: Report,
    ) -> bool:
        """
        Process a finding candidate through quality gates and add to report if approved.

        This method validates a finding candidate through the quality gate pipeline
        (if configured). If the candidate passes all gates, it's added to the report.
        Rejected findings are tracked with their rejection reasons.

        Args:
            candidate: Finding candidate to validate and potentially add.
            target: Target URL/hostname for environment validation.
            report: Report instance to add the finding to if approved.

        Returns:
            True if the finding was approved and added to the report, False otherwise.
        """
        # If no quality pipeline configured, convert directly to finding
        if self._quality_pipeline is None:
            logger.debug(
                "no_quality_pipeline",
                title=candidate.title,
                message="Quality pipeline not configured, adding finding without validation",
            )
            # Create a basic Finding from candidate
            finding = Finding(
                title=candidate.title,
                description=candidate.description,
                severity=candidate.final_severity,
                affected_asset=candidate.affected_asset,
                evidence=candidate.evidence,
                remediation="",  # To be filled later
                proof_of_concept=candidate.exploitability_proof or None,
            )
            report.add_finding(finding)
            return True

        # Process through quality gates
        try:
            approved, finding = await self._quality_pipeline.process_candidate(
                candidate, target
            )

            if approved and finding:
                report.add_finding(finding)
                logger.info(
                    "finding_approved_and_added",
                    title=candidate.title,
                    quality_score=candidate.quality_score,
                    gates_passed=len(candidate.gates_passed),
                )
                return True
            else:
                # Track rejection
                rejection_reason = "; ".join(candidate.rejection_reasons)
                self._rejected_findings.append((candidate.title, rejection_reason))
                logger.warning(
                    "finding_rejected_by_quality_gates",
                    title=candidate.title,
                    rejection_reasons=candidate.rejection_reasons,
                    gates_failed=candidate.gates_failed,
                )
                return False

        except Exception as e:
            logger.error(
                "quality_gate_processing_error",
                title=candidate.title,
                error=str(e),
                exc_info=True,
            )
            # Track as rejected due to error
            self._rejected_findings.append(
                (candidate.title, f"Quality gate error: {e!s}")
            )
            return False

    def get_rejected_findings(self) -> list[tuple[str, str]]:
        """
        Get list of findings rejected by quality gates.

        Returns:
            List of (title, reason) tuples for rejected findings.
        """
        return self._rejected_findings.copy()

    def clear_rejected_findings(self) -> None:
        """Clear the list of rejected findings."""
        self._rejected_findings.clear()
