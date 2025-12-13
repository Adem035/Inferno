"""
NVD (National Vulnerability Database) lookup tool for Inferno.

This module provides CVE lookup capabilities using the NVD API v2.0.
"""

from __future__ import annotations

import re

import httpx
import structlog

from inferno.tools.base import ToolResult

logger = structlog.get_logger(__name__)

# NVD API v2.0 endpoint
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Common software name mappings for better CPE matching
SOFTWARE_MAPPINGS = {
    "nginx": "nginx:nginx",
    "apache": "apache:http_server",
    "httpd": "apache:http_server",
    "mysql": "mysql:mysql",
    "mariadb": "mariadb:mariadb",
    "postgresql": "postgresql:postgresql",
    "postgres": "postgresql:postgresql",
    "redis": "redis:redis",
    "mongodb": "mongodb:mongodb",
    "wordpress": "wordpress:wordpress",
    "drupal": "drupal:drupal",
    "joomla": "joomla:joomla",
    "php": "php:php",
    "python": "python:python",
    "node": "nodejs:node.js",
    "nodejs": "nodejs:node.js",
    "express": "expressjs:express",
    "django": "djangoproject:django",
    "flask": "palletsprojects:flask",
    "rails": "rubyonrails:rails",
    "ruby": "ruby-lang:ruby",
    "java": "oracle:java",
    "tomcat": "apache:tomcat",
    "jenkins": "jenkins:jenkins",
    "gitlab": "gitlab:gitlab",
    "openssh": "openbsd:openssh",
    "openssl": "openssl:openssl",
    "docker": "docker:docker",
    "kubernetes": "kubernetes:kubernetes",
    "k8s": "kubernetes:kubernetes",
    "grafana": "grafana:grafana",
    "elastic": "elastic:elasticsearch",
    "elasticsearch": "elastic:elasticsearch",
    "kibana": "elastic:kibana",
    "logstash": "elastic:logstash",
    "spring": "vmware:spring_framework",
    "springboot": "vmware:spring_boot",
    "struts": "apache:struts",
    "log4j": "apache:log4j",
    "iis": "microsoft:internet_information_services",
    "exchange": "microsoft:exchange_server",
    "sharepoint": "microsoft:sharepoint",
    "windows": "microsoft:windows",
    "linux": "linux:linux_kernel",
    "ubuntu": "canonical:ubuntu_linux",
    "debian": "debian:debian_linux",
    "centos": "centos:centos",
    "redhat": "redhat:enterprise_linux",
    "vscode": "microsoft:visual_studio_code",
    "jira": "atlassian:jira",
    "confluence": "atlassian:confluence",
    "bitbucket": "atlassian:bitbucket",
    "sonarqube": "sonarsource:sonarqube",
    "nexus": "sonatype:nexus",
    "artifactory": "jfrog:artifactory",
    "vault": "hashicorp:vault",
    "consul": "hashicorp:consul",
    "terraform": "hashicorp:terraform",
    "ansible": "redhat:ansible",
    "puppet": "puppet:puppet",
    "chef": "chef:chef",
    "nagios": "nagios:nagios",
    "zabbix": "zabbix:zabbix",
    "prometheus": "prometheus:prometheus",
    "splunk": "splunk:splunk",
    "suricata": "oisf:suricata",
    "snort": "cisco:snort",
}


class NVDTool:
    """
    NVD vulnerability lookup tool.

    Queries the National Vulnerability Database for CVEs matching
    a given software and version.
    """

    def __init__(self, api_key: str | None = None, timeout: float = 30.0) -> None:
        """
        Initialize NVD tool.

        Args:
            api_key: Optional NVD API key for higher rate limits.
            timeout: Request timeout in seconds.
        """
        self._api_key = api_key
        self._timeout = timeout
        self._cache: dict[str, dict] = {}  # Simple cache for repeated lookups

    def _parse_version_string(self, version_string: str) -> tuple[str | None, str | None]:
        """
        Parse a version string like 'nginx/1.18.0' into (software, version).

        Args:
            version_string: Raw version string from banner/header.

        Returns:
            Tuple of (software_name, version) or (None, None) if unparseable.
        """
        if not version_string:
            return None, None

        # Common patterns
        patterns = [
            # nginx/1.18.0
            r'^([a-zA-Z][a-zA-Z0-9_-]*)/(\d+[\d.]+)',
            # Apache/2.4.41 (Ubuntu)
            r'^([a-zA-Z][a-zA-Z0-9_-]*)/(\d+[\d.]+)',
            # PHP/7.4.3
            r'^([a-zA-Z]+)/(\d+[\d.]+)',
            # Express 4.17.1
            r'^([a-zA-Z][a-zA-Z0-9_-]*)\s+(\d+[\d.]+)',
            # WordPress 6.4.1
            r'^([a-zA-Z][a-zA-Z0-9_-]*)\s+(\d+[\d.]+)',
            # OpenSSH_8.2p1
            r'^([a-zA-Z]+)_(\d+[\d.p]+)',
            # Microsoft-IIS/10.0
            r'^([a-zA-Z][a-zA-Z0-9_-]*)/(\d+[\d.]+)',
        ]

        for pattern in patterns:
            match = re.match(pattern, version_string, re.IGNORECASE)
            if match:
                software = match.group(1).lower()
                version = match.group(2)
                return software, version

        return None, None

    def _get_cpe_vendor_product(self, software: str) -> str:
        """
        Get CPE vendor:product string for a software name.

        Args:
            software: Software name.

        Returns:
            CPE vendor:product string.
        """
        software_lower = software.lower().strip()

        if software_lower in SOFTWARE_MAPPINGS:
            return SOFTWARE_MAPPINGS[software_lower]

        # Default: use software name as both vendor and product
        return f"{software_lower}:{software_lower}"

    async def execute(
        self,
        software: str | None = None,
        version: str | None = None,
        auto_detect: str | None = None,
        max_results: int = 10,
    ) -> ToolResult:
        """
        Query NVD for CVEs.

        Args:
            software: Software name (e.g., "nginx", "wordpress").
            version: Version string (e.g., "1.18.0").
            auto_detect: Raw version string to auto-parse (e.g., "nginx/1.18.0").
            max_results: Maximum number of CVEs to return.

        Returns:
            ToolResult with CVE information.
        """
        # Auto-detect from version string if provided
        if auto_detect:
            detected_software, detected_version = self._parse_version_string(auto_detect)
            if detected_software:
                software = software or detected_software
                version = version or detected_version

        if not software:
            return ToolResult(
                success=False,
                output="",
                error="Software name is required. Provide 'software' or 'auto_detect'.",
            )

        # Build cache key
        cache_key = f"{software}:{version or 'any'}"
        if cache_key in self._cache:
            logger.debug("nvd_cache_hit", cache_key=cache_key)
            return self._cache[cache_key]

        # Get CPE string
        cpe_vendor_product = self._get_cpe_vendor_product(software)
        vendor, product = cpe_vendor_product.split(":")

        # Build CPE match string
        # Format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
        if version:
            cpe_match = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        else:
            cpe_match = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"

        logger.info("nvd_lookup", software=software, version=version, cpe=cpe_match)

        try:
            # Query NVD API
            params = {
                "cpeName": cpe_match,
                "resultsPerPage": max_results,
            }

            # Also try keyword search if no version
            if not version:
                params = {
                    "keywordSearch": f"{software}",
                    "resultsPerPage": max_results,
                }

            headers = {}
            if self._api_key:
                headers["apiKey"] = self._api_key

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(NVD_API_BASE, params=params, headers=headers)

                if response.status_code == 404:
                    # Try keyword search as fallback
                    params = {
                        "keywordSearch": f"{software} {version}" if version else software,
                        "resultsPerPage": max_results,
                    }
                    response = await client.get(NVD_API_BASE, params=params, headers=headers)

                if response.status_code != 200:
                    return ToolResult(
                        success=False,
                        output="",
                        error=f"NVD API error: HTTP {response.status_code}",
                    )

                data = response.json()

        except httpx.TimeoutException:
            return ToolResult(
                success=False,
                output="",
                error="NVD API timeout. Try again later.",
            )
        except Exception as e:
            logger.error("nvd_request_failed", error=str(e))
            return ToolResult(
                success=False,
                output="",
                error=f"NVD request failed: {str(e)[:100]}",
            )

        # Parse results
        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        if not vulnerabilities:
            result = ToolResult(
                success=True,
                output=f"No known CVEs found for {software}" + (f" version {version}" if version else ""),
                metadata={
                    "software": software,
                    "version": version,
                    "total_cves": 0,
                },
            )
            self._cache[cache_key] = result
            return result

        # Format CVE results
        output_parts = [
            f"Found {total_results} CVE(s) for {software}" + (f" v{version}" if version else ""),
            f"Showing top {min(len(vulnerabilities), max_results)} by severity:\n",
        ]

        cve_list = []

        for vuln in vulnerabilities[:max_results]:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "Unknown")

            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:300]
                    break

            # Get CVSS score
            metrics = cve_data.get("metrics", {})
            cvss_score = None
            cvss_severity = "UNKNOWN"

            # Try CVSS 3.1 first, then 3.0, then 2.0
            for cvss_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if cvss_key in metrics:
                    cvss_data = metrics[cvss_key]
                    if cvss_data and len(cvss_data) > 0:
                        cvss_info = cvss_data[0].get("cvssData", {})
                        cvss_score = cvss_info.get("baseScore")
                        cvss_severity = cvss_info.get("baseSeverity", "UNKNOWN")
                        break

            # Check for exploit availability (references)
            references = cve_data.get("references", [])
            has_exploit = any(
                "exploit" in ref.get("url", "").lower() or
                "poc" in ref.get("url", "").lower() or
                "github.com" in ref.get("url", "").lower()
                for ref in references
            )

            # Get published date
            published = cve_data.get("published", "")[:10]

            # Severity emoji
            severity_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
                "UNKNOWN": "⚪",
            }.get(cvss_severity.upper(), "⚪")

            exploit_indicator = "⚡ EXPLOIT AVAILABLE" if has_exploit else ""

            output_parts.append(f"\n{severity_emoji} [{cve_id}] CVSS: {cvss_score or 'N/A'} ({cvss_severity})")
            if exploit_indicator:
                output_parts.append(f"   {exploit_indicator}")
            output_parts.append(f"   Published: {published}")
            output_parts.append(f"   {description}...")

            cve_list.append({
                "id": cve_id,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "has_exploit": has_exploit,
                "published": published,
                "description": description,
            })

        # Sort by CVSS score (highest first)
        cve_list.sort(key=lambda x: x["cvss_score"] or 0, reverse=True)

        result = ToolResult(
            success=True,
            output="\n".join(output_parts),
            metadata={
                "software": software,
                "version": version,
                "total_cves": total_results,
                "cves": cve_list,
            },
        )

        # Cache the result
        self._cache[cache_key] = result

        logger.info(
            "nvd_lookup_complete",
            software=software,
            version=version,
            cve_count=len(cve_list),
        )

        return result
