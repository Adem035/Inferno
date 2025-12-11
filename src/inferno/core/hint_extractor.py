"""
Hint Extractor for Inferno.

Extracts actionable hints from HTTP responses, HTML comments, error messages,
and other sources to guide attack selection and prioritization.

Key features:
- HTML comment extraction
- Error message parsing for technology hints
- CTF-specific hint detection
- Path/file hints from 404/500 errors
- Technology fingerprinting from headers
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class HintType(str, Enum):
    """Types of hints that can be extracted."""

    TECHNOLOGY = "technology"  # Tech stack hints (PHP, Node, etc.)
    PATH = "path"  # File/directory hints
    VULNERABILITY = "vulnerability"  # Explicit vuln hints
    CREDENTIAL = "credential"  # Credential patterns
    DEBUG = "debug"  # Debug information
    CTF = "ctf"  # CTF-specific hints
    CONFIGURATION = "configuration"  # Config hints
    INTERNAL = "internal"  # Internal paths/IPs


class HintPriority(str, Enum):
    """Priority levels for hints."""

    CRITICAL = "critical"  # Must investigate immediately
    HIGH = "high"  # Strong signal
    MEDIUM = "medium"  # Worth investigating
    LOW = "low"  # Background info


@dataclass
class Hint:
    """A single extracted hint."""

    content: str
    hint_type: HintType
    priority: HintPriority
    source: str  # Where the hint was found
    confidence: float = 1.0  # 0.0-1.0
    suggested_attacks: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class HintExtractor:
    """
    Extract actionable hints from various sources.

    This component analyzes responses, errors, and content to find
    hints that should guide attack selection.
    """

    # Technology fingerprints and their attack implications
    TECH_PATTERNS: dict[str, dict[str, Any]] = {
        # PHP indicators
        r"\.php": {
            "tech": "PHP",
            "attacks": ["type_juggling", "deserialization", "lfi", "rfi", "preg_replace_rce"],
            "priority": HintPriority.HIGH,
        },
        r"PHPSESSID": {
            "tech": "PHP",
            "attacks": ["session_fixation", "type_juggling", "deserialization"],
            "priority": HintPriority.HIGH,
        },
        r"X-Powered-By:\s*PHP": {
            "tech": "PHP",
            "attacks": ["type_juggling", "deserialization", "lfi"],
            "priority": HintPriority.HIGH,
        },
        # Node.js indicators
        r"express|node\.js|npm": {
            "tech": "Node.js",
            "attacks": ["prototype_pollution", "ssti_nunjucks", "ssrf", "nosql_injection"],
            "priority": HintPriority.HIGH,
        },
        r"connect\.sid": {
            "tech": "Node.js/Express",
            "attacks": ["prototype_pollution", "jwt_attacks"],
            "priority": HintPriority.HIGH,
        },
        # Python indicators
        r"werkzeug|flask|django|gunicorn": {
            "tech": "Python",
            "attacks": ["ssti_jinja2", "pickle_rce", "yaml_load", "ssrf"],
            "priority": HintPriority.HIGH,
        },
        # Java indicators
        r"\.jsp|jsessionid|java\.|tomcat|spring": {
            "tech": "Java",
            "attacks": ["deserialization", "ssti_freemarker", "xxe", "el_injection"],
            "priority": HintPriority.HIGH,
        },
        # Ruby indicators
        r"\.rb|rack|rails|sinatra": {
            "tech": "Ruby",
            "attacks": ["ssti_erb", "mass_assignment", "command_injection"],
            "priority": HintPriority.HIGH,
        },
        # ASP.NET indicators
        r"\.aspx?|__VIEWSTATE|ASP\.NET": {
            "tech": "ASP.NET",
            "attacks": ["viewstate_deser", "padding_oracle", "xxe"],
            "priority": HintPriority.HIGH,
        },
        # CGI indicators
        r"/cgi-bin/|\.cgi|\.pl": {
            "tech": "CGI",
            "attacks": ["command_injection", "path_traversal", "shellshock"],
            "priority": HintPriority.HIGH,
        },
        # Apache-specific
        r"apache|mod_": {
            "tech": "Apache",
            "attacks": ["path_traversal", "mod_proxy_ssrf", "htaccess_bypass"],
            "priority": HintPriority.MEDIUM,
        },
        # nginx-specific
        r"nginx": {
            "tech": "nginx",
            "attacks": ["path_normalization", "alias_traversal", "off_by_slash"],
            "priority": HintPriority.MEDIUM,
        },
    }

    # CTF-specific hint patterns
    CTF_PATTERNS: dict[str, dict[str, Any]] = {
        r"flag\{|CTF\{|FLAG=|/flag": {
            "hint": "Flag location hint",
            "priority": HintPriority.CRITICAL,
            "attacks": ["lfi", "rce", "ssrf"],
        },
        r"/tmp|/var/tmp|/dev/shm": {
            "hint": "Writable directory hint",
            "priority": HintPriority.HIGH,
            "attacks": ["file_upload", "lfi", "race_condition"],
        },
        r"serialize|unserialize|pickle|marshal": {
            "hint": "Serialization hint",
            "priority": HintPriority.CRITICAL,
            "attacks": ["deserialization", "pickle_rce"],
        },
        r"eval|exec|system|passthru|shell_exec|popen": {
            "hint": "Code execution function hint",
            "priority": HintPriority.CRITICAL,
            "attacks": ["command_injection", "rce"],
        },
        r"strcmp|strcasecmp|==\s*0|===\s*0": {
            "hint": "Type juggling vulnerability hint",
            "priority": HintPriority.HIGH,
            "attacks": ["type_juggling", "auth_bypass"],
        },
        r"preg_replace.*\/.*e|create_function": {
            "hint": "PHP code execution pattern",
            "priority": HintPriority.CRITICAL,
            "attacks": ["preg_replace_rce", "rce"],
        },
        r"include|require|include_once|require_once": {
            "hint": "File inclusion function",
            "priority": HintPriority.HIGH,
            "attacks": ["lfi", "rfi"],
        },
        r"file_get_contents|fopen|readfile|file\(": {
            "hint": "File read function",
            "priority": HintPriority.HIGH,
            "attacks": ["lfi", "ssrf", "xxe"],
        },
        r"curl|wget|http://|https://": {
            "hint": "URL fetch capability",
            "priority": HintPriority.HIGH,
            "attacks": ["ssrf", "rfi"],
        },
        r"md5|sha1|hash\(": {
            "hint": "Hash function (possible magic hash)",
            "priority": HintPriority.MEDIUM,
            "attacks": ["magic_hash", "hash_collision"],
        },
        r"base64|rot13|str_rot13": {
            "hint": "Encoding function",
            "priority": HintPriority.MEDIUM,
            "attacks": ["filter_bypass", "waf_bypass"],
        },
        r"SimpleXML|DOMDocument|xml_parse": {
            "hint": "XML parsing",
            "priority": HintPriority.HIGH,
            "attacks": ["xxe", "xml_injection"],
        },
        r"jwt|jsonwebtoken|HS256|RS256": {
            "hint": "JWT usage",
            "priority": HintPriority.HIGH,
            "attacks": ["jwt_none", "jwt_key_confusion", "jwt_weak_secret"],
        },
        r"admin|root|superuser|administrator": {
            "hint": "Admin reference",
            "priority": HintPriority.MEDIUM,
            "attacks": ["auth_bypass", "privilege_escalation", "idor"],
        },
    }

    # Path hints from error messages
    PATH_PATTERNS: list[tuple[str, HintPriority]] = [
        (r"/var/www/\S+", HintPriority.HIGH),
        (r"/home/\w+/\S+", HintPriority.HIGH),
        (r"/opt/\S+", HintPriority.MEDIUM),
        (r"/etc/\S+", HintPriority.HIGH),
        (r"/usr/share/\S+", HintPriority.MEDIUM),
        (r"C:\\[^\s<>\"]+", HintPriority.HIGH),
        (r"/app/\S+", HintPriority.HIGH),
        (r"/data/\S+", HintPriority.MEDIUM),
    ]

    # Internal IP patterns
    INTERNAL_PATTERNS: list[tuple[str, HintPriority]] = [
        (r"10\.\d+\.\d+\.\d+", HintPriority.HIGH),
        (r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", HintPriority.HIGH),
        (r"192\.168\.\d+\.\d+", HintPriority.HIGH),
        (r"127\.0\.0\.\d+", HintPriority.HIGH),
        (r"localhost", HintPriority.MEDIUM),
    ]

    def __init__(self) -> None:
        """Initialize the hint extractor."""
        self._compiled_tech: dict[re.Pattern, dict] = {
            re.compile(pattern, re.IGNORECASE): data
            for pattern, data in self.TECH_PATTERNS.items()
        }
        self._compiled_ctf: dict[re.Pattern, dict] = {
            re.compile(pattern, re.IGNORECASE): data
            for pattern, data in self.CTF_PATTERNS.items()
        }
        self._compiled_paths: list[tuple[re.Pattern, HintPriority]] = [
            (re.compile(pattern), priority)
            for pattern, priority in self.PATH_PATTERNS
        ]
        self._compiled_internal: list[tuple[re.Pattern, HintPriority]] = [
            (re.compile(pattern), priority)
            for pattern, priority in self.INTERNAL_PATTERNS
        ]

    def extract_from_response(
        self,
        body: str,
        headers: dict[str, str] | None = None,
        url: str = "",
        status_code: int = 200,
    ) -> list[Hint]:
        """
        Extract hints from an HTTP response.

        Args:
            body: Response body
            headers: Response headers
            url: Request URL
            status_code: HTTP status code

        Returns:
            List of extracted hints
        """
        hints: list[Hint] = []
        headers = headers or {}
        source = url or "response"

        # Extract from headers
        hints.extend(self._extract_from_headers(headers, source))

        # Extract HTML comments
        hints.extend(self._extract_html_comments(body, source))

        # Extract technology hints
        hints.extend(self._extract_technology_hints(body, headers, source))

        # Extract CTF-specific hints
        hints.extend(self._extract_ctf_hints(body, source))

        # Extract path hints
        hints.extend(self._extract_path_hints(body, source))

        # Extract internal network hints
        hints.extend(self._extract_internal_hints(body, source))

        # Extract from error messages (especially on 4xx/5xx)
        if status_code >= 400:
            hints.extend(self._extract_error_hints(body, status_code, source))

        # Deduplicate by content
        seen = set()
        unique_hints = []
        for hint in hints:
            key = f"{hint.content}:{hint.hint_type.value}"
            if key not in seen:
                seen.add(key)
                unique_hints.append(hint)

        # Sort by priority
        priority_order = {
            HintPriority.CRITICAL: 0,
            HintPriority.HIGH: 1,
            HintPriority.MEDIUM: 2,
            HintPriority.LOW: 3,
        }
        unique_hints.sort(key=lambda h: priority_order[h.priority])

        logger.debug(
            "hints_extracted",
            count=len(unique_hints),
            source=source,
            critical=sum(1 for h in unique_hints if h.priority == HintPriority.CRITICAL),
        )

        return unique_hints

    def _extract_from_headers(
        self,
        headers: dict[str, str],
        source: str,
    ) -> list[Hint]:
        """Extract hints from HTTP headers."""
        hints = []

        # Check common revealing headers
        revealing_headers = {
            "X-Powered-By": HintType.TECHNOLOGY,
            "Server": HintType.TECHNOLOGY,
            "X-AspNet-Version": HintType.TECHNOLOGY,
            "X-Runtime": HintType.TECHNOLOGY,
            "X-Debug": HintType.DEBUG,
            "X-Debug-Token": HintType.DEBUG,
            "X-Debug-Token-Link": HintType.DEBUG,
        }

        for header, hint_type in revealing_headers.items():
            for h_name, h_value in headers.items():
                if h_name.lower() == header.lower():
                    hints.append(Hint(
                        content=f"{header}: {h_value}",
                        hint_type=hint_type,
                        priority=HintPriority.MEDIUM if hint_type == HintType.TECHNOLOGY else HintPriority.HIGH,
                        source=f"{source} (header)",
                        suggested_attacks=self._get_attacks_for_tech(h_value),
                    ))

        return hints

    def _extract_html_comments(self, body: str, source: str) -> list[Hint]:
        """Extract hints from HTML comments."""
        hints = []

        # Match HTML comments
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        for match in comment_pattern.finditer(body):
            comment = match.group(1).strip()

            # Skip empty or very short comments
            if len(comment) < 3:
                continue

            # Skip common non-informative comments
            skip_patterns = [
                r"^\s*\[if\s+",  # IE conditionals
                r"^\s*end\s*$",
                r"^\s*\d+\s*$",  # Just numbers
            ]
            if any(re.match(p, comment, re.IGNORECASE) for p in skip_patterns):
                continue

            # Determine priority based on content
            priority = HintPriority.LOW
            hint_type = HintType.DEBUG

            # Check for high-value comment content
            if re.search(r"password|secret|key|token|credential", comment, re.I):
                priority = HintPriority.CRITICAL
                hint_type = HintType.CREDENTIAL
            elif re.search(r"TODO|FIXME|BUG|HACK|XXX", comment, re.I):
                priority = HintPriority.HIGH
                hint_type = HintType.DEBUG
            elif re.search(r"admin|root|flag|/tmp|/var", comment, re.I):
                priority = HintPriority.HIGH
                hint_type = HintType.CTF

            hints.append(Hint(
                content=comment[:500],  # Truncate long comments
                hint_type=hint_type,
                priority=priority,
                source=f"{source} (HTML comment)",
            ))

        return hints

    def _extract_technology_hints(
        self,
        body: str,
        headers: dict[str, str],
        source: str,
    ) -> list[Hint]:
        """Extract technology fingerprints."""
        hints = []
        combined = body + " " + str(headers)

        for pattern, data in self._compiled_tech.items():
            if pattern.search(combined):
                hints.append(Hint(
                    content=f"Technology detected: {data['tech']}",
                    hint_type=HintType.TECHNOLOGY,
                    priority=data["priority"],
                    source=source,
                    suggested_attacks=data["attacks"],
                    metadata={"technology": data["tech"]},
                ))

        return hints

    def _extract_ctf_hints(self, body: str, source: str) -> list[Hint]:
        """Extract CTF-specific hints."""
        hints = []

        for pattern, data in self._compiled_ctf.items():
            matches = pattern.findall(body)
            if matches:
                # Get the actual match for context
                match_str = matches[0] if isinstance(matches[0], str) else str(matches[0])
                hints.append(Hint(
                    content=f"{data['hint']}: {match_str[:100]}",
                    hint_type=HintType.CTF,
                    priority=data["priority"],
                    source=source,
                    suggested_attacks=data["attacks"],
                ))

        return hints

    def _extract_path_hints(self, body: str, source: str) -> list[Hint]:
        """Extract file path hints."""
        hints = []

        for pattern, priority in self._compiled_paths:
            for match in pattern.finditer(body):
                path = match.group(0)
                hints.append(Hint(
                    content=f"Path discovered: {path}",
                    hint_type=HintType.PATH,
                    priority=priority,
                    source=source,
                    suggested_attacks=["lfi", "path_traversal"],
                    metadata={"path": path},
                ))

        return hints

    def _extract_internal_hints(self, body: str, source: str) -> list[Hint]:
        """Extract internal network hints."""
        hints = []

        for pattern, priority in self._compiled_internal:
            for match in pattern.finditer(body):
                internal = match.group(0)
                hints.append(Hint(
                    content=f"Internal reference: {internal}",
                    hint_type=HintType.INTERNAL,
                    priority=priority,
                    source=source,
                    suggested_attacks=["ssrf", "network_pivot"],
                    metadata={"internal_target": internal},
                ))

        return hints

    def _extract_error_hints(
        self,
        body: str,
        status_code: int,
        source: str,
    ) -> list[Hint]:
        """Extract hints from error responses."""
        hints = []

        # Stack trace patterns
        stack_patterns = [
            (r"at\s+[\w.]+\([\w./]+:\d+\)", "Stack trace detected"),
            (r"File\s+\"[^\"]+\",\s+line\s+\d+", "Python traceback"),
            (r"#\d+\s+[\w\\]+->", "PHP stack trace"),
            (r"Exception in thread", "Java exception"),
        ]

        for pattern, desc in stack_patterns:
            if re.search(pattern, body):
                hints.append(Hint(
                    content=desc,
                    hint_type=HintType.DEBUG,
                    priority=HintPriority.HIGH,
                    source=f"{source} ({status_code})",
                    suggested_attacks=["error_based_injection"],
                ))

        # SQL error patterns
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*\Wmysqli?_",
            r"PostgreSQL.*ERROR",
            r"ORA-\d{5}",
            r"Microsoft.*ODBC.*SQL Server",
            r"SQLite.*error",
        ]

        for pattern in sql_errors:
            if re.search(pattern, body, re.I):
                hints.append(Hint(
                    content="SQL error message detected - possible SQLi",
                    hint_type=HintType.VULNERABILITY,
                    priority=HintPriority.CRITICAL,
                    source=f"{source} ({status_code})",
                    suggested_attacks=["sqli", "error_based_sqli", "union_sqli"],
                ))
                break

        return hints

    def _get_attacks_for_tech(self, tech_string: str) -> list[str]:
        """Get suggested attacks based on technology string."""
        tech_lower = tech_string.lower()

        if "php" in tech_lower:
            return ["type_juggling", "deserialization", "lfi"]
        elif "node" in tech_lower or "express" in tech_lower:
            return ["prototype_pollution", "ssti"]
        elif "python" in tech_lower or "flask" in tech_lower or "django" in tech_lower:
            return ["ssti_jinja2", "pickle_rce"]
        elif "java" in tech_lower or "tomcat" in tech_lower:
            return ["deserialization", "xxe"]
        elif "asp" in tech_lower or ".net" in tech_lower:
            return ["viewstate_deser", "xxe"]

        return []

    def prioritize_attacks(self, hints: list[Hint]) -> list[str]:
        """
        Get prioritized list of attacks based on extracted hints.

        Args:
            hints: List of extracted hints

        Returns:
            Ordered list of attack types to try
        """
        attack_scores: dict[str, float] = {}

        priority_multiplier = {
            HintPriority.CRITICAL: 10.0,
            HintPriority.HIGH: 5.0,
            HintPriority.MEDIUM: 2.0,
            HintPriority.LOW: 1.0,
        }

        for hint in hints:
            multiplier = priority_multiplier[hint.priority] * hint.confidence
            for attack in hint.suggested_attacks:
                attack_scores[attack] = attack_scores.get(attack, 0) + multiplier

        # Sort by score descending
        sorted_attacks = sorted(
            attack_scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        return [attack for attack, _ in sorted_attacks]


# Global singleton
_hint_extractor: HintExtractor | None = None


def get_hint_extractor() -> HintExtractor:
    """Get the global hint extractor instance."""
    global _hint_extractor
    if _hint_extractor is None:
        _hint_extractor = HintExtractor()
    return _hint_extractor
