"""
Attack Selector for Inferno.

Maps detected technologies to prioritized attack vectors.
Uses hints, fingerprints, and context to select the most effective attacks.

Key features:
- Technology-to-attack mapping
- Context-aware prioritization
- WAF-aware attack selection
- Learning from successful attacks
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

from inferno.core.hint_extractor import Hint, HintPriority, HintType

logger = structlog.get_logger(__name__)


class AttackCategory(str, Enum):
    """Categories of attacks."""

    INJECTION = "injection"  # SQLi, XSS, Command injection
    AUTHENTICATION = "authentication"  # Auth bypass, session attacks
    FILE_ACCESS = "file_access"  # LFI, RFI, path traversal
    SSRF = "ssrf"  # Server-side request forgery
    DESERIALIZATION = "deserialization"  # Object injection
    BUSINESS_LOGIC = "business_logic"  # Logic flaws
    CRYPTOGRAPHIC = "cryptographic"  # Crypto attacks
    RACE_CONDITION = "race_condition"  # Concurrency attacks


@dataclass
class AttackVector:
    """A specific attack vector to try."""

    name: str
    category: AttackCategory
    priority: float  # 0.0-1.0, higher = try first
    techniques: list[str]  # Specific techniques/payloads
    tools: list[str] = field(default_factory=list)  # Tools to use
    prerequisites: list[str] = field(default_factory=list)  # Required conditions
    description: str = ""


@dataclass
class AttackPlan:
    """A prioritized attack plan."""

    vectors: list[AttackVector]
    total_priority_score: float
    rationale: str
    estimated_coverage: float  # % of common vulns covered


class AttackSelector:
    """
    Select and prioritize attack vectors based on context.

    Uses technology fingerprints, hints, and known patterns
    to create an optimized attack plan.
    """

    # Technology to attack mapping
    TECH_ATTACKS: dict[str, list[dict[str, Any]]] = {
        "php": [
            {
                "name": "type_juggling",
                "category": AttackCategory.AUTHENTICATION,
                "priority": 0.9,
                "techniques": ["strcmp_bypass", "hash_comparison", "array_injection"],
                "tools": [],
                "description": "PHP loose comparison vulnerabilities",
            },
            {
                "name": "deserialization",
                "category": AttackCategory.DESERIALIZATION,
                "priority": 0.85,
                "techniques": ["phpggc", "gadget_chains", "phar_deser"],
                "tools": ["phpggc"],
                "description": "PHP object injection via unserialize()",
            },
            {
                "name": "lfi",
                "category": AttackCategory.FILE_ACCESS,
                "priority": 0.8,
                "techniques": ["wrapper_php", "filter_chain", "log_poison"],
                "tools": [],
                "description": "Local file inclusion via wrappers",
            },
            {
                "name": "preg_replace_rce",
                "category": AttackCategory.INJECTION,
                "priority": 0.7,
                "techniques": ["/e_modifier", "callback_injection"],
                "tools": [],
                "description": "RCE via preg_replace /e modifier",
            },
        ],
        "nodejs": [
            {
                "name": "prototype_pollution",
                "category": AttackCategory.INJECTION,
                "priority": 0.9,
                "techniques": ["__proto__", "constructor.prototype", "json_merge"],
                "tools": [],
                "description": "JavaScript prototype pollution",
            },
            {
                "name": "ssti_nunjucks",
                "category": AttackCategory.INJECTION,
                "priority": 0.8,
                "techniques": ["{{constructor}}", "range.constructor"],
                "tools": [],
                "description": "Server-side template injection in Nunjucks",
            },
            {
                "name": "nosql_injection",
                "category": AttackCategory.INJECTION,
                "priority": 0.75,
                "techniques": ["$gt", "$ne", "$where", "regex_injection"],
                "tools": [],
                "description": "NoSQL injection in MongoDB queries",
            },
        ],
        "python": [
            {
                "name": "ssti_jinja2",
                "category": AttackCategory.INJECTION,
                "priority": 0.9,
                "techniques": ["{{config}}", "lipsum.__globals__", "cycler.__init__"],
                "tools": ["tplmap"],
                "description": "Jinja2 server-side template injection",
            },
            {
                "name": "pickle_rce",
                "category": AttackCategory.DESERIALIZATION,
                "priority": 0.85,
                "techniques": ["__reduce__", "yaml.load", "marshal"],
                "tools": [],
                "description": "Python pickle deserialization RCE",
            },
            {
                "name": "ssrf",
                "category": AttackCategory.SSRF,
                "priority": 0.7,
                "techniques": ["file://", "dict://", "gopher://"],
                "tools": [],
                "description": "SSRF via Python URL handlers",
            },
        ],
        "java": [
            {
                "name": "deserialization",
                "category": AttackCategory.DESERIALIZATION,
                "priority": 0.95,
                "techniques": ["ysoserial", "CommonsCollections", "Spring"],
                "tools": ["ysoserial"],
                "description": "Java deserialization via gadget chains",
            },
            {
                "name": "xxe",
                "category": AttackCategory.FILE_ACCESS,
                "priority": 0.85,
                "techniques": ["external_entity", "parameter_entity", "blind_xxe"],
                "tools": [],
                "description": "XML External Entity injection",
            },
            {
                "name": "el_injection",
                "category": AttackCategory.INJECTION,
                "priority": 0.75,
                "techniques": ["${}", "T()", "Runtime.exec"],
                "tools": [],
                "description": "Expression Language injection",
            },
            {
                "name": "ssti_freemarker",
                "category": AttackCategory.INJECTION,
                "priority": 0.7,
                "techniques": ["<#assign>", "new()", "Execute"],
                "tools": [],
                "description": "Freemarker template injection",
            },
        ],
        "ruby": [
            {
                "name": "ssti_erb",
                "category": AttackCategory.INJECTION,
                "priority": 0.9,
                "techniques": ["<%= system() %>", "IO.popen", "open()"],
                "tools": [],
                "description": "ERB template injection for RCE",
            },
            {
                "name": "mass_assignment",
                "category": AttackCategory.BUSINESS_LOGIC,
                "priority": 0.8,
                "techniques": ["admin=true", "role_id=1"],
                "tools": [],
                "description": "Rails mass assignment vulnerability",
            },
            {
                "name": "deserialization",
                "category": AttackCategory.DESERIALIZATION,
                "priority": 0.75,
                "techniques": ["Marshal.load", "YAML.load"],
                "tools": [],
                "description": "Ruby deserialization attacks",
            },
        ],
        "aspnet": [
            {
                "name": "viewstate_deser",
                "category": AttackCategory.DESERIALIZATION,
                "priority": 0.9,
                "techniques": ["ysoserial.net", "viewstate_decode"],
                "tools": ["ysoserial.net"],
                "description": "ViewState deserialization",
            },
            {
                "name": "padding_oracle",
                "category": AttackCategory.CRYPTOGRAPHIC,
                "priority": 0.8,
                "techniques": ["padbuster", "viewstate_decrypt"],
                "tools": ["padbuster"],
                "description": "Padding oracle on ViewState",
            },
        ],
        "cgi": [
            {
                "name": "command_injection",
                "category": AttackCategory.INJECTION,
                "priority": 0.95,
                "techniques": ["semicolon", "pipe", "backtick", "newline"],
                "tools": [],
                "description": "OS command injection in CGI scripts",
            },
            {
                "name": "path_traversal",
                "category": AttackCategory.FILE_ACCESS,
                "priority": 0.85,
                "techniques": ["../", "....//", "%2e%2e/"],
                "tools": [],
                "description": "Path traversal in CGI",
            },
            {
                "name": "shellshock",
                "category": AttackCategory.INJECTION,
                "priority": 0.7,
                "techniques": ["() { :;};", "env_injection"],
                "tools": [],
                "description": "Shellshock (CVE-2014-6271)",
            },
        ],
        "apache": [
            {
                "name": "mod_proxy_ssrf",
                "category": AttackCategory.SSRF,
                "priority": 0.8,
                "techniques": ["proxy_pass", "rewrite_rule"],
                "tools": [],
                "description": "SSRF via Apache proxy misconfiguration",
            },
            {
                "name": "htaccess_bypass",
                "category": AttackCategory.FILE_ACCESS,
                "priority": 0.7,
                "techniques": ["AllowOverride", "Options"],
                "tools": [],
                "description": ".htaccess configuration bypass",
            },
        ],
        "nginx": [
            {
                "name": "alias_traversal",
                "category": AttackCategory.FILE_ACCESS,
                "priority": 0.85,
                "techniques": ["off_by_slash", "alias_without_slash"],
                "tools": [],
                "description": "Nginx alias path traversal",
            },
            {
                "name": "path_normalization",
                "category": AttackCategory.FILE_ACCESS,
                "priority": 0.75,
                "techniques": ["merge_slashes", "try_files"],
                "tools": [],
                "description": "Path normalization issues",
            },
        ],
    }

    # Default attacks for all targets
    DEFAULT_ATTACKS: list[dict[str, Any]] = [
        {
            "name": "sqli",
            "category": AttackCategory.INJECTION,
            "priority": 0.9,
            "techniques": ["union", "error_based", "blind_boolean", "blind_time"],
            "tools": ["sqlmap"],
            "description": "SQL injection testing",
        },
        {
            "name": "xss",
            "category": AttackCategory.INJECTION,
            "priority": 0.8,
            "techniques": ["reflected", "stored", "dom"],
            "tools": [],
            "description": "Cross-site scripting",
        },
        {
            "name": "ssrf",
            "category": AttackCategory.SSRF,
            "priority": 0.75,
            "techniques": ["localhost", "internal_ip", "cloud_metadata"],
            "tools": [],
            "description": "Server-side request forgery",
        },
        {
            "name": "idor",
            "category": AttackCategory.BUSINESS_LOGIC,
            "priority": 0.7,
            "techniques": ["sequential_ids", "uuid_enum", "hash_bypass"],
            "tools": [],
            "description": "Insecure direct object reference",
        },
        {
            "name": "path_traversal",
            "category": AttackCategory.FILE_ACCESS,
            "priority": 0.65,
            "techniques": ["dotdotslash", "encoding", "null_byte"],
            "tools": [],
            "description": "Path traversal / LFI",
        },
    ]

    def __init__(self) -> None:
        """Initialize the attack selector."""
        self._success_history: dict[str, int] = {}  # attack_name -> success count
        self._failure_history: dict[str, int] = {}  # attack_name -> failure count

    def select_attacks(
        self,
        technologies: list[str],
        hints: list[Hint] | None = None,
        waf_detected: bool = False,
        context: str = "web",
    ) -> AttackPlan:
        """
        Select and prioritize attacks based on context.

        Args:
            technologies: Detected technologies (php, nodejs, etc.)
            hints: Extracted hints from responses
            waf_detected: Whether a WAF was detected
            context: Context type (web, api, ctf)

        Returns:
            AttackPlan with prioritized attack vectors
        """
        vectors: list[AttackVector] = []
        hints = hints or []

        # Add technology-specific attacks
        for tech in technologies:
            tech_lower = tech.lower()
            if tech_lower in self.TECH_ATTACKS:
                for attack_data in self.TECH_ATTACKS[tech_lower]:
                    vector = AttackVector(
                        name=attack_data["name"],
                        category=attack_data["category"],
                        priority=attack_data["priority"],
                        techniques=attack_data["techniques"],
                        tools=attack_data.get("tools", []),
                        description=attack_data["description"],
                    )
                    vectors.append(vector)

        # Add default attacks
        for attack_data in self.DEFAULT_ATTACKS:
            # Check if already added via tech-specific
            if not any(v.name == attack_data["name"] for v in vectors):
                vector = AttackVector(
                    name=attack_data["name"],
                    category=attack_data["category"],
                    priority=attack_data["priority"] * 0.9,  # Slightly lower for defaults
                    techniques=attack_data["techniques"],
                    tools=attack_data.get("tools", []),
                    description=attack_data["description"],
                )
                vectors.append(vector)

        # Boost priorities based on hints
        for hint in hints:
            for vector in vectors:
                if vector.name in hint.suggested_attacks:
                    boost = 0.1 if hint.priority == HintPriority.HIGH else 0.2 if hint.priority == HintPriority.CRITICAL else 0.05
                    vector.priority = min(1.0, vector.priority + boost)

        # Adjust for WAF presence
        if waf_detected:
            # Prioritize attacks that are harder to detect
            hard_to_detect = ["business_logic", "race_condition", "type_juggling", "prototype_pollution"]
            for vector in vectors:
                if vector.name in hard_to_detect:
                    vector.priority += 0.15
                else:
                    vector.priority *= 0.9  # Slightly reduce noisy attacks

        # Apply historical success rates
        for vector in vectors:
            successes = self._success_history.get(vector.name, 0)
            failures = self._failure_history.get(vector.name, 0)
            if successes + failures > 5:  # Only adjust if we have enough data
                success_rate = successes / (successes + failures)
                vector.priority *= (0.8 + 0.4 * success_rate)  # 0.8-1.2 multiplier

        # Sort by priority
        vectors.sort(key=lambda v: v.priority, reverse=True)

        # Calculate total score and coverage
        total_score = sum(v.priority for v in vectors)
        categories_covered = len(set(v.category for v in vectors))
        estimated_coverage = min(1.0, categories_covered / len(AttackCategory) * 1.2)

        # Generate rationale
        top_attacks = ", ".join(v.name for v in vectors[:5])
        rationale = f"Selected {len(vectors)} attack vectors. Top priorities: {top_attacks}. "
        if technologies:
            rationale += f"Technology-specific attacks for: {', '.join(technologies)}. "
        if waf_detected:
            rationale += "WAF detected - prioritizing stealthy attacks. "

        plan = AttackPlan(
            vectors=vectors,
            total_priority_score=total_score,
            rationale=rationale,
            estimated_coverage=estimated_coverage,
        )

        logger.info(
            "attack_plan_created",
            num_vectors=len(vectors),
            top_attack=vectors[0].name if vectors else "none",
            technologies=technologies,
            waf_detected=waf_detected,
        )

        return plan

    def record_result(
        self,
        attack_name: str,
        success: bool,
    ) -> None:
        """
        Record attack success/failure for learning.

        Args:
            attack_name: Name of the attack
            success: Whether it was successful
        """
        if success:
            self._success_history[attack_name] = self._success_history.get(attack_name, 0) + 1
        else:
            self._failure_history[attack_name] = self._failure_history.get(attack_name, 0) + 1

    def get_techniques_for_attack(self, attack_name: str) -> list[str]:
        """Get specific techniques for an attack."""
        # Check tech-specific attacks
        for tech_attacks in self.TECH_ATTACKS.values():
            for attack in tech_attacks:
                if attack["name"] == attack_name:
                    return attack["techniques"]

        # Check default attacks
        for attack in self.DEFAULT_ATTACKS:
            if attack["name"] == attack_name:
                return attack["techniques"]

        return []

    def get_tools_for_attack(self, attack_name: str) -> list[str]:
        """Get recommended tools for an attack."""
        for tech_attacks in self.TECH_ATTACKS.values():
            for attack in tech_attacks:
                if attack["name"] == attack_name:
                    return attack.get("tools", [])

        for attack in self.DEFAULT_ATTACKS:
            if attack["name"] == attack_name:
                return attack.get("tools", [])

        return []


# Global singleton
_attack_selector: AttackSelector | None = None


def get_attack_selector() -> AttackSelector:
    """Get the global attack selector instance."""
    global _attack_selector
    if _attack_selector is None:
        _attack_selector = AttackSelector()
    return _attack_selector
