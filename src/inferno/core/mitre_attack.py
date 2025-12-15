"""
MITRE ATT&CK Framework Mapping for Inferno.

This module provides mappings between penetration testing activities,
vulnerabilities, and MITRE ATT&CK techniques.

ATT&CK Tactics (Relevant for Pentest):
- TA0043: Reconnaissance
- TA0042: Resource Development
- TA0001: Initial Access
- TA0002: Execution
- TA0003: Persistence
- TA0004: Privilege Escalation
- TA0005: Defense Evasion
- TA0006: Credential Access
- TA0007: Discovery
- TA0008: Lateral Movement
- TA0009: Collection
- TA0010: Exfiltration
- TA0011: Command and Control
- TA0040: Impact
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ATTACKTactic(str, Enum):
    """MITRE ATT&CK Tactics."""

    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    COMMAND_AND_CONTROL = "TA0011"
    IMPACT = "TA0040"


@dataclass
class ATTACKTechnique:
    """MITRE ATT&CK Technique representation."""

    technique_id: str  # e.g., "T1190"
    name: str  # e.g., "Exploit Public-Facing Application"
    tactic: ATTACKTactic
    subtechnique_id: str | None = None  # e.g., "T1190.001"
    description: str = ""
    detection_complexity: int = 5  # 1-10, higher = harder to detect
    exploit_complexity: int = 5  # 1-10, higher = more complex

    @property
    def full_id(self) -> str:
        """Get full technique ID including subtechnique."""
        if self.subtechnique_id:
            return self.subtechnique_id
        return self.technique_id

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "technique_id": self.technique_id,
            "subtechnique_id": self.subtechnique_id,
            "full_id": self.full_id,
            "name": self.name,
            "tactic": self.tactic.value,
            "tactic_name": self.tactic.name.replace("_", " ").title(),
            "description": self.description,
            "detection_complexity": self.detection_complexity,
            "exploit_complexity": self.exploit_complexity,
        }


# =============================================================================
# ATT&CK Technique Database
# =============================================================================

# Reconnaissance Techniques (TA0043)
RECON_TECHNIQUES = {
    "port_scan": ATTACKTechnique(
        technique_id="T1046",
        name="Network Service Discovery",
        tactic=ATTACKTactic.RECONNAISSANCE,
        description="Scanning for open ports and services",
        detection_complexity=3,
        exploit_complexity=1,
    ),
    "subdomain_enum": ATTACKTechnique(
        technique_id="T1596",
        subtechnique_id="T1596.001",
        name="Search Open Technical Databases: DNS/Passive DNS",
        tactic=ATTACKTactic.RECONNAISSANCE,
        description="Enumerate subdomains via DNS",
        detection_complexity=2,
        exploit_complexity=1,
    ),
    "tech_fingerprint": ATTACKTechnique(
        technique_id="T1592",
        subtechnique_id="T1592.004",
        name="Gather Victim Host Information: Client Configurations",
        tactic=ATTACKTactic.RECONNAISSANCE,
        description="Identify technology stack and versions",
        detection_complexity=2,
        exploit_complexity=2,
    ),
    "osint": ATTACKTechnique(
        technique_id="T1593",
        name="Search Open Websites/Domains",
        tactic=ATTACKTactic.RECONNAISSANCE,
        description="Gather information from public sources",
        detection_complexity=1,
        exploit_complexity=1,
    ),
    "dir_bruteforce": ATTACKTechnique(
        technique_id="T1083",
        name="File and Directory Discovery",
        tactic=ATTACKTactic.RECONNAISSANCE,
        description="Enumerate directories and files",
        detection_complexity=4,
        exploit_complexity=2,
    ),
}

# Initial Access Techniques (TA0001)
INITIAL_ACCESS_TECHNIQUES = {
    "sqli": ATTACKTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="SQL Injection attack",
        detection_complexity=6,
        exploit_complexity=5,
    ),
    "xss": ATTACKTechnique(
        technique_id="T1189",
        name="Drive-by Compromise",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="Cross-Site Scripting",
        detection_complexity=5,
        exploit_complexity=4,
    ),
    "ssrf": ATTACKTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="Server-Side Request Forgery",
        detection_complexity=7,
        exploit_complexity=6,
    ),
    "rce": ATTACKTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="Remote Code Execution",
        detection_complexity=8,
        exploit_complexity=8,
    ),
    "lfi": ATTACKTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="Local File Inclusion",
        detection_complexity=6,
        exploit_complexity=5,
    ),
    "rfi": ATTACKTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="Remote File Inclusion",
        detection_complexity=7,
        exploit_complexity=6,
    ),
    "xxe": ATTACKTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="XML External Entity Injection",
        detection_complexity=7,
        exploit_complexity=6,
    ),
    "ssti": ATTACKTechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="Server-Side Template Injection",
        detection_complexity=8,
        exploit_complexity=7,
    ),
    "auth_bypass": ATTACKTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="Authentication Bypass",
        detection_complexity=6,
        exploit_complexity=5,
    ),
    "default_creds": ATTACKTechnique(
        technique_id="T1078",
        subtechnique_id="T1078.001",
        name="Valid Accounts: Default Accounts",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="Default credentials exploitation",
        detection_complexity=3,
        exploit_complexity=1,
    ),
    "phishing": ATTACKTechnique(
        technique_id="T1566",
        name="Phishing",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="Social engineering via email/web",
        detection_complexity=5,
        exploit_complexity=4,
    ),
    "supply_chain": ATTACKTechnique(
        technique_id="T1195",
        name="Supply Chain Compromise",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        description="Third-party software/dependency attack",
        detection_complexity=9,
        exploit_complexity=8,
    ),
}

# Execution Techniques (TA0002)
EXECUTION_TECHNIQUES = {
    "command_injection": ATTACKTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic=ATTACKTactic.EXECUTION,
        description="OS Command Injection",
        detection_complexity=6,
        exploit_complexity=5,
    ),
    "code_execution": ATTACKTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic=ATTACKTactic.EXECUTION,
        description="Arbitrary code execution",
        detection_complexity=7,
        exploit_complexity=7,
    ),
    "webshell": ATTACKTechnique(
        technique_id="T1505",
        subtechnique_id="T1505.003",
        name="Server Software Component: Web Shell",
        tactic=ATTACKTactic.EXECUTION,
        description="Web shell deployment",
        detection_complexity=6,
        exploit_complexity=5,
    ),
    "deserialization": ATTACKTechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic=ATTACKTactic.EXECUTION,
        description="Insecure deserialization",
        detection_complexity=8,
        exploit_complexity=7,
    ),
}

# Credential Access Techniques (TA0006)
CREDENTIAL_ACCESS_TECHNIQUES = {
    "credential_dump": ATTACKTechnique(
        technique_id="T1003",
        name="OS Credential Dumping",
        tactic=ATTACKTactic.CREDENTIAL_ACCESS,
        description="Extract credentials from system",
        detection_complexity=7,
        exploit_complexity=6,
    ),
    "password_spray": ATTACKTechnique(
        technique_id="T1110",
        subtechnique_id="T1110.003",
        name="Brute Force: Password Spraying",
        tactic=ATTACKTactic.CREDENTIAL_ACCESS,
        description="Password spraying attack",
        detection_complexity=5,
        exploit_complexity=3,
    ),
    "brute_force": ATTACKTechnique(
        technique_id="T1110",
        subtechnique_id="T1110.001",
        name="Brute Force: Password Guessing",
        tactic=ATTACKTactic.CREDENTIAL_ACCESS,
        description="Brute force password attack",
        detection_complexity=4,
        exploit_complexity=2,
    ),
    "keylogging": ATTACKTechnique(
        technique_id="T1056",
        subtechnique_id="T1056.001",
        name="Input Capture: Keylogging",
        tactic=ATTACKTactic.CREDENTIAL_ACCESS,
        description="Capture keystrokes",
        detection_complexity=6,
        exploit_complexity=5,
    ),
    "session_hijack": ATTACKTechnique(
        technique_id="T1563",
        name="Remote Service Session Hijacking",
        tactic=ATTACKTactic.CREDENTIAL_ACCESS,
        description="Session token theft/hijacking",
        detection_complexity=6,
        exploit_complexity=5,
    ),
}

# Privilege Escalation Techniques (TA0004)
PRIVESC_TECHNIQUES = {
    "privesc_local": ATTACKTechnique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic=ATTACKTactic.PRIVILEGE_ESCALATION,
        description="Local privilege escalation",
        detection_complexity=7,
        exploit_complexity=7,
    ),
    "idor": ATTACKTechnique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic=ATTACKTactic.PRIVILEGE_ESCALATION,
        description="Insecure Direct Object Reference",
        detection_complexity=5,
        exploit_complexity=4,
    ),
    "vertical_privesc": ATTACKTechnique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic=ATTACKTactic.PRIVILEGE_ESCALATION,
        description="Vertical privilege escalation",
        detection_complexity=6,
        exploit_complexity=6,
    ),
    "horizontal_privesc": ATTACKTechnique(
        technique_id="T1078",
        name="Valid Accounts",
        tactic=ATTACKTactic.PRIVILEGE_ESCALATION,
        description="Horizontal privilege escalation",
        detection_complexity=5,
        exploit_complexity=4,
    ),
}

# Defense Evasion Techniques (TA0005)
DEFENSE_EVASION_TECHNIQUES = {
    "waf_bypass": ATTACKTechnique(
        technique_id="T1562",
        subtechnique_id="T1562.001",
        name="Impair Defenses: Disable or Modify Tools",
        tactic=ATTACKTactic.DEFENSE_EVASION,
        description="WAF bypass techniques",
        detection_complexity=8,
        exploit_complexity=6,
    ),
    "obfuscation": ATTACKTechnique(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        tactic=ATTACKTactic.DEFENSE_EVASION,
        description="Payload obfuscation",
        detection_complexity=7,
        exploit_complexity=5,
    ),
    "encoding": ATTACKTechnique(
        technique_id="T1140",
        name="Deobfuscate/Decode Files or Information",
        tactic=ATTACKTactic.DEFENSE_EVASION,
        description="Encoding/decoding payloads",
        detection_complexity=5,
        exploit_complexity=3,
    ),
}

# Impact Techniques (TA0040)
IMPACT_TECHNIQUES = {
    "data_destruction": ATTACKTechnique(
        technique_id="T1485",
        name="Data Destruction",
        tactic=ATTACKTactic.IMPACT,
        description="Data deletion/corruption",
        detection_complexity=6,
        exploit_complexity=4,
    ),
    "defacement": ATTACKTechnique(
        technique_id="T1491",
        name="Defacement",
        tactic=ATTACKTactic.IMPACT,
        description="Website defacement",
        detection_complexity=2,
        exploit_complexity=3,
    ),
    "dos": ATTACKTechnique(
        technique_id="T1499",
        name="Endpoint Denial of Service",
        tactic=ATTACKTactic.IMPACT,
        description="Denial of service attack",
        detection_complexity=3,
        exploit_complexity=2,
    ),
    "ransomware": ATTACKTechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactic=ATTACKTactic.IMPACT,
        description="Ransomware/encryption attack",
        detection_complexity=5,
        exploit_complexity=6,
    ),
}

# Combined technique database
ALL_TECHNIQUES: dict[str, ATTACKTechnique] = {
    **RECON_TECHNIQUES,
    **INITIAL_ACCESS_TECHNIQUES,
    **EXECUTION_TECHNIQUES,
    **CREDENTIAL_ACCESS_TECHNIQUES,
    **PRIVESC_TECHNIQUES,
    **DEFENSE_EVASION_TECHNIQUES,
    **IMPACT_TECHNIQUES,
}


# =============================================================================
# Vulnerability to ATT&CK Mapping
# =============================================================================

# Map vulnerability types to ATT&CK techniques
VULN_TO_ATTACK_MAP: dict[str, list[str]] = {
    # Web vulnerabilities
    "sqli": ["sqli", "credential_dump"],
    "sql_injection": ["sqli", "credential_dump"],
    "xss": ["xss", "session_hijack"],
    "cross_site_scripting": ["xss", "session_hijack"],
    "ssrf": ["ssrf"],
    "server_side_request_forgery": ["ssrf"],
    "rce": ["rce", "code_execution", "webshell"],
    "remote_code_execution": ["rce", "code_execution", "webshell"],
    "lfi": ["lfi"],
    "local_file_inclusion": ["lfi"],
    "rfi": ["rfi"],
    "remote_file_inclusion": ["rfi"],
    "xxe": ["xxe"],
    "xml_external_entity": ["xxe"],
    "ssti": ["ssti", "code_execution"],
    "server_side_template_injection": ["ssti", "code_execution"],
    "command_injection": ["command_injection", "code_execution"],
    "os_command_injection": ["command_injection", "code_execution"],
    "path_traversal": ["lfi"],
    "directory_traversal": ["lfi"],

    # Auth vulnerabilities
    "auth_bypass": ["auth_bypass"],
    "authentication_bypass": ["auth_bypass"],
    "broken_auth": ["auth_bypass", "default_creds"],
    "default_credentials": ["default_creds"],
    "weak_password": ["brute_force", "password_spray"],
    "session_fixation": ["session_hijack"],
    "session_hijacking": ["session_hijack"],

    # Access control
    "idor": ["idor"],
    "insecure_direct_object_reference": ["idor"],
    "broken_access_control": ["idor", "horizontal_privesc", "vertical_privesc"],
    "privesc": ["privesc_local", "vertical_privesc"],
    "privilege_escalation": ["privesc_local", "vertical_privesc"],

    # Other
    "deserialization": ["deserialization"],
    "insecure_deserialization": ["deserialization"],
    "file_upload": ["webshell"],
    "unrestricted_file_upload": ["webshell"],
    "information_disclosure": ["tech_fingerprint", "osint"],
    "sensitive_data_exposure": ["tech_fingerprint"],
    "cors_misconfiguration": ["session_hijack"],
    "open_redirect": ["phishing"],
    "csrf": ["xss"],
    "clickjacking": ["xss"],
}

# Tool to ATT&CK technique mapping
TOOL_TO_ATTACK_MAP: dict[str, list[str]] = {
    "nmap": ["port_scan", "tech_fingerprint"],
    "masscan": ["port_scan"],
    "rustscan": ["port_scan"],
    "gobuster": ["dir_bruteforce"],
    "dirbuster": ["dir_bruteforce"],
    "dirb": ["dir_bruteforce"],
    "ffuf": ["dir_bruteforce"],
    "feroxbuster": ["dir_bruteforce"],
    "subfinder": ["subdomain_enum"],
    "amass": ["subdomain_enum", "osint"],
    "sublist3r": ["subdomain_enum"],
    "sqlmap": ["sqli", "credential_dump"],
    "nikto": ["tech_fingerprint", "dir_bruteforce"],
    "nuclei": ["tech_fingerprint", "sqli", "xss", "ssrf"],
    "burp": ["sqli", "xss", "ssrf", "lfi", "auth_bypass"],
    "wfuzz": ["dir_bruteforce", "sqli", "xss"],
    "hydra": ["brute_force", "password_spray"],
    "medusa": ["brute_force"],
    "john": ["credential_dump", "brute_force"],
    "hashcat": ["credential_dump", "brute_force"],
    "mimikatz": ["credential_dump"],
    "responder": ["credential_dump", "session_hijack"],
    "msfconsole": ["rce", "privesc_local", "code_execution"],
    "metasploit": ["rce", "privesc_local", "code_execution"],
    "searchsploit": ["rce", "privesc_local"],
    "linpeas": ["privesc_local"],
    "winpeas": ["privesc_local"],
    "curl": ["ssrf", "xxe", "lfi"],
    "wget": ["ssrf", "lfi"],
    "nc": ["rce", "code_execution"],
    "netcat": ["rce", "code_execution"],
}


# =============================================================================
# Mapping Functions
# =============================================================================

def get_technique_for_vuln(vuln_type: str) -> list[ATTACKTechnique]:
    """
    Get ATT&CK techniques for a vulnerability type.

    Args:
        vuln_type: Vulnerability type (e.g., "sqli", "xss")

    Returns:
        List of ATTACKTechnique objects
    """
    vuln_normalized = vuln_type.lower().replace("-", "_").replace(" ", "_")
    technique_keys = VULN_TO_ATTACK_MAP.get(vuln_normalized, [])

    techniques = []
    for key in technique_keys:
        if key in ALL_TECHNIQUES:
            techniques.append(ALL_TECHNIQUES[key])

    return techniques


def get_technique_for_tool(tool_name: str) -> list[ATTACKTechnique]:
    """
    Get ATT&CK techniques for a tool.

    Args:
        tool_name: Tool name (e.g., "nmap", "sqlmap")

    Returns:
        List of ATTACKTechnique objects
    """
    tool_normalized = tool_name.lower().replace("-", "_").replace(" ", "_")
    technique_keys = TOOL_TO_ATTACK_MAP.get(tool_normalized, [])

    techniques = []
    for key in technique_keys:
        if key in ALL_TECHNIQUES:
            techniques.append(ALL_TECHNIQUES[key])

    return techniques


def get_technique_by_id(technique_id: str) -> ATTACKTechnique | None:
    """
    Get ATT&CK technique by its ID.

    Args:
        technique_id: Technique ID (e.g., "T1190", "T1059.001")

    Returns:
        ATTACKTechnique or None
    """
    for technique in ALL_TECHNIQUES.values():
        if technique.full_id == technique_id:
            return technique
    return None


def get_techniques_by_tactic(tactic: ATTACKTactic) -> list[ATTACKTechnique]:
    """
    Get all techniques for a tactic.

    Args:
        tactic: ATT&CK Tactic enum

    Returns:
        List of ATTACKTechnique objects
    """
    return [t for t in ALL_TECHNIQUES.values() if t.tactic == tactic]


def calculate_detection_complexity(techniques: list[ATTACKTechnique]) -> int:
    """
    Calculate aggregate detection complexity for techniques.

    Uses the maximum detection complexity among techniques,
    as the overall detection difficulty is bounded by the hardest-to-detect technique.

    Args:
        techniques: List of ATTACKTechnique objects

    Returns:
        Detection complexity score (1-10)
    """
    if not techniques:
        return 5  # Default medium complexity

    return max(t.detection_complexity for t in techniques)


def calculate_exploit_complexity(techniques: list[ATTACKTechnique]) -> int:
    """
    Calculate aggregate exploit complexity for techniques.

    Uses the maximum exploit complexity among techniques,
    as successful exploitation requires mastering all techniques.

    Args:
        techniques: List of ATTACKTechnique objects

    Returns:
        Exploit complexity score (1-10)
    """
    if not techniques:
        return 5  # Default medium complexity

    return max(t.exploit_complexity for t in techniques)


@dataclass
class ATTACKMapping:
    """Complete ATT&CK mapping for a finding/activity."""

    techniques: list[ATTACKTechnique] = field(default_factory=list)
    primary_tactic: ATTACKTactic | None = None
    detection_complexity: int = 5
    exploit_complexity: int = 5

    def __post_init__(self):
        """Calculate complexities from techniques."""
        if self.techniques:
            self.detection_complexity = calculate_detection_complexity(self.techniques)
            self.exploit_complexity = calculate_exploit_complexity(self.techniques)
            # Primary tactic is from the most complex technique
            most_complex = max(self.techniques, key=lambda t: t.exploit_complexity)
            self.primary_tactic = most_complex.tactic

    @property
    def technique_ids(self) -> list[str]:
        """Get list of technique IDs."""
        return [t.full_id for t in self.techniques]

    @property
    def tactic_ids(self) -> list[str]:
        """Get unique tactic IDs."""
        return list(set(t.tactic.value for t in self.techniques))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "techniques": [t.to_dict() for t in self.techniques],
            "technique_ids": self.technique_ids,
            "tactic_ids": self.tactic_ids,
            "primary_tactic": self.primary_tactic.value if self.primary_tactic else None,
            "detection_complexity": self.detection_complexity,
            "exploit_complexity": self.exploit_complexity,
        }


def map_finding_to_attack(
    vuln_type: str,
    tools_used: list[str] | None = None,
) -> ATTACKMapping:
    """
    Create complete ATT&CK mapping for a finding.

    Args:
        vuln_type: Vulnerability type
        tools_used: List of tools used to discover/exploit

    Returns:
        ATTACKMapping with all relevant techniques
    """
    techniques = get_technique_for_vuln(vuln_type)

    # Add techniques from tools used
    if tools_used:
        for tool in tools_used:
            tool_techniques = get_technique_for_tool(tool)
            for tech in tool_techniques:
                if tech not in techniques:
                    techniques.append(tech)

    return ATTACKMapping(techniques=techniques)
