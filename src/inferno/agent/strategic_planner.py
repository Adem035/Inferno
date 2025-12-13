"""
Strategic Planner for Inferno-AI.

Transforms Inferno from reactive to proactive by generating strategic attack plans
before tool execution. The planner profiles targets, builds application models,
prioritizes attack vectors, and allocates token budget across phases.

Key Features:
- Target profiling (tech stack, industry, security posture)
- Initial ApplicationModel construction from reconnaissance
- Prioritized attack step generation
- Attack chain definition based on target profile
- Token budget allocation across assessment phases
- Execution tracking and dynamic re-prioritization
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from anthropic import Anthropic


logger = structlog.get_logger(__name__)


class AttackPhase(str, Enum):
    """Attack assessment phases."""

    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"


class AttackType(str, Enum):
    """Types of attacks for planning."""

    # Web vulnerabilities
    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    IDOR = "idor"
    LFI = "lfi"
    RFI = "rfi"
    XXE = "xxe"
    SSTI = "ssti"
    DESERIALIZATION = "deserialization"
    CSRF = "csrf"
    CORS_MISCONFIG = "cors_misconfig"

    # Authentication/Authorization
    AUTH_BYPASS = "auth_bypass"
    SESSION_HIJACK = "session_hijack"
    JWT_ATTACK = "jwt_attack"
    OAUTH_MISCONFIGURATION = "oauth_misconfiguration"
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # Business logic
    BUSINESS_LOGIC = "business_logic"
    RACE_CONDITION = "race_condition"
    PRICE_MANIPULATION = "price_manipulation"
    WORKFLOW_BYPASS = "workflow_bypass"

    # Infrastructure
    RCE = "rce"
    FILE_UPLOAD = "file_upload"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"

    # Information disclosure
    INFO_DISCLOSURE = "info_disclosure"
    CREDENTIAL_LEAK = "credential_leak"
    SOURCE_CODE_LEAK = "source_code_leak"

    # API security
    BOLA = "bola"  # Broken Object Level Authorization
    BFLA = "bfla"  # Broken Function Level Authorization
    MASS_ASSIGNMENT = "mass_assignment"
    API_RATE_LIMITING = "api_rate_limiting"

    # Network
    PORT_SCAN = "port_scan"
    SERVICE_ENUMERATION = "service_enumeration"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"


class Priority(str, Enum):
    """Attack step priority levels."""

    CRITICAL = "critical"  # Must test immediately
    HIGH = "high"  # Test in first 25% of budget
    MEDIUM = "medium"  # Test in middle 50% of budget
    LOW = "low"  # Test if time permits
    SKIP = "skip"  # Skip based on target profile


@dataclass
class AttackPlanStep:
    """A single step in the attack plan."""

    step_id: str
    phase: AttackPhase
    target: str  # URL, endpoint, or asset
    attack_type: AttackType
    description: str
    rationale: str
    parameters: dict[str, Any] = field(default_factory=dict)
    prerequisites: list[str] = field(default_factory=list)  # Required step IDs
    priority: Priority = Priority.MEDIUM
    estimated_tokens: int = 5000
    tools_needed: list[str] = field(default_factory=list)
    completed: bool = False
    success: bool | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "phase": self.phase.value,
            "target": self.target,
            "attack_type": self.attack_type.value,
            "description": self.description,
            "rationale": self.rationale,
            "parameters": self.parameters,
            "prerequisites": self.prerequisites,
            "priority": self.priority.value,
            "estimated_tokens": self.estimated_tokens,
            "tools_needed": self.tools_needed,
            "completed": self.completed,
            "success": self.success,
            "findings": self.findings,
        }


@dataclass
class AttackChain:
    """A multi-step attack chain."""

    chain_id: str
    name: str
    steps: list[AttackPlanStep]
    expected_impact: str  # High, Critical, etc.
    prerequisites: list[str] = field(default_factory=list)  # Required findings
    priority: Priority = Priority.MEDIUM
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "steps": [s.to_dict() for s in self.steps],
            "expected_impact": self.expected_impact,
            "prerequisites": self.prerequisites,
            "priority": self.priority.value,
            "rationale": self.rationale,
        }


@dataclass
class AttackPlan:
    """Complete strategic attack plan."""

    plan_id: str
    target: str
    objective: str
    created_at: str
    mode: str  # thorough, ctf, bug_bounty, etc.

    # Steps organized by phase
    reconnaissance_steps: list[AttackPlanStep] = field(default_factory=list)
    enumeration_steps: list[AttackPlanStep] = field(default_factory=list)
    exploitation_steps: list[AttackPlanStep] = field(default_factory=list)
    post_exploitation_steps: list[AttackPlanStep] = field(default_factory=list)

    # Attack chains
    attack_chains: list[AttackChain] = field(default_factory=list)

    # Intelligence
    high_value_targets: list[str] = field(default_factory=list)
    skip_list: list[str] = field(default_factory=list)  # Attacks to skip

    # Budget allocation
    total_estimated_tokens: int = 0
    phases_budget: dict[str, float] = field(default_factory=dict)  # Phase -> % allocation

    # Target profile metadata
    target_profile: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "target": self.target,
            "objective": self.objective,
            "created_at": self.created_at,
            "mode": self.mode,
            "reconnaissance_steps": [s.to_dict() for s in self.reconnaissance_steps],
            "enumeration_steps": [s.to_dict() for s in self.enumeration_steps],
            "exploitation_steps": [s.to_dict() for s in self.exploitation_steps],
            "post_exploitation_steps": [s.to_dict() for s in self.post_exploitation_steps],
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "high_value_targets": self.high_value_targets,
            "skip_list": self.skip_list,
            "total_estimated_tokens": self.total_estimated_tokens,
            "phases_budget": self.phases_budget,
            "target_profile": self.target_profile,
        }

    def get_all_steps(self) -> list[AttackPlanStep]:
        """Get all steps across all phases."""
        return (
            self.reconnaissance_steps
            + self.enumeration_steps
            + self.exploitation_steps
            + self.post_exploitation_steps
        )

    def get_pending_steps(self) -> list[AttackPlanStep]:
        """Get steps not yet completed."""
        return [s for s in self.get_all_steps() if not s.completed]

    def get_completed_steps(self) -> list[AttackPlanStep]:
        """Get completed steps."""
        return [s for s in self.get_all_steps() if s.completed]


class StrategicPlanner:
    """
    Strategic planner for penetration testing assessments.

    Generates comprehensive attack plans before execution, transforming
    Inferno from reactive tool execution to proactive strategic planning.
    """

    def __init__(
        self,
        client: Anthropic | None = None,
        operation_dir: Path | None = None,
    ) -> None:
        """
        Initialize the strategic planner.

        Args:
            client: Anthropic API client for AI-assisted planning
            operation_dir: Directory for saving plans
        """
        self._client = client
        self._operation_dir = operation_dir
        self._current_plan: AttackPlan | None = None

    async def create_plan(
        self,
        target: str,
        objective: str,
        initial_recon: dict[str, Any] | None = None,
        mode: str = "thorough",
        max_tokens: int = 1_000_000,
    ) -> AttackPlan:
        """
        Create a comprehensive strategic attack plan.

        Args:
            target: Target URL or IP address
            objective: Assessment objective
            initial_recon: Optional initial reconnaissance data
            mode: Assessment mode (thorough, ctf, bug_bounty, etc.)
            max_tokens: Maximum token budget

        Returns:
            Complete attack plan
        """
        logger.info(
            "creating_strategic_plan",
            target=target,
            mode=mode,
            max_tokens=max_tokens,
        )

        plan_id = f"plan_{uuid.uuid4().hex[:8]}"

        # Step 1: Profile the target
        profile = await self._profile_target(target, initial_recon)

        # Step 2: Build initial application model
        app_model = await self._build_initial_model(target, initial_recon)

        # Step 3: Identify high-value targets
        high_value_targets = await self._identify_high_value_targets(profile, app_model)

        # Step 4: Generate attack steps
        steps = await self._generate_attack_steps(
            target=target,
            profile=profile,
            app_model=app_model,
            high_value_targets=high_value_targets,
            mode=mode,
        )

        # Step 5: Define attack chains
        attack_chains = await self._define_attack_chains(profile, steps, mode)

        # Step 6: Allocate budget
        budget_allocation = self._allocate_budget(max_tokens, mode)

        # Step 7: Organize steps by phase
        recon_steps = [s for s in steps if s.phase == AttackPhase.RECONNAISSANCE]
        enum_steps = [s for s in steps if s.phase == AttackPhase.ENUMERATION]
        exploit_steps = [s for s in steps if s.phase == AttackPhase.EXPLOITATION]
        post_exploit_steps = [s for s in steps if s.phase == AttackPhase.POST_EXPLOITATION]

        # Step 8: Build the plan
        plan = AttackPlan(
            plan_id=plan_id,
            target=target,
            objective=objective,
            created_at=datetime.now(timezone.utc).isoformat(),
            mode=mode,
            reconnaissance_steps=recon_steps,
            enumeration_steps=enum_steps,
            exploitation_steps=exploit_steps,
            post_exploitation_steps=post_exploit_steps,
            attack_chains=attack_chains,
            high_value_targets=high_value_targets,
            skip_list=profile.get("avoid_vulns", []),
            total_estimated_tokens=sum(s.estimated_tokens for s in steps),
            phases_budget=budget_allocation,
            target_profile=profile,
        )

        self._current_plan = plan
        self._save_plan(plan)

        logger.info(
            "strategic_plan_created",
            plan_id=plan_id,
            total_steps=len(steps),
            chains=len(attack_chains),
            estimated_tokens=plan.total_estimated_tokens,
        )

        return plan

    async def _profile_target(
        self,
        target: str,
        recon_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Profile the target to understand technology, industry, and security posture.

        Args:
            target: Target URL or IP
            recon_data: Optional reconnaissance data

        Returns:
            Target profile dictionary
        """
        logger.info("profiling_target", target=target)

        profile: dict[str, Any] = {
            "url": target,
            "industry": "generic",
            "company_size": "unknown",
            "security_posture": "moderate",
            "tech_stack": [],
            "frameworks": [],
            "waf_detected": None,
            "cdn_detected": None,
            "security_headers": {},
            "attack_surface": [],
            "recommended_approach": "Standard methodology",
            "priority_vulns": ["IDOR", "SQLi", "Auth bypass", "XSS"],
            "avoid_vulns": [],
            "time_investment": {
                "reconnaissance": 25,
                "enumeration": 25,
                "exploitation": 35,
                "post_exploitation": 15,
            },
        }

        if not recon_data:
            return profile

        # Extract industry indicators
        endpoints = recon_data.get("endpoints", [])
        content = recon_data.get("content", "")
        all_text = " ".join(endpoints).lower() + " " + content.lower()

        # Industry detection
        industry_indicators = {
            "fintech": ["payment", "wallet", "transfer", "balance", "transaction", "crypto", "bank"],
            "ecommerce": ["cart", "checkout", "order", "product", "shop", "buy", "price"],
            "saas": ["tenant", "workspace", "organization", "team", "subscription", "api/v"],
            "healthcare": ["patient", "medical", "health", "doctor", "appointment", "prescription"],
            "social": ["profile", "friend", "follow", "message", "post", "feed", "social"],
            "api_service": ["/api/", "/v1/", "/v2/", "graphql", "rest", "swagger", "openapi"],
            "ctf": ["ctf", "flag", "challenge", "hack"],
        }

        best_industry = "generic"
        best_score = 0

        for industry, indicators in industry_indicators.items():
            score = sum(1 for indicator in indicators if indicator in all_text)
            if score > best_score:
                best_score = score
                best_industry = industry

        profile["industry"] = best_industry

        # Industry-specific priorities
        industry_profiles = {
            "fintech": {
                "priority_vulns": ["IDOR", "Auth bypass", "Business logic", "API security", "Rate limiting"],
                "avoid_vulns": ["Generic XSS", "Low-impact info disclosure"],
                "time_investment": {"reconnaissance": 20, "enumeration": 30, "exploitation": 35, "post_exploitation": 15},
            },
            "ecommerce": {
                "priority_vulns": ["Price manipulation", "Cart tampering", "IDOR on orders", "Payment bypass"],
                "avoid_vulns": ["Reflected XSS on static pages"],
                "time_investment": {"reconnaissance": 15, "enumeration": 25, "exploitation": 45, "post_exploitation": 15},
            },
            "saas": {
                "priority_vulns": ["Tenant isolation", "IDOR", "Privilege escalation", "API auth"],
                "avoid_vulns": ["Self-XSS"],
                "time_investment": {"reconnaissance": 20, "enumeration": 30, "exploitation": 35, "post_exploitation": 15},
            },
            "ctf": {
                "priority_vulns": ["SQLi", "LFI/RFI", "Command injection", "SSTI", "Deserialization"],
                "avoid_vulns": [],
                "time_investment": {"reconnaissance": 10, "enumeration": 20, "exploitation": 50, "post_exploitation": 20},
            },
        }

        if best_industry in industry_profiles:
            industry_data = industry_profiles[best_industry]
            profile["priority_vulns"] = industry_data["priority_vulns"]
            profile["avoid_vulns"] = industry_data["avoid_vulns"]
            profile["time_investment"] = industry_data["time_investment"]

        # Detect tech stack
        tech_patterns = {
            "PHP": [r"\.php", r"PHPSESSID"],
            "Python": [r"\.py", r"Flask", r"Django", r"FastAPI"],
            "Node.js": [r"node", r"express", r"npm"],
            "Java": [r"\.jsp", r"JSESSIONID", r"Spring"],
            ".NET": [r"\.aspx", r"ASP\.NET", r"__VIEWSTATE"],
        }

        import re

        for tech_name, patterns in tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    profile["tech_stack"].append(tech_name)
                    break

        # Analyze security headers
        headers = recon_data.get("headers", {})
        if headers:
            headers_lower = {k.lower(): v for k, v in headers.items()}

            security_headers = {
                "strict-transport-security": "strict-transport-security" in headers_lower,
                "content-security-policy": "content-security-policy" in headers_lower,
                "x-frame-options": "x-frame-options" in headers_lower,
                "x-content-type-options": "x-content-type-options" in headers_lower,
            }

            profile["security_headers"] = security_headers

            # Determine security posture
            header_count = sum(security_headers.values())
            if header_count >= 3:
                profile["security_posture"] = "strong"
                profile["recommended_approach"] = "Focus on business logic, avoid noisy scans"
            elif header_count >= 1:
                profile["security_posture"] = "moderate"
                profile["recommended_approach"] = "Balanced approach with WAF bypass ready"
            else:
                profile["security_posture"] = "weak"
                profile["recommended_approach"] = "Wide attack surface, try everything"

        logger.info("target_profile_created", industry=best_industry, security_posture=profile["security_posture"])

        return profile

    async def _build_initial_model(
        self,
        target: str,
        recon_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Build an initial ApplicationModel from reconnaissance data.

        Args:
            target: Target URL or IP
            recon_data: Optional reconnaissance data

        Returns:
            Application model dictionary
        """
        logger.info("building_application_model", target=target)

        model: dict[str, Any] = {
            "target": target,
            "endpoints": [],
            "parameters": {},
            "authentication": {
                "mechanisms": [],
                "session_management": "unknown",
            },
            "entry_points": [],
            "data_flows": [],
            "trust_boundaries": [],
        }

        if not recon_data:
            return model

        # Extract endpoints
        model["endpoints"] = recon_data.get("endpoints", [])

        # Identify authentication mechanisms
        content = recon_data.get("content", "").lower()
        headers = recon_data.get("headers", {})

        auth_indicators = {
            "JWT": ["jwt", "bearer", "authorization"],
            "Cookie-based": ["set-cookie", "session", "phpsessid"],
            "OAuth": ["oauth", "authorize", "token"],
            "API Key": ["api_key", "x-api-key"],
        }

        for auth_type, indicators in auth_indicators.items():
            if any(indicator in content or indicator in str(headers).lower() for indicator in indicators):
                model["authentication"]["mechanisms"].append(auth_type)

        # Identify entry points (forms, APIs, upload points)
        if "form" in content or "input" in content:
            model["entry_points"].append("HTML Forms")

        if any(ep for ep in model["endpoints"] if "/api/" in ep or "/v1/" in ep):
            model["entry_points"].append("REST API")

        if "graphql" in content:
            model["entry_points"].append("GraphQL")

        if "upload" in content or "file" in content:
            model["entry_points"].append("File Upload")

        logger.info(
            "application_model_built",
            endpoints=len(model["endpoints"]),
            auth_mechanisms=len(model["authentication"]["mechanisms"]),
            entry_points=len(model["entry_points"]),
        )

        return model

    async def _identify_high_value_targets(
        self,
        profile: dict[str, Any],
        app_model: dict[str, Any],
    ) -> list[str]:
        """
        Identify high-value targets based on profile and application model.

        Args:
            profile: Target profile
            app_model: Application model

        Returns:
            List of high-value target identifiers
        """
        logger.info("identifying_high_value_targets")

        high_value = []

        # Industry-specific high-value targets
        industry = profile.get("industry", "generic")

        industry_targets = {
            "fintech": ["admin", "transaction", "wallet", "payment", "balance", "transfer"],
            "ecommerce": ["checkout", "payment", "cart", "order", "admin"],
            "saas": ["admin", "organization", "workspace", "billing", "api"],
            "healthcare": ["patient", "medical", "appointment", "prescription"],
            "social": ["admin", "profile", "message", "private"],
            "api_service": ["admin", "user", "auth", "token"],
            "ctf": ["flag", "admin", "upload", "exec"],
        }

        targets = industry_targets.get(industry, ["admin", "user", "api", "auth"])

        # Find endpoints matching high-value patterns
        endpoints = app_model.get("endpoints", [])
        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()
            for target_pattern in targets:
                if target_pattern in endpoint_lower:
                    if endpoint not in high_value:
                        high_value.append(endpoint)
                    break

        # Authentication endpoints are always high-value
        for endpoint in endpoints:
            if any(keyword in endpoint.lower() for keyword in ["login", "auth", "signin", "oauth"]):
                if endpoint not in high_value:
                    high_value.append(endpoint)

        logger.info("high_value_targets_identified", count=len(high_value))

        return high_value

    async def _generate_attack_steps(
        self,
        target: str,
        profile: dict[str, Any],
        app_model: dict[str, Any],
        high_value_targets: list[str],
        mode: str,
    ) -> list[AttackPlanStep]:
        """
        Generate prioritized attack steps based on target profile.

        Args:
            target: Target URL or IP
            profile: Target profile
            app_model: Application model
            high_value_targets: List of high-value targets
            mode: Assessment mode

        Returns:
            List of attack plan steps
        """
        logger.info("generating_attack_steps", mode=mode)

        steps: list[AttackPlanStep] = []
        step_counter = 0

        def create_step(
            phase: AttackPhase,
            attack_type: AttackType,
            description: str,
            rationale: str,
            priority: Priority = Priority.MEDIUM,
            estimated_tokens: int = 5000,
            tools: list[str] | None = None,
            target_endpoint: str | None = None,
        ) -> AttackPlanStep:
            nonlocal step_counter
            step_counter += 1
            return AttackPlanStep(
                step_id=f"step_{step_counter:03d}",
                phase=phase,
                target=target_endpoint or target,
                attack_type=attack_type,
                description=description,
                rationale=rationale,
                priority=priority,
                estimated_tokens=estimated_tokens,
                tools_needed=tools or [],
            )

        # RECONNAISSANCE PHASE
        # Essential recon steps
        steps.append(
            create_step(
                phase=AttackPhase.RECONNAISSANCE,
                attack_type=AttackType.PORT_SCAN,
                description="Comprehensive port scan to identify all services",
                rationale="Map attack surface and identify all potential entry points",
                priority=Priority.HIGH,
                estimated_tokens=3000,
                tools=["nmap_scan"],
            )
        )

        steps.append(
            create_step(
                phase=AttackPhase.RECONNAISSANCE,
                attack_type=AttackType.SERVICE_ENUMERATION,
                description="Enumerate web services and technology stack",
                rationale="Identify frameworks, CMS, and versions for CVE exploitation",
                priority=Priority.HIGH,
                estimated_tokens=4000,
                tools=["http_request", "browser"],
            )
        )

        # Subdomain enumeration (lower priority for single targets)
        if mode != "ctf":
            steps.append(
                create_step(
                    phase=AttackPhase.RECONNAISSANCE,
                    attack_type=AttackType.SUBDOMAIN_ENUMERATION,
                    description="Enumerate subdomains for additional attack surface",
                    rationale="Find forgotten or development subdomains with weaker security",
                    priority=Priority.MEDIUM,
                    estimated_tokens=5000,
                    tools=["shell"],  # Using external tools via shell
                )
            )

        # ENUMERATION PHASE
        # Directory enumeration
        steps.append(
            create_step(
                phase=AttackPhase.ENUMERATION,
                attack_type=AttackType.INFO_DISCLOSURE,
                description="Directory and file enumeration",
                rationale="Discover hidden endpoints, admin panels, and sensitive files",
                priority=Priority.HIGH,
                estimated_tokens=6000,
                tools=["gobuster", "endpoint_discovery"],
            )
        )

        # Parameter mining on high-value targets
        for hvt in high_value_targets[:3]:  # Limit to top 3
            steps.append(
                create_step(
                    phase=AttackPhase.ENUMERATION,
                    attack_type=AttackType.INFO_DISCLOSURE,
                    description=f"Parameter mining on {hvt}",
                    rationale="Discover hidden parameters that may bypass security controls",
                    priority=Priority.HIGH,
                    estimated_tokens=4000,
                    tools=["parameter_miner"],
                    target_endpoint=hvt,
                )
            )

        # EXPLOITATION PHASE - Prioritized by target profile
        priority_vulns = profile.get("priority_vulns", [])
        avoid_vulns = profile.get("avoid_vulns", [])

        # Map priority vulns to attack types
        vuln_mapping = {
            "IDOR": AttackType.IDOR,
            "SQLi": AttackType.SQLI,
            "Auth bypass": AttackType.AUTH_BYPASS,
            "XSS": AttackType.XSS,
            "SSRF": AttackType.SSRF,
            "Business logic": AttackType.BUSINESS_LOGIC,
            "API security": AttackType.BOLA,
            "Rate limiting": AttackType.API_RATE_LIMITING,
            "Price manipulation": AttackType.PRICE_MANIPULATION,
            "Cart tampering": AttackType.BUSINESS_LOGIC,
            "Payment bypass": AttackType.BUSINESS_LOGIC,
            "Tenant isolation": AttackType.BOLA,
            "Privilege escalation": AttackType.PRIVILEGE_ESCALATION,
            "LFI/RFI": AttackType.LFI,
            "Command injection": AttackType.COMMAND_INJECTION,
            "SSTI": AttackType.SSTI,
            "Deserialization": AttackType.DESERIALIZATION,
        }

        # Add priority vulnerability tests
        for i, vuln in enumerate(priority_vulns):
            attack_type = vuln_mapping.get(vuln)
            if not attack_type:
                continue

            priority = Priority.CRITICAL if i < 2 else Priority.HIGH

            # IDOR testing
            if attack_type == AttackType.IDOR:
                steps.append(
                    create_step(
                        phase=AttackPhase.EXPLOITATION,
                        attack_type=attack_type,
                        description=f"Test for IDOR vulnerabilities on {vuln} endpoints",
                        rationale=f"Profile indicates {vuln} is high-value for this {profile['industry']} target",
                        priority=priority,
                        estimated_tokens=7000,
                        tools=["idor_scanner", "http_request"],
                    )
                )

            # SQL Injection
            elif attack_type == AttackType.SQLI:
                steps.append(
                    create_step(
                        phase=AttackPhase.EXPLOITATION,
                        attack_type=attack_type,
                        description="SQL injection testing on input parameters",
                        rationale=f"High-priority for {profile['industry']} targets due to credential/data access",
                        priority=priority,
                        estimated_tokens=8000,
                        tools=["sqlmap", "http_request"],
                    )
                )

            # Auth bypass
            elif attack_type == AttackType.AUTH_BYPASS:
                steps.append(
                    create_step(
                        phase=AttackPhase.EXPLOITATION,
                        attack_type=attack_type,
                        description="Authentication bypass testing",
                        rationale="Direct access to protected functionality without credentials",
                        priority=priority,
                        estimated_tokens=6000,
                        tools=["auth_analyzer", "http_request"],
                    )
                )

            # Business logic
            elif attack_type == AttackType.BUSINESS_LOGIC:
                steps.append(
                    create_step(
                        phase=AttackPhase.EXPLOITATION,
                        attack_type=attack_type,
                        description="Business logic vulnerability testing",
                        rationale=f"Critical for {profile['industry']} - test workflow bypasses and race conditions",
                        priority=priority,
                        estimated_tokens=9000,
                        tools=["business_logic_tester", "race_condition"],
                    )
                )

            # Generic exploitation for other types
            else:
                steps.append(
                    create_step(
                        phase=AttackPhase.EXPLOITATION,
                        attack_type=attack_type,
                        description=f"{vuln} vulnerability testing",
                        rationale=f"Priority vulnerability for {profile['industry']} targets",
                        priority=priority,
                        estimated_tokens=6000,
                        tools=["http_request"],
                    )
                )

        # POST-EXPLOITATION PHASE
        # Only if mode is thorough or red_team
        if mode in ["thorough", "red_team"]:
            steps.append(
                create_step(
                    phase=AttackPhase.POST_EXPLOITATION,
                    attack_type=AttackType.PRIVILEGE_ESCALATION,
                    description="Privilege escalation testing",
                    rationale="Escalate from user to admin access",
                    priority=Priority.MEDIUM,
                    estimated_tokens=7000,
                    tools=["http_request", "auth_analyzer"],
                )
            )

            steps.append(
                create_step(
                    phase=AttackPhase.POST_EXPLOITATION,
                    attack_type=AttackType.CREDENTIAL_LEAK,
                    description="Credential extraction and lateral movement",
                    rationale="Extract credentials for access to additional systems",
                    priority=Priority.MEDIUM,
                    estimated_tokens=6000,
                    tools=["http_request", "shell"],
                )
            )

        # CTF mode - add aggressive RCE-focused steps
        if mode == "ctf":
            steps.append(
                create_step(
                    phase=AttackPhase.EXPLOITATION,
                    attack_type=AttackType.COMMAND_INJECTION,
                    description="Command injection testing on all inputs",
                    rationale="CTF targets often have command injection for shell access",
                    priority=Priority.CRITICAL,
                    estimated_tokens=8000,
                    tools=["http_request", "shell"],
                )
            )

            steps.append(
                create_step(
                    phase=AttackPhase.EXPLOITATION,
                    attack_type=AttackType.FILE_UPLOAD,
                    description="File upload bypass testing",
                    rationale="Common CTF RCE vector via webshell upload",
                    priority=Priority.CRITICAL,
                    estimated_tokens=7000,
                    tools=["http_request"],
                )
            )

        logger.info("attack_steps_generated", total=len(steps), by_phase={
            "reconnaissance": len([s for s in steps if s.phase == AttackPhase.RECONNAISSANCE]),
            "enumeration": len([s for s in steps if s.phase == AttackPhase.ENUMERATION]),
            "exploitation": len([s for s in steps if s.phase == AttackPhase.EXPLOITATION]),
            "post_exploitation": len([s for s in steps if s.phase == AttackPhase.POST_EXPLOITATION]),
        })

        return steps

    async def _define_attack_chains(
        self,
        profile: dict[str, Any],
        steps: list[AttackPlanStep],
        mode: str,
    ) -> list[AttackChain]:
        """
        Define attack chains based on target profile.

        Args:
            profile: Target profile
            steps: Attack plan steps
            mode: Assessment mode

        Returns:
            List of attack chains
        """
        logger.info("defining_attack_chains", mode=mode)

        chains: list[AttackChain] = []

        # Find steps by attack type
        steps_by_type = {}
        for step in steps:
            if step.attack_type not in steps_by_type:
                steps_by_type[step.attack_type] = []
            steps_by_type[step.attack_type].append(step)

        # Chain 1: SQLi → Credential Dump → Auth Bypass → RCE
        if AttackType.SQLI in steps_by_type and AttackType.AUTH_BYPASS in steps_by_type:
            chain_steps = []

            if AttackType.SQLI in steps_by_type:
                chain_steps.append(steps_by_type[AttackType.SQLI][0])

            # Create credential extraction step
            chain_steps.append(
                AttackPlanStep(
                    step_id=f"chain1_cred_extract",
                    phase=AttackPhase.EXPLOITATION,
                    target=profile["url"],
                    attack_type=AttackType.CREDENTIAL_LEAK,
                    description="Extract credentials from database via SQLi",
                    rationale="Use SQLi to dump admin credentials",
                    priority=Priority.HIGH,
                    estimated_tokens=5000,
                    tools=["sqlmap"],
                    prerequisites=[chain_steps[0].step_id],
                )
            )

            if AttackType.AUTH_BYPASS in steps_by_type:
                auth_step = steps_by_type[AttackType.AUTH_BYPASS][0]
                auth_step.prerequisites = [chain_steps[-1].step_id]
                chain_steps.append(auth_step)

            chains.append(
                AttackChain(
                    chain_id="chain_sqli_to_rce",
                    name="SQL Injection to RCE",
                    steps=chain_steps,
                    expected_impact="Critical",
                    prerequisites=["SQLi vulnerability"],
                    priority=Priority.CRITICAL,
                    rationale="Classic attack chain from database access to remote code execution",
                )
            )

        # Chain 2: IDOR → PII Leak → Account Takeover
        if AttackType.IDOR in steps_by_type:
            idor_step = steps_by_type[AttackType.IDOR][0]

            chain_steps = [idor_step]

            # Add session hijack step
            chain_steps.append(
                AttackPlanStep(
                    step_id=f"chain2_session_hijack",
                    phase=AttackPhase.EXPLOITATION,
                    target=profile["url"],
                    attack_type=AttackType.SESSION_HIJACK,
                    description="Hijack user session via IDOR-leaked session data",
                    rationale="Use IDOR to access session tokens or reset tokens",
                    priority=Priority.HIGH,
                    estimated_tokens=6000,
                    tools=["http_request"],
                    prerequisites=[idor_step.step_id],
                )
            )

            chains.append(
                AttackChain(
                    chain_id="chain_idor_to_takeover",
                    name="IDOR to Account Takeover",
                    steps=chain_steps,
                    expected_impact="High",
                    prerequisites=["IDOR vulnerability"],
                    priority=Priority.HIGH,
                    rationale=f"High-value for {profile['industry']} targets",
                )
            )

        # Chain 3: SSRF → Internal Access → Credential Leak
        if AttackType.SSRF in steps_by_type:
            ssrf_step = steps_by_type[AttackType.SSRF][0]

            chain_steps = [ssrf_step]

            # Add cloud metadata access
            chain_steps.append(
                AttackPlanStep(
                    step_id=f"chain3_cloud_metadata",
                    phase=AttackPhase.EXPLOITATION,
                    target=profile["url"],
                    attack_type=AttackType.INFO_DISCLOSURE,
                    description="Access cloud metadata via SSRF",
                    rationale="Extract IAM credentials from metadata service",
                    priority=Priority.CRITICAL,
                    estimated_tokens=5000,
                    tools=["http_request", "ssrf_detector"],
                    prerequisites=[ssrf_step.step_id],
                )
            )

            chains.append(
                AttackChain(
                    chain_id="chain_ssrf_to_cloud",
                    name="SSRF to Cloud Compromise",
                    steps=chain_steps,
                    expected_impact="Critical",
                    prerequisites=["SSRF vulnerability", "Cloud environment"],
                    priority=Priority.CRITICAL,
                    rationale="Direct path to infrastructure compromise",
                )
            )

        logger.info("attack_chains_defined", count=len(chains))

        return chains

    def _allocate_budget(
        self,
        total_tokens: int,
        mode: str,
    ) -> dict[str, float]:
        """
        Allocate token budget across assessment phases.

        Args:
            total_tokens: Total token budget
            mode: Assessment mode

        Returns:
            Dictionary mapping phase to percentage allocation
        """
        logger.info("allocating_budget", total_tokens=total_tokens, mode=mode)

        # Mode-specific allocations
        allocations = {
            "ctf": {
                "reconnaissance": 0.10,  # 10% - quick recon
                "enumeration": 0.20,  # 20% - find entry points
                "exploitation": 0.50,  # 50% - aggressive exploitation
                "post_exploitation": 0.15,  # 15% - shell access
                "validation": 0.05,  # 5% - minimal validation
            },
            "bug_bounty": {
                "reconnaissance": 0.25,  # 25% - thorough recon
                "enumeration": 0.25,  # 25% - find all endpoints
                "exploitation": 0.35,  # 35% - focused exploitation
                "post_exploitation": 0.10,  # 10% - limited post-ex
                "validation": 0.05,  # 5% - validate findings
            },
            "thorough": {
                "reconnaissance": 0.25,  # 25% - comprehensive recon
                "enumeration": 0.25,  # 25% - exhaustive enumeration
                "exploitation": 0.30,  # 30% - systematic exploitation
                "post_exploitation": 0.15,  # 15% - privilege escalation
                "validation": 0.05,  # 5% - thorough validation
            },
            "red_team": {
                "reconnaissance": 0.20,  # 20% - targeted recon
                "enumeration": 0.20,  # 20% - stealthy enumeration
                "exploitation": 0.30,  # 30% - exploitation
                "post_exploitation": 0.25,  # 25% - lateral movement
                "validation": 0.05,  # 5% - validate access
            },
        }

        budget = allocations.get(mode, allocations["thorough"])

        logger.info("budget_allocated", allocation=budget)

        return budget

    def mark_step_complete(
        self,
        step_id: str,
        success: bool,
        findings: list[dict[str, Any]] | None = None,
    ) -> None:
        """
        Mark a step as completed.

        Args:
            step_id: Step identifier
            success: Whether the step succeeded
            findings: Optional findings from the step
        """
        if not self._current_plan:
            logger.warning("no_current_plan", step_id=step_id)
            return

        for step in self._current_plan.get_all_steps():
            if step.step_id == step_id:
                step.completed = True
                step.success = success
                if findings:
                    step.findings = findings

                logger.info(
                    "step_marked_complete",
                    step_id=step_id,
                    success=success,
                    findings_count=len(findings) if findings else 0,
                )

                self._save_plan(self._current_plan)
                return

        logger.warning("step_not_found", step_id=step_id)

    def get_next_steps(
        self,
        max_count: int = 3,
    ) -> list[AttackPlanStep]:
        """
        Get the next steps to execute based on priorities and prerequisites.

        Args:
            max_count: Maximum number of steps to return

        Returns:
            List of next steps to execute
        """
        if not self._current_plan:
            return []

        pending = self._current_plan.get_pending_steps()
        completed_ids = {s.step_id for s in self._current_plan.get_completed_steps()}

        # Filter to steps with prerequisites met
        executable = []
        for step in pending:
            if not step.prerequisites or all(prereq in completed_ids for prereq in step.prerequisites):
                executable.append(step)

        # Sort by priority
        priority_order = {
            Priority.CRITICAL: 0,
            Priority.HIGH: 1,
            Priority.MEDIUM: 2,
            Priority.LOW: 3,
            Priority.SKIP: 4,
        }

        executable.sort(key=lambda s: priority_order.get(s.priority, 999))

        return executable[:max_count]

    def update_priorities(
        self,
        new_findings: list[dict[str, Any]],
    ) -> None:
        """
        Dynamically update step priorities based on new findings.

        Args:
            new_findings: New findings to consider
        """
        if not self._current_plan:
            return

        logger.info("updating_priorities", findings_count=len(new_findings))

        # Upgrade priorities if high-value findings discovered
        for finding in new_findings:
            severity = finding.get("severity", "low")
            vuln_type = finding.get("vuln_type", "")

            # If we found SQLi, upgrade auth bypass steps to critical
            if vuln_type == "sqli" and severity in ["high", "critical"]:
                for step in self._current_plan.get_all_steps():
                    if step.attack_type == AttackType.AUTH_BYPASS and not step.completed:
                        step.priority = Priority.CRITICAL
                        logger.info("priority_upgraded", step_id=step.step_id, reason="SQLi found - credential dump likely")

            # If we found SSRF, upgrade cloud metadata steps
            if vuln_type == "ssrf":
                for step in self._current_plan.get_all_steps():
                    if step.attack_type == AttackType.INFO_DISCLOSURE and "metadata" in step.description.lower():
                        step.priority = Priority.CRITICAL
                        logger.info("priority_upgraded", step_id=step.step_id, reason="SSRF found - cloud access possible")

        self._save_plan(self._current_plan)

    def get_progress_report(self) -> str:
        """
        Generate a progress report for the current plan.

        Returns:
            Formatted progress report
        """
        if not self._current_plan:
            return "No active plan."

        total_steps = len(self._current_plan.get_all_steps())
        completed = len(self._current_plan.get_completed_steps())
        pending = len(self._current_plan.get_pending_steps())

        successful = sum(1 for s in self._current_plan.get_completed_steps() if s.success)
        failed = sum(1 for s in self._current_plan.get_completed_steps() if s.success is False)

        total_findings = sum(len(s.findings) for s in self._current_plan.get_completed_steps())

        report = [
            f"# Strategic Plan Progress: {self._current_plan.plan_id}",
            "",
            f"**Target**: {self._current_plan.target}",
            f"**Mode**: {self._current_plan.mode}",
            f"**Created**: {self._current_plan.created_at}",
            "",
            "## Overall Progress",
            f"- **Total Steps**: {total_steps}",
            f"- **Completed**: {completed} ({completed/max(total_steps, 1)*100:.1f}%)",
            f"- **Pending**: {pending}",
            f"- **Successful**: {successful}",
            f"- **Failed**: {failed}",
            f"- **Total Findings**: {total_findings}",
            "",
            "## Progress by Phase",
        ]

        for phase in [AttackPhase.RECONNAISSANCE, AttackPhase.ENUMERATION, AttackPhase.EXPLOITATION, AttackPhase.POST_EXPLOITATION]:
            phase_steps = [s for s in self._current_plan.get_all_steps() if s.phase == phase]
            phase_completed = sum(1 for s in phase_steps if s.completed)
            phase_total = len(phase_steps)

            if phase_total > 0:
                report.append(f"- **{phase.value.title()}**: {phase_completed}/{phase_total} ({phase_completed/phase_total*100:.0f}%)")

        # Next steps
        next_steps = self.get_next_steps(max_count=3)
        if next_steps:
            report.append("")
            report.append("## Next Recommended Steps")
            for i, step in enumerate(next_steps, 1):
                report.append(f"{i}. [{step.priority.value.upper()}] {step.description}")

        # Attack chains
        if self._current_plan.attack_chains:
            report.append("")
            report.append("## Attack Chains")
            for chain in self._current_plan.attack_chains:
                completed_chain_steps = sum(1 for s in chain.steps if s.completed)
                total_chain_steps = len(chain.steps)
                report.append(f"- **{chain.name}**: {completed_chain_steps}/{total_chain_steps} steps")

        return "\n".join(report)

    def _save_plan(self, plan: AttackPlan) -> None:
        """Save plan to disk."""
        if not self._operation_dir:
            return

        plan_path = self._operation_dir / f"{plan.plan_id}.json"
        try:
            plan_path.write_text(json.dumps(plan.to_dict(), indent=2))
            logger.info("plan_saved", plan_id=plan.plan_id, path=str(plan_path))
        except Exception as e:
            logger.error("failed_to_save_plan", error=str(e))

    def load_plan(self, plan_id: str) -> AttackPlan | None:
        """
        Load a plan from disk.

        Args:
            plan_id: Plan identifier

        Returns:
            Loaded plan or None if not found
        """
        if not self._operation_dir:
            return None

        plan_path = self._operation_dir / f"{plan_id}.json"
        if not plan_path.exists():
            logger.warning("plan_not_found", plan_id=plan_id)
            return None

        try:
            data = json.loads(plan_path.read_text())

            # Reconstruct steps
            def dict_to_step(step_dict: dict[str, Any]) -> AttackPlanStep:
                return AttackPlanStep(
                    step_id=step_dict["step_id"],
                    phase=AttackPhase(step_dict["phase"]),
                    target=step_dict["target"],
                    attack_type=AttackType(step_dict["attack_type"]),
                    description=step_dict["description"],
                    rationale=step_dict["rationale"],
                    parameters=step_dict.get("parameters", {}),
                    prerequisites=step_dict.get("prerequisites", []),
                    priority=Priority(step_dict["priority"]),
                    estimated_tokens=step_dict.get("estimated_tokens", 5000),
                    tools_needed=step_dict.get("tools_needed", []),
                    completed=step_dict.get("completed", False),
                    success=step_dict.get("success"),
                    findings=step_dict.get("findings", []),
                )

            # Reconstruct chains
            def dict_to_chain(chain_dict: dict[str, Any]) -> AttackChain:
                return AttackChain(
                    chain_id=chain_dict["chain_id"],
                    name=chain_dict["name"],
                    steps=[dict_to_step(s) for s in chain_dict["steps"]],
                    expected_impact=chain_dict["expected_impact"],
                    prerequisites=chain_dict.get("prerequisites", []),
                    priority=Priority(chain_dict["priority"]),
                    rationale=chain_dict.get("rationale", ""),
                )

            plan = AttackPlan(
                plan_id=data["plan_id"],
                target=data["target"],
                objective=data["objective"],
                created_at=data["created_at"],
                mode=data["mode"],
                reconnaissance_steps=[dict_to_step(s) for s in data.get("reconnaissance_steps", [])],
                enumeration_steps=[dict_to_step(s) for s in data.get("enumeration_steps", [])],
                exploitation_steps=[dict_to_step(s) for s in data.get("exploitation_steps", [])],
                post_exploitation_steps=[dict_to_step(s) for s in data.get("post_exploitation_steps", [])],
                attack_chains=[dict_to_chain(c) for c in data.get("attack_chains", [])],
                high_value_targets=data.get("high_value_targets", []),
                skip_list=data.get("skip_list", []),
                total_estimated_tokens=data.get("total_estimated_tokens", 0),
                phases_budget=data.get("phases_budget", {}),
                target_profile=data.get("target_profile"),
            )

            self._current_plan = plan
            logger.info("plan_loaded", plan_id=plan_id)
            return plan

        except Exception as e:
            logger.error("failed_to_load_plan", plan_id=plan_id, error=str(e))
            return None
