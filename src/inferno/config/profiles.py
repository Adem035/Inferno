"""
Configuration profiles for different assessment scenarios.

Supports:
- Bug bounty program presets (HackerOne, Bugcrowd)
- Assessment modes (web, network, cloud)
- Custom user profiles
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class AssessmentProfile:
    """Assessment configuration profile."""

    name: str
    description: str = ""
    mode: str = "web"  # web, network, cloud, api
    max_turns: int = 500
    persona: str = "thorough"
    auto_continue: bool = True
    max_continuations: int = 5
    rules: list[str] = field(default_factory=list)
    scope_inclusions: list[str] = field(default_factory=list)
    scope_exclusions: list[str] = field(default_factory=list)

    # Bug bounty specific
    program_type: str | None = None  # hackerone, bugcrowd, intigriti
    program_handle: str | None = None
    rate_limit_rpm: int = 60  # Requests per minute

    # Scanning preferences
    aggressive: bool = False
    stealth: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize profile to dict."""
        return {
            "name": self.name,
            "description": self.description,
            "mode": self.mode,
            "max_turns": self.max_turns,
            "persona": self.persona,
            "auto_continue": self.auto_continue,
            "max_continuations": self.max_continuations,
            "rules": self.rules,
            "scope_inclusions": self.scope_inclusions,
            "scope_exclusions": self.scope_exclusions,
            "program_type": self.program_type,
            "program_handle": self.program_handle,
            "rate_limit_rpm": self.rate_limit_rpm,
            "aggressive": self.aggressive,
            "stealth": self.stealth,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssessmentProfile:
        """Deserialize profile from dict."""
        return cls(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            mode=data.get("mode", "web"),
            max_turns=data.get("max_turns", 500),
            persona=data.get("persona", "thorough"),
            auto_continue=data.get("auto_continue", True),
            max_continuations=data.get("max_continuations", 5),
            rules=data.get("rules", []),
            scope_inclusions=data.get("scope_inclusions", []),
            scope_exclusions=data.get("scope_exclusions", []),
            program_type=data.get("program_type"),
            program_handle=data.get("program_handle"),
            rate_limit_rpm=data.get("rate_limit_rpm", 60),
            aggressive=data.get("aggressive", False),
            stealth=data.get("stealth", False),
        )


class ProfileManager:
    """Manage assessment profiles."""

    def __init__(self, profiles_dir: Path | None = None):
        self.profiles_dir = profiles_dir or Path.home() / ".config/inferno/profiles"
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self._builtin_profiles = self._load_builtin_profiles()

    def _load_builtin_profiles(self) -> dict[str, AssessmentProfile]:
        """Load built-in profiles."""
        return {
            "hackerone-default": AssessmentProfile(
                name="hackerone-default",
                description="Standard HackerOne bug bounty assessment",
                mode="web",
                max_turns=500,
                persona="thorough",
                rules=[
                    "Stay within defined scope",
                    "No destructive testing (DoS, data deletion)",
                    "Report high/critical findings immediately",
                    "Follow responsible disclosure",
                    "Document all findings with PoC",
                ],
                rate_limit_rpm=60,
                program_type="hackerone",
            ),
            "bugcrowd-default": AssessmentProfile(
                name="bugcrowd-default",
                description="Standard Bugcrowd bug bounty assessment",
                mode="web",
                max_turns=500,
                persona="thorough",
                rules=[
                    "Stay within defined scope",
                    "No destructive testing",
                    "Follow Bugcrowd disclosure policy",
                    "Document reproduction steps clearly",
                ],
                rate_limit_rpm=60,
                program_type="bugcrowd",
            ),
            "pentest-stealth": AssessmentProfile(
                name="pentest-stealth",
                description="Stealthy penetration testing",
                mode="network",
                max_turns=800,
                persona="stealthy",
                stealth=True,
                rules=[
                    "Low and slow approach",
                    "Avoid detection by IDS/IPS",
                    "Use evasion techniques",
                    "Minimize network noise",
                ],
                rate_limit_rpm=10,
            ),
            "api-security": AssessmentProfile(
                name="api-security",
                description="API security assessment",
                mode="api",
                max_turns=400,
                persona="thorough",
                rules=[
                    "Test all API endpoints",
                    "Check authentication/authorization",
                    "Test rate limiting",
                    "Look for IDOR vulnerabilities",
                    "Test input validation",
                ],
            ),
            "quick-recon": AssessmentProfile(
                name="quick-recon",
                description="Quick reconnaissance only",
                mode="web",
                max_turns=50,
                persona="recon",
                rules=[
                    "Gather information only",
                    "No active exploitation",
                    "Map attack surface",
                    "Identify technologies",
                ],
            ),
        }

    def create_profile(self, profile: AssessmentProfile) -> None:
        """Save a custom profile."""
        path = self.profiles_dir / f"{profile.name}.json"
        path.write_text(json.dumps(profile.to_dict(), indent=2))
        logger.info("profile_created", name=profile.name, path=str(path))

    def load_profile(self, name: str) -> AssessmentProfile:
        """Load a profile by name (builtin or custom)."""
        # Check builtin first
        if name in self._builtin_profiles:
            return self._builtin_profiles[name]

        # Check custom profiles
        path = self.profiles_dir / f"{name}.json"
        if not path.exists():
            raise ValueError(f"Profile not found: {name}")

        data = json.loads(path.read_text())
        return AssessmentProfile.from_dict(data)

    def list_profiles(self) -> list[tuple[str, str, bool]]:
        """List all profiles (name, description, is_builtin)."""
        profiles = []

        # Builtin profiles
        for name, profile in self._builtin_profiles.items():
            profiles.append((name, profile.description, True))

        # Custom profiles
        for path in self.profiles_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text())
                profiles.append((
                    data.get("name", path.stem),
                    data.get("description", ""),
                    False,
                ))
            except Exception:
                continue

        return profiles

    def delete_profile(self, name: str) -> bool:
        """Delete a custom profile."""
        if name in self._builtin_profiles:
            raise ValueError(f"Cannot delete builtin profile: {name}")

        path = self.profiles_dir / f"{name}.json"
        if path.exists():
            path.unlink()
            logger.info("profile_deleted", name=name)
            return True
        return False

    def get_profile_for_program(
        self,
        platform: Literal["hackerone", "bugcrowd", "intigriti"],
        program_handle: str,
    ) -> AssessmentProfile:
        """Get or create a profile for a bug bounty program."""
        profile_name = f"{platform}-{program_handle}"

        # Check if custom profile exists
        try:
            return self.load_profile(profile_name)
        except ValueError:
            pass

        # Create from platform default
        base_profile = self._builtin_profiles.get(
            f"{platform}-default",
            self._builtin_profiles["hackerone-default"],
        )

        return AssessmentProfile(
            name=profile_name,
            description=f"{platform.title()} program: {program_handle}",
            mode=base_profile.mode,
            max_turns=base_profile.max_turns,
            persona=base_profile.persona,
            rules=base_profile.rules.copy(),
            program_type=platform,
            program_handle=program_handle,
            rate_limit_rpm=base_profile.rate_limit_rpm,
        )


# Singleton instance
_profile_manager: ProfileManager | None = None


def get_profile_manager() -> ProfileManager:
    """Get or create the profile manager singleton."""
    global _profile_manager
    if _profile_manager is None:
        _profile_manager = ProfileManager()
    return _profile_manager
