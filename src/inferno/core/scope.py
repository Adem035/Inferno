"""
Scope Management for Inferno.

This module provides comprehensive scope management to ensure
assessments stay within authorized boundaries.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


class ScopeViolation(Exception):
    """Raised when an action would violate scope."""
    pass


class ScopeAction(str, Enum):
    """Actions that can be taken when scope is violated."""
    BLOCK = "block"  # Block the action completely
    WARN = "warn"  # Warn but allow
    LOG = "log"  # Just log the violation
    ALLOW = "allow"  # Allow (for testing/CTF mode)


@dataclass
class ScopeRule:
    """A single scope rule."""
    pattern: str
    rule_type: str  # "include" or "exclude"
    resource_type: str  # "url", "domain", "ip", "port", "path"
    reason: str | None = None

    def matches(self, value: str) -> bool:
        """Check if value matches this rule."""
        if self.resource_type == "ip":
            return self._match_ip(value)
        elif self.resource_type == "domain":
            return self._match_domain(value)
        elif self.resource_type == "url":
            return self._match_url(value)
        elif self.resource_type == "path":
            return self._match_path(value)
        elif self.resource_type == "port":
            return self._match_port(value)
        else:
            return fnmatch.fnmatch(value.lower(), self.pattern.lower())

    def _match_ip(self, value: str) -> bool:
        """Match IP address or CIDR range."""
        try:
            # Check if pattern is CIDR
            if "/" in self.pattern:
                network = ipaddress.ip_network(self.pattern, strict=False)
                ip = ipaddress.ip_address(value)
                return ip in network
            else:
                # Exact match or wildcard
                return fnmatch.fnmatch(value, self.pattern)
        except ValueError:
            return False

    def _match_domain(self, value: str) -> bool:
        """Match domain including subdomains."""
        value = value.lower()
        pattern = self.pattern.lower()

        # Exact match
        if value == pattern:
            return True

        # Wildcard subdomain match (*.example.com)
        if pattern.startswith("*."):
            base_domain = pattern[2:]
            return value == base_domain or value.endswith("." + base_domain)

        # Check if value is subdomain of pattern
        if value.endswith("." + pattern):
            return True

        return fnmatch.fnmatch(value, pattern)

    def _match_url(self, value: str) -> bool:
        """Match URL pattern."""
        return fnmatch.fnmatch(value.lower(), self.pattern.lower())

    def _match_path(self, value: str) -> bool:
        """Match URL path pattern."""
        return fnmatch.fnmatch(value, self.pattern)

    def _match_port(self, value: str) -> bool:
        """Match port or port range."""
        try:
            port = int(value)
            if "-" in self.pattern:
                start, end = map(int, self.pattern.split("-"))
                return start <= port <= end
            else:
                return port == int(self.pattern)
        except ValueError:
            return False


@dataclass
class ScopeConfig:
    """Complete scope configuration."""

    # Primary targets (always in scope)
    targets: list[str] = field(default_factory=list)

    # Explicit inclusions
    include_domains: list[str] = field(default_factory=list)
    include_ips: list[str] = field(default_factory=list)
    include_paths: list[str] = field(default_factory=list)

    # Explicit exclusions (take precedence)
    exclude_domains: list[str] = field(default_factory=list)
    exclude_ips: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    exclude_ports: list[str] = field(default_factory=list)

    # Behavior settings
    violation_action: ScopeAction = ScopeAction.BLOCK
    allow_subdomains: bool = True
    allow_same_ip: bool = True

    # Special settings
    ctf_mode: bool = False  # Disable scope checking
    strict_mode: bool = False  # Extra strict checking

    @classmethod
    def from_target(cls, target: str, **kwargs: Any) -> ScopeConfig:
        """Create scope config from a target URL/IP."""
        config = cls(**kwargs)
        config.targets.append(target)

        parsed = urlparse(target)
        if parsed.netloc:
            host = parsed.netloc.split(":")[0]

            # Check if it's an IP
            try:
                ipaddress.ip_address(host)
                config.include_ips.append(host)
            except ValueError:
                # It's a domain
                if config.allow_subdomains:
                    config.include_domains.append(f"*.{host}")
                config.include_domains.append(host)

        return config

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "targets": self.targets,
            "include_domains": self.include_domains,
            "include_ips": self.include_ips,
            "include_paths": self.include_paths,
            "exclude_domains": self.exclude_domains,
            "exclude_ips": self.exclude_ips,
            "exclude_paths": self.exclude_paths,
            "exclude_ports": self.exclude_ports,
            "violation_action": self.violation_action.value,
            "allow_subdomains": self.allow_subdomains,
            "ctf_mode": self.ctf_mode,
        }


class ScopeManager:
    """
    Manages and enforces scope boundaries during assessments.

    Features:
    - Domain/subdomain matching with wildcards
    - IP address and CIDR range support
    - Path-based inclusion/exclusion
    - Port restrictions
    - Violation tracking and reporting
    """

    def __init__(self, config: ScopeConfig | None = None) -> None:
        """Initialize scope manager."""
        self._config = config or ScopeConfig()
        self._rules: list[ScopeRule] = []
        self._violations: list[dict[str, Any]] = []
        self._checked_count = 0
        self._blocked_count = 0

        self._build_rules()

    def _build_rules(self) -> None:
        """Build rules from config."""
        self._rules = []

        # Add include rules
        for domain in self._config.include_domains:
            self._rules.append(ScopeRule(
                pattern=domain,
                rule_type="include",
                resource_type="domain",
            ))

        for ip in self._config.include_ips:
            self._rules.append(ScopeRule(
                pattern=ip,
                rule_type="include",
                resource_type="ip",
            ))

        for path in self._config.include_paths:
            self._rules.append(ScopeRule(
                pattern=path,
                rule_type="include",
                resource_type="path",
            ))

        # Add exclude rules (these take precedence)
        for domain in self._config.exclude_domains:
            self._rules.append(ScopeRule(
                pattern=domain,
                rule_type="exclude",
                resource_type="domain",
            ))

        for ip in self._config.exclude_ips:
            self._rules.append(ScopeRule(
                pattern=ip,
                rule_type="exclude",
                resource_type="ip",
            ))

        for path in self._config.exclude_paths:
            self._rules.append(ScopeRule(
                pattern=path,
                rule_type="exclude",
                resource_type="path",
            ))

        for port in self._config.exclude_ports:
            self._rules.append(ScopeRule(
                pattern=port,
                rule_type="exclude",
                resource_type="port",
            ))

    def configure(self, config: ScopeConfig) -> None:
        """Update configuration."""
        self._config = config
        self._build_rules()

    def add_target(self, target: str) -> None:
        """Add a target to scope."""
        self._config.targets.append(target)

        parsed = urlparse(target)
        if parsed.netloc:
            host = parsed.netloc.split(":")[0]
            try:
                ipaddress.ip_address(host)
                if host not in self._config.include_ips:
                    self._config.include_ips.append(host)
            except ValueError:
                if host not in self._config.include_domains:
                    self._config.include_domains.append(host)
                    if self._config.allow_subdomains:
                        self._config.include_domains.append(f"*.{host}")

        self._build_rules()

    def add_exclusion(
        self,
        pattern: str,
        resource_type: str = "domain",
        reason: str | None = None,
    ) -> None:
        """Add an exclusion rule."""
        if resource_type == "domain":
            self._config.exclude_domains.append(pattern)
        elif resource_type == "ip":
            self._config.exclude_ips.append(pattern)
        elif resource_type == "path":
            self._config.exclude_paths.append(pattern)
        elif resource_type == "port":
            self._config.exclude_ports.append(pattern)

        self._rules.append(ScopeRule(
            pattern=pattern,
            rule_type="exclude",
            resource_type=resource_type,
            reason=reason,
        ))

    def is_in_scope(self, url: str) -> tuple[bool, str | None]:
        """
        Check if a URL is in scope.

        Returns:
            Tuple of (is_in_scope, reason_if_not)
        """
        self._checked_count += 1

        # CTF mode disables scope checking
        if self._config.ctf_mode:
            return True, None

        parsed = urlparse(url)

        # Extract components
        host = parsed.netloc.split(":")[0] if parsed.netloc else ""
        port = None
        if ":" in parsed.netloc:
            try:
                port = parsed.netloc.split(":")[1]
            except (IndexError, ValueError):
                pass

        path = parsed.path or "/"

        # Check exclusions first (they take precedence)
        for rule in self._rules:
            if rule.rule_type != "exclude":
                continue

            if rule.resource_type == "domain" and rule.matches(host):
                return False, f"Domain excluded: {host} matches {rule.pattern}"

            if rule.resource_type == "ip" and rule.matches(host):
                return False, f"IP excluded: {host} matches {rule.pattern}"

            if rule.resource_type == "path" and rule.matches(path):
                return False, f"Path excluded: {path} matches {rule.pattern}"

            if rule.resource_type == "port" and port and rule.matches(port):
                return False, f"Port excluded: {port} matches {rule.pattern}"

        # Check inclusions
        has_include_rules = any(r.rule_type == "include" for r in self._rules)

        if not has_include_rules:
            # No include rules means allow all (except exclusions checked above)
            return True, None

        for rule in self._rules:
            if rule.rule_type != "include":
                continue

            if rule.resource_type == "domain" and rule.matches(host):
                return True, None

            if rule.resource_type == "ip" and rule.matches(host):
                return True, None

        # No include rule matched
        return False, f"Not in scope: {host} doesn't match any include rules"

    def check_url(self, url: str) -> bool:
        """
        Check URL and enforce scope policy.

        Raises ScopeViolation if action is BLOCK.
        Returns False if out of scope, True if in scope.
        """
        in_scope, reason = self.is_in_scope(url)

        if not in_scope:
            self._blocked_count += 1
            self._violations.append({
                "url": url,
                "reason": reason,
                "action": self._config.violation_action.value,
            })

            logger.warning(
                "scope_violation",
                url=url,
                reason=reason,
                action=self._config.violation_action.value,
            )

            if self._config.violation_action == ScopeAction.BLOCK:
                raise ScopeViolation(f"Out of scope: {url} - {reason}")

        return in_scope

    def check_command(self, command: str) -> tuple[bool, str | None]:
        """
        Check if a shell command might access out-of-scope resources.

        Returns:
            Tuple of (is_safe, reason_if_not)
        """
        # Extract potential URLs/IPs/domains from command
        url_pattern = r'https?://[^\s"\'>]+'
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'

        # Check URLs
        for match in re.findall(url_pattern, command):
            in_scope, reason = self.is_in_scope(match)
            if not in_scope:
                return False, f"Command targets out-of-scope URL: {match}"

        # Check IPs
        for ip in re.findall(ip_pattern, command):
            # Skip common safe IPs
            if ip in ["127.0.0.1", "0.0.0.0", "255.255.255.255"]:
                continue

            # Check if IP is in scope
            for rule in self._rules:
                if rule.rule_type == "exclude" and rule.resource_type == "ip":
                    if rule.matches(ip):
                        return False, f"Command targets excluded IP: {ip}"

            # Check if IP is in include rules
            has_ip_includes = any(
                r.rule_type == "include" and r.resource_type == "ip"
                for r in self._rules
            )
            if has_ip_includes:
                in_scope = any(
                    r.rule_type == "include" and r.resource_type == "ip" and r.matches(ip)
                    for r in self._rules
                )
                if not in_scope:
                    return False, f"Command targets out-of-scope IP: {ip}"

        return True, None

    def get_violations(self) -> list[dict[str, Any]]:
        """Get all recorded violations."""
        return self._violations.copy()

    def get_stats(self) -> dict[str, Any]:
        """Get scope checking statistics."""
        return {
            "total_checked": self._checked_count,
            "blocked": self._blocked_count,
            "violations": len(self._violations),
            "rules_count": len(self._rules),
            "ctf_mode": self._config.ctf_mode,
        }

    def get_scope_summary(self) -> str:
        """Get a human-readable scope summary."""
        lines = ["# Scope Configuration\n"]

        lines.append("## Targets:")
        for t in self._config.targets:
            lines.append(f"  - {t}")

        lines.append("\n## Included Domains:")
        for d in self._config.include_domains:
            lines.append(f"  - {d}")

        lines.append("\n## Included IPs:")
        for ip in self._config.include_ips:
            lines.append(f"  - {ip}")

        if self._config.exclude_domains:
            lines.append("\n## Excluded Domains:")
            for d in self._config.exclude_domains:
                lines.append(f"  - {d}")

        if self._config.exclude_ips:
            lines.append("\n## Excluded IPs:")
            for ip in self._config.exclude_ips:
                lines.append(f"  - {ip}")

        lines.append("\n## Settings:")
        lines.append(f"  - Violation Action: {self._config.violation_action.value}")
        lines.append(f"  - Allow Subdomains: {self._config.allow_subdomains}")
        lines.append(f"  - CTF Mode: {self._config.ctf_mode}")

        return "\n".join(lines)


# Global scope manager instance
_scope_manager: ScopeManager | None = None


def get_scope_manager() -> ScopeManager:
    """Get the global scope manager."""
    global _scope_manager
    if _scope_manager is None:
        _scope_manager = ScopeManager()
    return _scope_manager


def configure_scope(config: ScopeConfig) -> ScopeManager:
    """Configure the global scope manager."""
    global _scope_manager
    _scope_manager = ScopeManager(config)
    return _scope_manager


def check_scope(url: str) -> bool:
    """Quick scope check using global manager."""
    return get_scope_manager().check_url(url)
