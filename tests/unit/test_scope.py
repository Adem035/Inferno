"""
Unit tests for scope management (core/scope.py).
Security-critical tests for scope enforcement.
"""

import pytest
from pathlib import Path


class TestScopeManager:
    """Tests for ScopeManager class."""

    def test_domain_matching_exact(self, sample_scope_config):
        """Test exact domain matching."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        # Should match
        in_scope, _ = scope.is_in_scope("https://example.com/api")
        assert in_scope

        in_scope, _ = scope.is_in_scope("https://test.example.com/users")
        assert in_scope

    def test_subdomain_wildcard_matching(self, sample_scope_config):
        """Test wildcard subdomain matching."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        # Wildcards should match
        assert scope.is_in_scope("https://api.example.com")[0]
        assert scope.is_in_scope("https://dev.test.example.com")[0]

        # Should NOT match different TLD
        assert not scope.is_in_scope("https://example.org")[0]
        assert not scope.is_in_scope("https://notexample.com")[0]

    def test_excluded_domains(self, sample_scope_config):
        """Test domain exclusion."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        # admin.example.com is excluded
        in_scope, reason = scope.is_in_scope("https://admin.example.com")
        assert not in_scope
        assert "excluded" in reason.lower()

    def test_ip_cidr_matching(self, sample_scope_config):
        """Test IP CIDR range matching."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        # 192.168.1.0/24 is in scope
        assert scope.is_in_scope("http://192.168.1.1")[0]
        assert scope.is_in_scope("http://192.168.1.254")[0]

        # Outside range
        assert not scope.is_in_scope("http://192.168.2.1")[0]
        assert not scope.is_in_scope("http://10.0.0.1")[0]

    def test_path_exclusion(self, sample_scope_config):
        """Test path-based exclusion."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        # /admin/* is excluded
        assert not scope.is_in_scope("https://example.com/admin/users")[0]
        assert not scope.is_in_scope("https://example.com/api/internal/secrets")[0]

        # Other paths are OK
        assert scope.is_in_scope("https://example.com/api/public")[0]

    def test_permissive_mode_bypass(self, ctf_scope_config):
        """Test that permissive mode allows broader scope."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(ctf_scope_config)

        # Permissive mode should allow any target
        in_scope, _ = scope.is_in_scope("http://ctf.htb:8080/anything")
        assert in_scope


class TestScopeBypassPrevention:
    """Security tests to prevent scope bypass."""

    def test_url_credential_bypass(self, sample_scope_config):
        """Test that URL credential injection doesn't bypass scope."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        # Attacker tries: example.com@attacker.com
        in_scope, _ = scope.is_in_scope("https://example.com@attacker.com/path")
        assert not in_scope

    def test_domain_prefix_bypass(self, sample_scope_config):
        """Test that domain prefix doesn't bypass scope."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        # example.com.attacker.com should NOT match
        assert not scope.is_in_scope("https://example.com.attacker.com")[0]

    def test_url_encoding_bypass(self, sample_scope_config):
        """Test URL encoding doesn't bypass scope."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        # URL encoded attempts
        assert not scope.is_in_scope("https://example%2ecom%2fattacker.com")[0]

    def test_path_traversal_bypass(self, sample_scope_config):
        """Test path traversal doesn't escape scope."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        # Path traversal shouldn't change domain matching
        in_scope, _ = scope.is_in_scope("https://example.com/../../../etc/passwd")
        # Domain is in scope, path traversal is a separate concern
        assert in_scope


class TestCommandScopeChecking:
    """Tests for shell command scope validation."""

    def test_safe_command_allowed(self, sample_scope_config):
        """Test that safe commands are allowed."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        is_safe, _ = scope.check_command("curl https://example.com/api")
        assert is_safe

    def test_out_of_scope_url_in_command(self, sample_scope_config):
        """Test that out-of-scope URLs in commands are blocked."""
        from inferno.core.scope import ScopeManager

        scope = ScopeManager(sample_scope_config)

        is_safe, reason = scope.check_command("curl https://attacker.com/shell")
        assert not is_safe
        assert "out-of-scope" in reason.lower() or "scope" in reason.lower()
