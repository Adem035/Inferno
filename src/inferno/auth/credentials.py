"""
Credential management for Inferno.

This module provides a flexible credential management system that supports
multiple credential sources including:
- API Keys (environment variables, files)
- OAuth tokens (for Claude Pro/Team subscription users)

OAuth allows users with Claude subscriptions to use Inferno without
additional API costs.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import structlog

logger = structlog.get_logger(__name__)


# OAuth configuration for Anthropic
ANTHROPIC_OAUTH_CONFIG = {
    "authorization_url": "https://console.anthropic.com/oauth/authorize",
    "token_url": "https://console.anthropic.com/oauth/token",
    "redirect_uri": "http://localhost:8765/callback",
    "scopes": ["user:inference"],
}


class CredentialError(Exception):
    """Raised when credential retrieval fails."""

    pass


class CredentialValidationError(CredentialError):
    """Raised when credential validation fails."""

    pass


class CredentialType(str):
    """Types of credentials."""

    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"


@dataclass
class Credential:
    """Represents a credential with metadata."""

    value: str
    source: str
    loaded_at: datetime
    credential_type: str = CredentialType.API_KEY
    expires_at: datetime | None = None
    refresh_token: str | None = None
    metadata: dict[str, Any] | None = None

    @property
    def is_expired(self) -> bool:
        """Check if the credential is expired."""
        if self.expires_at is None:
            return False
        return datetime.now(UTC) > self.expires_at

    @property
    def is_oauth(self) -> bool:
        """Check if this is an OAuth token."""
        return self.credential_type == CredentialType.OAUTH_TOKEN

    @property
    def needs_refresh(self) -> bool:
        """Check if OAuth token needs refresh (within 5 minutes of expiry)."""
        if not self.is_oauth or self.expires_at is None:
            return False
        buffer = timedelta(minutes=5)
        return datetime.now(UTC) + buffer > self.expires_at

    def get_value(self) -> str:
        """Get the credential value, raising if expired."""
        if self.is_expired:
            raise CredentialError(f"Credential from {self.source} has expired")
        return self.value


class CredentialProvider(ABC):
    """
    Abstract base class for credential providers.

    Designed with OAuth-ready architecture - when Anthropic adds OAuth support,
    implement a new OAuthCredentialProvider without changing existing code.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for logging."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this provider can provide credentials."""
        ...

    @abstractmethod
    def get_credential(self) -> Credential:
        """
        Retrieve the credential.

        Returns:
            Credential object.

        Raises:
            CredentialError: If credential cannot be retrieved.
        """
        ...

    def validate_credential(self, credential: Credential) -> bool:
        """
        Validate a credential.

        Override in subclasses for provider-specific validation.

        Args:
            credential: The credential to validate.

        Returns:
            True if valid, False otherwise.
        """
        return bool(credential.value) and len(credential.value) >= 10


class EnvironmentCredentialProvider(CredentialProvider):
    """
    Provides credentials from environment variables.

    This is the primary provider for API key authentication.
    """

    def __init__(
        self,
        env_var: str = "ANTHROPIC_API_KEY",
        prefix: str | None = None,
    ) -> None:
        """
        Initialize the environment credential provider.

        Args:
            env_var: Name of the environment variable.
            prefix: Optional prefix to prepend to env_var.
        """
        self._env_var = f"{prefix}_{env_var}" if prefix else env_var

    @property
    def name(self) -> str:
        return f"env:{self._env_var}"

    def is_available(self) -> bool:
        """Check if the environment variable is set."""
        value = os.environ.get(self._env_var)
        return value is not None and len(value) > 0

    def get_credential(self) -> Credential:
        """Get credential from environment variable."""
        value = os.environ.get(self._env_var)

        if not value:
            raise CredentialError(
                f"Environment variable {self._env_var} not set or empty"
            )

        credential = Credential(
            value=value,
            source=self.name,
            loaded_at=datetime.now(UTC),
        )

        if not self.validate_credential(credential):
            raise CredentialValidationError(
                f"Invalid credential from {self.name}"
            )

        logger.debug("credential_loaded", provider=self.name)
        return credential


class FileCredentialProvider(CredentialProvider):
    """
    Provides credentials from a JSON file.

    File format:
    {
        "api_key": "sk-ant-...",
        "expires_at": "2025-12-31T23:59:59Z"  // optional
    }
    """

    DEFAULT_PATH = Path.home() / ".inferno" / "credentials.json"

    def __init__(
        self,
        path: Path | None = None,
        key_field: str = "api_key",
    ) -> None:
        """
        Initialize the file credential provider.

        Args:
            path: Path to the credentials file.
            key_field: Field name containing the API key.
        """
        self._path = path or self.DEFAULT_PATH
        self._key_field = key_field

    @property
    def name(self) -> str:
        return f"file:{self._path}"

    def is_available(self) -> bool:
        """Check if the credentials file exists and is readable."""
        return self._path.exists() and self._path.is_file()

    def get_credential(self) -> Credential:
        """Load credential from file."""
        if not self.is_available():
            raise CredentialError(f"Credentials file not found: {self._path}")

        try:
            with open(self._path) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise CredentialError(f"Invalid JSON in {self._path}: {e}") from e
        except OSError as e:
            raise CredentialError(f"Cannot read {self._path}: {e}") from e

        if self._key_field not in data:
            raise CredentialError(
                f"Field '{self._key_field}' not found in {self._path}"
            )

        expires_at = None
        if "expires_at" in data:
            try:
                expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
            except ValueError:
                logger.warning(
                    "invalid_expires_at",
                    path=str(self._path),
                    value=data["expires_at"],
                )

        credential = Credential(
            value=data[self._key_field],
            source=self.name,
            loaded_at=datetime.now(UTC),
            expires_at=expires_at,
            metadata={k: v for k, v in data.items() if k not in (self._key_field, "expires_at")},
        )

        if not self.validate_credential(credential):
            raise CredentialValidationError(f"Invalid credential from {self.name}")

        logger.debug("credential_loaded", provider=self.name)
        return credential

    @classmethod
    def save_credential(
        cls,
        api_key: str,
        path: Path | None = None,
        expires_at: datetime | None = None,
        **metadata: Any,
    ) -> Path:
        """
        Save a credential to file.

        Args:
            api_key: The API key to save.
            path: Path to save to (uses default if not specified).
            expires_at: Optional expiration datetime.
            **metadata: Additional metadata to save.

        Returns:
            Path to the saved file.
        """
        save_path = path or cls.DEFAULT_PATH
        save_path.parent.mkdir(parents=True, exist_ok=True)

        data: dict[str, Any] = {"api_key": api_key, **metadata}
        if expires_at:
            data["expires_at"] = expires_at.isoformat()

        with open(save_path, "w") as f:
            json.dump(data, f, indent=2)

        # Set restrictive permissions (owner read/write only)
        save_path.chmod(0o600)

        logger.info("credential_saved", path=str(save_path))
        return save_path


class OAuthCredentialProvider(CredentialProvider):
    """
    Provides credentials via OAuth for Claude subscription users.

    This allows users with Claude Pro/Team subscriptions to use
    Inferno without additional API billing.

    The OAuth flow:
    1. User initiates auth via CLI command
    2. Browser opens to Anthropic consent page
    3. User approves and is redirected back
    4. Token is saved and used for API calls
    """

    TOKEN_PATH = Path.home() / ".inferno" / "oauth_token.json"

    def __init__(
        self,
        client_id: str | None = None,
        token_path: Path | None = None,
    ) -> None:
        """
        Initialize the OAuth credential provider.

        Args:
            client_id: OAuth client ID (from env or parameter).
            token_path: Path to store OAuth tokens.
        """
        self._client_id = client_id or os.environ.get("INFERNO_OAUTH_CLIENT_ID")
        self._token_path = token_path or self.TOKEN_PATH
        self._cached_credential: Credential | None = None

    @property
    def name(self) -> str:
        return "oauth:anthropic"

    def is_available(self) -> bool:
        """Check if OAuth tokens are available."""
        # Check for saved token
        if self._token_path.exists():
            try:
                self._load_saved_token()
                return True
            except Exception:
                pass
        return False

    def _load_saved_token(self) -> Credential:
        """Load saved OAuth token from file."""
        with open(self._token_path) as f:
            data = json.load(f)

        expires_at = None
        if "expires_at" in data:
            expires_at = datetime.fromisoformat(data["expires_at"])

        return Credential(
            value=data["access_token"],
            source=self.name,
            loaded_at=datetime.now(UTC),
            credential_type=CredentialType.OAUTH_TOKEN,
            expires_at=expires_at,
            refresh_token=data.get("refresh_token"),
            metadata={"token_type": data.get("token_type", "Bearer")},
        )

    def get_credential(self) -> Credential:
        """Get OAuth credential."""
        if not self._token_path.exists():
            raise CredentialError(
                "No OAuth token found. Run 'inferno auth login' to authenticate."
            )

        credential = self._load_saved_token()

        # Check if token needs refresh
        if credential.needs_refresh and credential.refresh_token:
            logger.info("oauth_token_refresh_needed")
            credential = self._refresh_token(credential.refresh_token)

        if credential.is_expired:
            raise CredentialError(
                "OAuth token expired. Run 'inferno auth login' to re-authenticate."
            )

        logger.debug("oauth_credential_loaded")
        return credential

    def _refresh_token(self, refresh_token: str) -> Credential:
        """Refresh an expired OAuth token."""
        import httpx

        if not self._client_id:
            raise CredentialError("OAuth client ID not configured")

        try:
            response = httpx.post(
                ANTHROPIC_OAUTH_CONFIG["token_url"],
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": self._client_id,
                },
            )
            response.raise_for_status()
            token_data = response.json()

            # Calculate expiration
            expires_in = token_data.get("expires_in", 3600)
            expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)

            # Save refreshed token
            self._save_token(token_data, expires_at)

            return Credential(
                value=token_data["access_token"],
                source=self.name,
                loaded_at=datetime.now(UTC),
                credential_type=CredentialType.OAUTH_TOKEN,
                expires_at=expires_at,
                refresh_token=token_data.get("refresh_token", refresh_token),
            )

        except Exception as e:
            logger.error("oauth_refresh_failed", error=str(e))
            raise CredentialError(f"Failed to refresh OAuth token: {e}") from e

    def _save_token(
        self,
        token_data: dict[str, Any],
        expires_at: datetime | None = None,
    ) -> None:
        """Save OAuth token to file."""
        self._token_path.parent.mkdir(parents=True, exist_ok=True)

        save_data = {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "Bearer"),
        }

        if "refresh_token" in token_data:
            save_data["refresh_token"] = token_data["refresh_token"]

        if expires_at:
            save_data["expires_at"] = expires_at.isoformat()

        with open(self._token_path, "w") as f:
            json.dump(save_data, f, indent=2)

        self._token_path.chmod(0o600)
        logger.info("oauth_token_saved")

    def initiate_auth_flow(self) -> str:
        """
        Initiate the OAuth authorization flow.

        Returns:
            The authorization URL for the user to visit.
        """
        if not self._client_id:
            raise CredentialError(
                "OAuth client ID not configured. Set INFERNO_OAUTH_CLIENT_ID environment variable."
            )

        params = {
            "client_id": self._client_id,
            "redirect_uri": ANTHROPIC_OAUTH_CONFIG["redirect_uri"],
            "response_type": "code",
            "scope": " ".join(ANTHROPIC_OAUTH_CONFIG["scopes"]),
        }

        auth_url = f"{ANTHROPIC_OAUTH_CONFIG['authorization_url']}?{urlencode(params)}"
        return auth_url

    def complete_auth_flow(self, authorization_code: str) -> Credential:
        """
        Complete the OAuth flow with the authorization code.

        Args:
            authorization_code: The code received from the callback.

        Returns:
            The OAuth credential.
        """
        import httpx

        if not self._client_id:
            raise CredentialError("OAuth client ID not configured")

        try:
            response = httpx.post(
                ANTHROPIC_OAUTH_CONFIG["token_url"],
                data={
                    "grant_type": "authorization_code",
                    "code": authorization_code,
                    "client_id": self._client_id,
                    "redirect_uri": ANTHROPIC_OAUTH_CONFIG["redirect_uri"],
                },
            )
            response.raise_for_status()
            token_data = response.json()

            # Calculate expiration
            expires_in = token_data.get("expires_in", 3600)
            expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)

            # Save token
            self._save_token(token_data, expires_at)

            logger.info("oauth_auth_completed")

            return Credential(
                value=token_data["access_token"],
                source=self.name,
                loaded_at=datetime.now(UTC),
                credential_type=CredentialType.OAUTH_TOKEN,
                expires_at=expires_at,
                refresh_token=token_data.get("refresh_token"),
            )

        except Exception as e:
            logger.error("oauth_auth_failed", error=str(e))
            raise CredentialError(f"OAuth authentication failed: {e}") from e

    def logout(self) -> bool:
        """
        Remove saved OAuth tokens.

        Returns:
            True if tokens were removed.
        """
        if self._token_path.exists():
            self._token_path.unlink()
            logger.info("oauth_logout")
            return True
        return False


class EnvironmentOAuthProvider(CredentialProvider):
    """
    Provides OAuth tokens from environment variables.

    This is the primary method for Windows/Linux users who don't have macOS Keychain.
    Users can set CLAUDE_CODE_OAUTH_TOKEN or INFERNO_OAUTH_TOKEN environment variable.

    Useful for:
    - Windows users (no Keychain)
    - Linux users
    - CI/CD pipelines
    - Docker containers
    """

    def __init__(
        self,
        env_vars: list[str] | None = None,
    ) -> None:
        """
        Initialize the environment OAuth provider.

        Args:
            env_vars: List of environment variable names to check (in order).
        """
        self._env_vars = env_vars or [
            "CLAUDE_CODE_OAUTH_TOKEN",  # Claude Code token (cross-platform)
            "INFERNO_OAUTH_TOKEN",      # Inferno-specific token
        ]

    @property
    def name(self) -> str:
        return "env:oauth"

    def is_available(self) -> bool:
        """Check if any OAuth token environment variable is set."""
        for env_var in self._env_vars:
            value = os.environ.get(env_var)
            if value and value.startswith("sk-ant-oat"):
                return True
        return False

    def get_credential(self) -> Credential:
        """Get OAuth credential from environment variable."""
        for env_var in self._env_vars:
            value = os.environ.get(env_var)
            if value and value.strip():
                credential = Credential(
                    value=value.strip(),
                    source=f"env:{env_var}",
                    loaded_at=datetime.now(UTC),
                    credential_type=CredentialType.OAUTH_TOKEN,
                    metadata={"token_type": "Bearer"},
                )

                if self.validate_credential(credential):
                    logger.debug("oauth_credential_loaded", provider=f"env:{env_var}")
                    return credential

        raise CredentialError(
            f"No valid OAuth token found in environment variables: {', '.join(self._env_vars)}"
        )

    def validate_credential(self, credential: Credential) -> bool:
        """Validate the OAuth token format."""
        # Claude OAuth tokens start with sk-ant-oat
        return (
            credential.value.startswith("sk-ant-oat")
            and len(credential.value) > 20
        )


class KeychainCredentialProvider(CredentialProvider):
    """
    Provides credentials from macOS Keychain using Claude Code's stored OAuth tokens.

    This allows users with Claude Max/Pro subscriptions who have authenticated
    via Claude Code CLI to reuse those credentials without additional setup.

    The credentials are stored by Claude Code at:
    - Service: "Claude Code-credentials"
    - Account: <username>
    - Format: {"claudeAiOauth":{"accessToken":"sk-ant-oat01-..."}}
    """

    KEYCHAIN_SERVICE = "Claude Code-credentials"

    def __init__(self, account: str | None = None) -> None:
        """
        Initialize the Keychain credential provider.

        Args:
            account: Keychain account name. If None, uses current user.
        """
        self._account = account or os.environ.get("USER", os.environ.get("USERNAME", ""))
        self._cached_credential: Credential | None = None

    @property
    def name(self) -> str:
        return "keychain:claude-code"

    def is_available(self) -> bool:
        """Check if running on macOS and credentials exist in keychain."""
        if platform.system() != "Darwin":
            return False

        try:
            self._read_keychain()
            return True
        except Exception:
            return False

    def _read_keychain(self) -> dict[str, Any]:
        """
        Read credentials from macOS Keychain.

        Returns:
            Parsed JSON credentials.

        Raises:
            CredentialError: If keychain read fails.
        """
        try:
            result = subprocess.run(
                [
                    "security",
                    "find-generic-password",
                    "-s", self.KEYCHAIN_SERVICE,
                    "-a", self._account,
                    "-w",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            raw_value = result.stdout.strip()
            return json.loads(raw_value)
        except subprocess.CalledProcessError as e:
            raise CredentialError(
                f"Failed to read from macOS Keychain: {e.stderr or 'Credentials not found'}"
            ) from e
        except json.JSONDecodeError as e:
            raise CredentialError(
                f"Invalid JSON in Keychain credentials: {e}"
            ) from e

    def get_credential(self) -> Credential:
        """
        Get OAuth credential from macOS Keychain.

        Returns:
            Credential with the OAuth access token.

        Raises:
            CredentialError: If keychain read fails or token not found.
        """
        if platform.system() != "Darwin":
            raise CredentialError(
                "Keychain credentials only available on macOS"
            )

        data = self._read_keychain()

        # Claude Code stores tokens in claudeAiOauth.accessToken
        oauth_data = data.get("claudeAiOauth", {})
        access_token = oauth_data.get("accessToken")

        if not access_token:
            raise CredentialError(
                "No OAuth access token found in Claude Code keychain. "
                "Make sure you're logged in to Claude Code CLI."
            )

        credential = Credential(
            value=access_token,
            source=self.name,
            loaded_at=datetime.now(UTC),
            credential_type=CredentialType.OAUTH_TOKEN,
            expires_at=None,  # Claude Code tokens don't have expiry info stored
            metadata={
                "token_type": "Bearer",
                "from_claude_code": True,
            },
        )

        if not self.validate_credential(credential):
            raise CredentialValidationError(
                f"Invalid credential from {self.name}"
            )

        logger.debug("keychain_credential_loaded", provider=self.name)
        return credential

    def validate_credential(self, credential: Credential) -> bool:
        """Validate the OAuth token format."""
        # Claude OAuth tokens start with sk-ant-oat
        return (
            credential.value.startswith("sk-ant-oat")
            and len(credential.value) > 20
        )


class CredentialManager:
    """
    Manages credential providers with fallback chain.

    Providers are tried in order until one succeeds:
    1. Keychain (macOS only) - reuses Claude Code OAuth tokens
    2. OAuth (if token exists) - for Claude subscription users
    3. Environment variable (ANTHROPIC_API_KEY)
    4. Credentials file (~/.inferno/credentials.json)

    This allows users to choose between:
    - Reusing Claude Code credentials (easiest for Claude Max users)
    - API key billing (pay per token)
    - OAuth with Claude subscription (no additional cost)
    """

    def __init__(
        self,
        providers: list[CredentialProvider] | None = None,
        prefer_oauth: bool = True,
    ) -> None:
        """
        Initialize the credential manager.

        Args:
            providers: List of credential providers to use.
            prefer_oauth: If True, OAuth/Keychain is tried first (default).
        """
        if providers is not None:
            self._providers = providers
        elif prefer_oauth:
            # OAuth first for subscription users (cross-platform support)
            self._providers = [
                KeychainCredentialProvider(),      # macOS Keychain (Claude Code creds)
                EnvironmentOAuthProvider(),        # ENV var OAuth (Windows/Linux/Docker)
                OAuthCredentialProvider(),         # Inferno's own OAuth flow
                EnvironmentCredentialProvider(),   # API key from env
                FileCredentialProvider(),          # API key from file
            ]
        else:
            # API key first
            self._providers = [
                EnvironmentCredentialProvider(),
                FileCredentialProvider(),
                KeychainCredentialProvider(),
                EnvironmentOAuthProvider(),
                OAuthCredentialProvider(),
            ]
        self._cached_credential: Credential | None = None

    @property
    def providers(self) -> list[CredentialProvider]:
        """Get the list of credential providers."""
        return self._providers

    def add_provider(self, provider: CredentialProvider, priority: int = -1) -> None:
        """
        Add a credential provider.

        Args:
            provider: The provider to add.
            priority: Position in the provider list (-1 for end).
        """
        if priority < 0:
            self._providers.append(provider)
        else:
            self._providers.insert(priority, provider)
        logger.debug("provider_added", provider=provider.name, priority=priority)

    def get_credential(self, force_refresh: bool = False) -> Credential:
        """
        Get a valid credential from the first available provider.

        Args:
            force_refresh: Skip cache and load fresh credential.

        Returns:
            Valid Credential object.

        Raises:
            CredentialError: If no provider can supply a valid credential.
        """
        # Check cache first
        if not force_refresh and self._cached_credential:
            if not self._cached_credential.is_expired:
                return self._cached_credential
            logger.debug("cached_credential_expired")

        errors: list[str] = []

        for provider in self._providers:
            if not provider.is_available():
                logger.debug("provider_not_available", provider=provider.name)
                continue

            try:
                credential = provider.get_credential()
                self._cached_credential = credential
                logger.info("credential_obtained", provider=provider.name)
                return credential
            except CredentialError as e:
                errors.append(f"{provider.name}: {e}")
                logger.debug("provider_failed", provider=provider.name, error=str(e))

        # All providers failed
        error_summary = "; ".join(errors) if errors else "No providers available"
        raise CredentialError(
            f"Failed to obtain credentials from any provider. Errors: {error_summary}"
        )

    def get_api_key(self, force_refresh: bool = False) -> str:
        """
        Convenience method to get just the API key string.

        Args:
            force_refresh: Skip cache and load fresh credential.

        Returns:
            API key string.
        """
        return self.get_credential(force_refresh).get_value()

    def invalidate_cache(self) -> None:
        """Clear the cached credential."""
        self._cached_credential = None
        logger.debug("credential_cache_invalidated")

    def get_available_providers(self) -> list[str]:
        """Get names of providers that are currently available."""
        return [p.name for p in self._providers if p.is_available()]


# Singleton instance
_credential_manager: CredentialManager | None = None


def get_credential_manager() -> CredentialManager:
    """Get the singleton CredentialManager instance."""
    global _credential_manager
    if _credential_manager is None:
        _credential_manager = CredentialManager()
    return _credential_manager


def get_api_key() -> str:
    """Convenience function to get the API key."""
    return get_credential_manager().get_api_key()


def reset_credential_manager() -> None:
    """Reset the singleton CredentialManager instance."""
    global _credential_manager
    _credential_manager = None


def setup_sdk_auth() -> str | None:
    """
    Set up authentication for Claude Agent SDK.

    The Claude Agent SDK runs the claude CLI as a subprocess. This function
    ensures the subprocess has access to credentials by:
    1. Getting credentials from Inferno's credential manager
    2. Setting ANTHROPIC_API_KEY environment variable if we have an API key
    3. Returning the cli_path for OAuth-authenticated CLI

    Returns:
        Path to claude CLI if found, None otherwise.

    Note:
        For OAuth authentication, the SDK uses the cli_path to run
        an already-authenticated claude CLI. For API key auth, we
        set the environment variable so the subprocess can use it.
    """
    import shutil

    # Get CLI path
    cli_path = shutil.which("claude")

    # Try to get credentials and set env var as fallback
    try:
        credential = get_credential_manager().get_credential()

        # If it's an API key (not OAuth), set the env var
        if not credential.is_oauth:
            os.environ["ANTHROPIC_API_KEY"] = credential.get_value()
            logger.debug("sdk_auth_api_key_set")
        else:
            # For OAuth, ensure the SDK knows to use the CLI
            # The CLI should already have the OAuth token from `claude login`
            logger.debug("sdk_auth_oauth_mode", cli_path=cli_path)

    except CredentialError as e:
        # No credentials available - SDK will need to rely on CLI auth
        logger.warning("sdk_auth_no_credentials", error=str(e))

    return cli_path
