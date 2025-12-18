"""
Inferno authentication module.

This module provides credential management and Claude API client wrappers
with support for advanced tool features.
"""

from inferno.auth.client import (
    AsyncInfernoClient,
    ClientError,
    InfernoClient,
    RateLimitError,
    TokenLimitError,
    TokenTracker,
    TokenUsage,
)
from inferno.auth.credentials import (
    Credential,
    CredentialError,
    CredentialManager,
    CredentialProvider,
    CredentialValidationError,
    EnvironmentCredentialProvider,
    FileCredentialProvider,
    KeychainCredentialProvider,
    get_api_key,
    get_credential_manager,
    setup_sdk_auth,
)

__all__ = [
    # Client
    "InfernoClient",
    "AsyncInfernoClient",
    "ClientError",
    "RateLimitError",
    "TokenLimitError",
    "TokenUsage",
    "TokenTracker",
    # Credentials
    "Credential",
    "CredentialError",
    "CredentialValidationError",
    "CredentialProvider",
    "CredentialManager",
    "EnvironmentCredentialProvider",
    "FileCredentialProvider",
    "KeychainCredentialProvider",
    "get_credential_manager",
    "get_api_key",
    "setup_sdk_auth",
]
