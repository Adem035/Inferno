"""
Unicode Security - Homograph attack detection and URL normalization.

This module provides security checks for Unicode-based attacks,
particularly homograph attacks that use visually similar characters
from different scripts (e.g., Cyrillic 'а' vs Latin 'a').

Reference: https://en.wikipedia.org/wiki/IDN_homograph_attack
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Set
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


class RiskLevel(str, Enum):
    """Risk level for detected homographs."""
    CRITICAL = "critical"  # Known attack character
    HIGH = "high"          # Definite lookalike from dangerous script
    MEDIUM = "medium"      # Possible lookalike
    LOW = "low"            # Non-ASCII but not clearly malicious
    SAFE = "safe"          # No issues detected


@dataclass
class HomographResult:
    """Result of homograph detection for a single character."""
    char: str
    position: int
    unicode_name: str
    unicode_category: str
    script: str
    lookalike_ascii: Optional[str]
    risk_level: RiskLevel
    description: str


@dataclass
class SecurityCheckResult:
    """Overall security check result for a string."""
    original: str
    normalized: str
    is_safe: bool
    risk_level: RiskLevel
    homographs: List[HomographResult]
    mixed_scripts: bool
    scripts_found: Set[str]
    recommendations: List[str]


# Cyrillic characters that look like Latin characters
CYRILLIC_LOOKALIKES = {
    'а': 'a', 'А': 'A',
    'В': 'B',
    'с': 'c', 'С': 'C',
    'е': 'e', 'Е': 'E',
    'Н': 'H',
    'і': 'i', 'І': 'I',
    'К': 'K',
    'М': 'M',
    'о': 'o', 'О': 'O',
    'р': 'p', 'Р': 'P',
    'ѕ': 's', 'Ѕ': 'S',
    'Т': 'T',
    'у': 'y',
    'х': 'x', 'Х': 'X',
}

# Greek characters that look like Latin characters
GREEK_LOOKALIKES = {
    'Α': 'A', 'α': 'a',
    'Β': 'B', 'β': 'b',
    'Ε': 'E', 'ε': 'e',
    'Η': 'H', 'η': 'n',
    'Ι': 'I', 'ι': 'i',
    'Κ': 'K', 'κ': 'k',
    'Μ': 'M',
    'Ν': 'N', 'ν': 'v',
    'Ο': 'O', 'ο': 'o',
    'Ρ': 'P', 'ρ': 'p',
    'Τ': 'T', 'τ': 't',
    'Υ': 'Y', 'υ': 'u',
    'Χ': 'X', 'χ': 'x',
    'Ζ': 'Z',
}

# Combine all lookalikes
ALL_LOOKALIKES = {**CYRILLIC_LOOKALIKES, **GREEK_LOOKALIKES}

# Additional confusable characters (subset of Unicode confusables)
CONFUSABLES = {
    'ℓ': 'l',  # Script small l
    '𝟎': '0', '𝟏': '1', '𝟐': '2', '𝟑': '3', '𝟒': '4',  # Mathematical digits
    '𝟓': '5', '𝟔': '6', '𝟕': '7', '𝟖': '8', '𝟗': '9',
    'Ⅰ': 'I', 'Ⅴ': 'V', 'Ⅹ': 'X', 'Ⅼ': 'L', 'Ⅽ': 'C', 'Ⅾ': 'D', 'Ⅿ': 'M',  # Roman numerals
    'ⅰ': 'i', 'ⅴ': 'v', 'ⅹ': 'x', 'ⅼ': 'l', 'ⅽ': 'c', 'ⅾ': 'd', 'ⅿ': 'm',
    '①': '1', '②': '2', '③': '3', '④': '4', '⑤': '5',  # Circled numbers
    'ⓐ': 'a', 'ⓑ': 'b', 'ⓒ': 'c', 'ⓓ': 'd', 'ⓔ': 'e',  # Circled letters
    '＠': '@', '／': '/', '＼': '\\',  # Fullwidth symbols
    # Punctuation variants
    '\u2010': '-',  # Hyphen
    '\u2011': '-',  # Non-breaking hyphen
    '\u2212': '-',  # Minus sign
    '\uff0d': '-',  # Fullwidth hyphen-minus
    '\u2018': "'",  # Left single quote
    '\u2019': "'",  # Right single quote
    '\u201c': '"',  # Left double quote
    '\u201d': '"',  # Right double quote
    '\u2024': '.',  # One dot leader
    '\u2027': '-',  # Hyphenation point
    '\u30fb': '.',  # Katakana middle dot
}

# Zero-width characters (remove them entirely)
ZERO_WIDTH_CHARS = {
    '\u200b': '',  # Zero width space
    '\u200c': '',  # Zero width non-joiner
    '\u200d': '',  # Zero width joiner
    '\ufeff': '',  # BOM / zero width no-break space
}

# Dangerous scripts for domain spoofing
DANGEROUS_SCRIPTS = {'Cyrillic', 'Greek', 'Armenian'}

# Safe scripts that don't need checking
SAFE_SCRIPTS = {'Common', 'Latin'}


def get_script(char: str) -> str:
    """
    Get the Unicode script for a character.

    Args:
        char: Single character to check.

    Returns:
        Script name (e.g., 'Latin', 'Cyrillic', 'Common').
    """
    try:
        name = unicodedata.name(char, '')
        # Extract script from character name
        if 'LATIN' in name:
            return 'Latin'
        elif 'CYRILLIC' in name:
            return 'Cyrillic'
        elif 'GREEK' in name:
            return 'Greek'
        elif 'ARMENIAN' in name:
            return 'Armenian'
        elif 'ARABIC' in name:
            return 'Arabic'
        elif 'HEBREW' in name:
            return 'Hebrew'
        elif 'CJK' in name or 'HIRAGANA' in name or 'KATAKANA' in name:
            return 'CJK'
        else:
            # Check category for common characters
            category = unicodedata.category(char)
            if category.startswith('N'):  # Numbers
                return 'Common'
            elif category.startswith('P') or category.startswith('S'):  # Punctuation/Symbols
                return 'Common'
            elif category == 'Zs':  # Space
                return 'Common'
            return 'Other'
    except Exception:
        return 'Unknown'


def detect_homographs(text: str) -> List[HomographResult]:
    """
    Detect potential homograph attacks in text.

    Args:
        text: Text to analyze.

    Returns:
        List of HomographResult for each suspicious character.
    """
    results = []

    for i, char in enumerate(text):
        unicode_name = unicodedata.name(char, 'UNKNOWN')
        unicode_category = unicodedata.category(char)
        script = get_script(char)

        # Check known lookalikes
        if char in ALL_LOOKALIKES:
            results.append(HomographResult(
                char=char,
                position=i,
                unicode_name=unicode_name,
                unicode_category=unicode_category,
                script=script,
                lookalike_ascii=ALL_LOOKALIKES[char],
                risk_level=RiskLevel.CRITICAL if script in DANGEROUS_SCRIPTS else RiskLevel.HIGH,
                description=f"Looks like ASCII '{ALL_LOOKALIKES[char]}' but is {script} character",
            ))

        # Check confusables
        elif char in CONFUSABLES:
            results.append(HomographResult(
                char=char,
                position=i,
                unicode_name=unicode_name,
                unicode_category=unicode_category,
                script=script,
                lookalike_ascii=CONFUSABLES[char],
                risk_level=RiskLevel.MEDIUM,
                description=f"Confusable character, looks like '{CONFUSABLES[char]}'",
            ))

        # Check non-ASCII letters from dangerous scripts
        elif ord(char) > 127 and script in DANGEROUS_SCRIPTS:
            results.append(HomographResult(
                char=char,
                position=i,
                unicode_name=unicode_name,
                unicode_category=unicode_category,
                script=script,
                lookalike_ascii=None,
                risk_level=RiskLevel.MEDIUM,
                description=f"Non-ASCII {script} character in input",
            ))

        # Check other non-ASCII that might be letters
        elif ord(char) > 127 and unicode_category.startswith('L'):
            results.append(HomographResult(
                char=char,
                position=i,
                unicode_name=unicode_name,
                unicode_category=unicode_category,
                script=script,
                lookalike_ascii=None,
                risk_level=RiskLevel.LOW,
                description=f"Non-ASCII letter from {script} script",
            ))

    return results


def normalize_text(text: str, aggressive: bool = False) -> str:
    """
    Normalize text by replacing homographs with ASCII equivalents.

    Args:
        text: Text to normalize.
        aggressive: If True, replace all non-ASCII with closest ASCII.

    Returns:
        Normalized text.
    """
    # First, remove zero-width characters
    for zw_char in ZERO_WIDTH_CHARS:
        text = text.replace(zw_char, '')

    result = list(text)

    # Replace known lookalikes
    for i, char in enumerate(text):
        if char in ALL_LOOKALIKES:
            result[i] = ALL_LOOKALIKES[char]
        elif char in CONFUSABLES:
            result[i] = CONFUSABLES[char]
        elif aggressive and ord(char) > 127:
            # Try NFKD normalization for aggressive mode
            normalized = unicodedata.normalize('NFKD', char)
            ascii_char = normalized.encode('ascii', 'ignore').decode('ascii')
            if ascii_char:
                result[i] = ascii_char[0]

    return ''.join(result)


def detect_homograph_bypass(text: str) -> bool:
    """
    Detect if text contains Unicode homograph characters that could be used for bypass.

    Args:
        text: Text to check.

    Returns:
        True if homograph bypass attempt detected.
    """
    normalized = normalize_text(text)

    if normalized != text:
        # Check if the normalized version reveals dangerous commands
        dangerous_commands = ['curl', 'wget', 'nc ', 'netcat', 'bash', 'sh ',
                             '/bin/sh', 'exec', 'eval', 'python', 'perl', 'ruby']
        for cmd in dangerous_commands:
            if cmd in normalized.lower() and cmd not in text.lower():
                return True
    return False


def check_url_security(url: str) -> SecurityCheckResult:
    """
    Comprehensive security check for a URL.

    Args:
        url: URL to check.

    Returns:
        SecurityCheckResult with detailed analysis.
    """
    homographs = detect_homographs(url)

    # Identify scripts used
    scripts_found = set()
    for char in url:
        if ord(char) > 127:
            scripts_found.add(get_script(char))

    # Check for mixed scripts (common attack pattern)
    has_latin = any(c.isascii() and c.isalpha() for c in url)
    has_non_latin_letter = any(
        ord(c) > 127 and unicodedata.category(c).startswith('L')
        for c in url
    )
    mixed_scripts = has_latin and has_non_latin_letter

    # Determine overall risk
    if any(h.risk_level == RiskLevel.CRITICAL for h in homographs):
        risk_level = RiskLevel.CRITICAL
    elif any(h.risk_level == RiskLevel.HIGH for h in homographs):
        risk_level = RiskLevel.HIGH
    elif mixed_scripts:
        risk_level = RiskLevel.HIGH
    elif any(h.risk_level == RiskLevel.MEDIUM for h in homographs):
        risk_level = RiskLevel.MEDIUM
    elif homographs:
        risk_level = RiskLevel.LOW
    else:
        risk_level = RiskLevel.SAFE

    # Generate recommendations
    recommendations = []
    if risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        recommendations.append("DANGER: This URL may be a phishing attempt using lookalike characters")
        recommendations.append(f"Normalized URL: {normalize_text(url)}")
    if mixed_scripts:
        recommendations.append("WARNING: URL contains mixed scripts which is a common attack pattern")
    if homographs:
        recommendations.append(f"Found {len(homographs)} suspicious characters")

    # Parse URL to check domain specifically
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            domain_homographs = detect_homographs(parsed.netloc)
            if domain_homographs:
                recommendations.append(
                    f"CRITICAL: Domain contains {len(domain_homographs)} suspicious characters"
                )
    except Exception:
        pass

    return SecurityCheckResult(
        original=url,
        normalized=normalize_text(url),
        is_safe=risk_level == RiskLevel.SAFE,
        risk_level=risk_level,
        homographs=homographs,
        mixed_scripts=mixed_scripts,
        scripts_found=scripts_found,
        recommendations=recommendations,
    )


def validate_url(url: str, strict: bool = True) -> tuple[bool, str]:
    """
    Validate URL for security issues.

    Args:
        url: URL to validate.
        strict: If True, reject any suspicious URLs.

    Returns:
        Tuple of (is_valid, message).
    """
    result = check_url_security(url)

    if result.is_safe:
        return True, "URL is safe"

    if strict:
        if result.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            return False, f"URL blocked: {'; '.join(result.recommendations)}"

    # For non-strict mode, warn but allow
    logger.warning(
        "url_security_warning",
        url=url,
        risk_level=result.risk_level.value,
        homographs=len(result.homographs),
    )

    return True, f"Warning: {'; '.join(result.recommendations)}"


def sanitize_input(text: str, context: str = "general") -> str:
    """
    Sanitize user input by normalizing potentially dangerous characters.

    Args:
        text: Input text to sanitize.
        context: Context for sanitization ("url", "command", "general").

    Returns:
        Sanitized text.
    """
    if context == "url":
        # For URLs, be aggressive about normalization
        return normalize_text(text, aggressive=True)
    elif context == "command":
        # For commands, normalize and warn
        result = detect_homographs(text)
        if result:
            logger.warning(
                "homograph_in_command",
                original=text,
                homographs=len(result),
            )
        return normalize_text(text, aggressive=False)
    else:
        # For general text, just normalize known lookalikes
        return normalize_text(text, aggressive=False)


# Export key functions
__all__ = [
    # Data classes
    'RiskLevel',
    'HomographResult',
    'SecurityCheckResult',
    # Detection functions
    'detect_homographs',
    'detect_homograph_bypass',
    'normalize_text',
    'check_url_security',
    'validate_url',
    'sanitize_input',
    'get_script',
    # Constants (for reuse)
    'CYRILLIC_LOOKALIKES',
    'GREEK_LOOKALIKES',
    'ALL_LOOKALIKES',
    'CONFUSABLES',
    'ZERO_WIDTH_CHARS',
    'DANGEROUS_SCRIPTS',
]
