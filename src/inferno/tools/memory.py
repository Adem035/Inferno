"""
Memory tool for Inferno.

This module provides a dual memory system using Qdrant for persistent storage:

1. Episodic Memory: Per-target collection (target_{target_id})
   - Stores chronological records of interactions and findings
   - Scoped to specific security targets/assessments
   - Uses collection name: "target_{sanitized_target}"

2. Semantic Memory: Global "_all_" collection
   - Enables cross-exercise knowledge transfer
   - Stores techniques, patterns, and generalizable knowledge
   - Uses collection name: "_all_"

The implementation bypasses Mem0 entirely for direct Qdrant integration,
avoiding dependencies and providing more control over the memory system.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import uuid
import warnings
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import structlog

from inferno.tools.base import HybridTool, ToolExample, ToolResult

if TYPE_CHECKING:
    from qdrant_client import QdrantClient
    from sentence_transformers import SentenceTransformer

logger = structlog.get_logger(__name__)


# Suppress noisy warnings
logging.getLogger("root").setLevel(logging.WARNING)
warnings.filterwarnings("ignore", message=".*Qdrant client version.*")


class EmbeddingCache:
    """LRU cache for embeddings to avoid redundant computation."""

    def __init__(self, embedder: Any, max_size: int = 1000) -> None:
        self._embedder = embedder
        self._cache: dict[str, list[float]] = {}
        self._max_size = max_size
        self._access_order: list[str] = []

    def embed(self, text: str) -> list[float]:
        """Get embedding with caching."""
        cache_key = hashlib.sha256(text.encode()).hexdigest()[:16]

        if cache_key in self._cache:
            # Move to end (most recently used)
            self._access_order.remove(cache_key)
            self._access_order.append(cache_key)
            return self._cache[cache_key]

        # Compute embedding
        embedding = self._embedder.encode(text).tolist()

        # LRU eviction
        if len(self._cache) >= self._max_size:
            oldest = self._access_order.pop(0)
            del self._cache[oldest]

        self._cache[cache_key] = embedding
        self._access_order.append(cache_key)
        return embedding

    def clear(self) -> None:
        """Clear the cache."""
        self._cache.clear()
        self._access_order.clear()


class QdrantConnector:
    """
    Direct Qdrant connector for vector storage.

    Bypasses Mem0 entirely for direct control over:
    - Collection management (episodic vs semantic)
    - Embedding generation using sentence_transformers
    - Vector storage and retrieval

    This class follows the CAI pattern but is adapted for Inferno's
    dual memory architecture.
    """

    # Default embedding configuration
    DEFAULT_MODEL = "all-MiniLM-L6-v2"
    DEFAULT_DIMENSION = 384

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6333,
        api_key: str | None = None,
        embedding_model: str | None = None,
        embedding_dimension: int | None = None,
        cache_size: int = 1000,
    ) -> None:
        """
        Initialize the Qdrant connector.

        Args:
            host: Qdrant server host.
            port: Qdrant server port.
            api_key: Optional API key for cloud Qdrant.
            embedding_model: Sentence transformer model name.
            embedding_dimension: Vector dimension (auto-detected if None).
            cache_size: Maximum embeddings to cache.
        """
        self._host = host
        self._port = port
        self._api_key = api_key
        self._embedding_model = embedding_model or self.DEFAULT_MODEL
        self._embedding_dimension = embedding_dimension or self.DEFAULT_DIMENSION
        self._cache_size = cache_size

        # Lazy initialization
        self._client: QdrantClient | None = None
        self._embedder: SentenceTransformer | None = None
        self._embedding_cache: EmbeddingCache | None = None

        # Track created collections
        self._collections: set[str] = set()

    def _get_client(self) -> QdrantClient:
        """Get or create Qdrant client."""
        if self._client is None:
            from qdrant_client import QdrantClient

            if self._api_key:
                # Cloud Qdrant
                self._client = QdrantClient(
                    host=self._host,
                    port=self._port,
                    api_key=self._api_key,
                )
            else:
                # Local Qdrant
                self._client = QdrantClient(
                    host=self._host,
                    port=self._port,
                )

            logger.info(
                "qdrant_client_initialized",
                host=self._host,
                port=self._port,
            )
        return self._client

    def _get_embedder(self) -> SentenceTransformer:
        """Get or create sentence transformer embedder."""
        if self._embedder is None:
            from sentence_transformers import SentenceTransformer

            self._embedder = SentenceTransformer(self._embedding_model)
            self._embedding_cache = EmbeddingCache(
                self._embedder,
                max_size=self._cache_size
            )

            logger.info(
                "embedder_initialized",
                model=self._embedding_model,
            )
        return self._embedder

    def _embed(self, text: str) -> list[float]:
        """Generate embedding for text with caching."""
        self._get_embedder()

        if self._embedding_cache:
            return self._embedding_cache.embed(text)

        # Fallback to direct embedding
        return self._embedder.encode(text).tolist()

    def create_collection(self, collection_name: str) -> bool:
        """
        Create a collection if it doesn't exist.

        Args:
            collection_name: Name of the collection to create.

        Returns:
            True if collection was created or already exists.
        """
        from qdrant_client.models import Distance, VectorParams

        client = self._get_client()

        try:
            if not client.collection_exists(collection_name):
                client.create_collection(
                    collection_name=collection_name,
                    vectors_config=VectorParams(
                        size=self._embedding_dimension,
                        distance=Distance.COSINE,
                    ),
                )
                logger.info(
                    "collection_created",
                    collection=collection_name,
                    dimension=self._embedding_dimension,
                )

            self._collections.add(collection_name)
            return True

        except Exception as e:
            logger.error("collection_create_failed", error=str(e))
            return False

    def add_points(
        self,
        collection_name: str,
        texts: list[str],
        metadata: list[dict[str, Any]] | None = None,
        id_point: str | int | None = None,
    ) -> bool:
        """
        Add points (texts with embeddings) to a collection.

        Args:
            collection_name: Target collection.
            texts: List of text content to embed and store.
            metadata: Optional list of metadata dicts (one per text).
            id_point: Optional point ID (auto-generated if None).

        Returns:
            True if points were added successfully.
        """
        from qdrant_client.models import PointStruct

        client = self._get_client()

        # Ensure collection exists
        self.create_collection(collection_name)

        points = []
        for i, text in enumerate(texts):
            # Generate embedding
            vector = self._embed(text)

            # Generate or use provided ID
            if id_point is not None:
                point_id = str(id_point) if isinstance(id_point, int) else id_point
            else:
                point_id = str(uuid.uuid4())

            # Build payload
            payload = {
                "text": text,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Add metadata if provided
            if metadata and i < len(metadata):
                payload["metadata"] = metadata[i]

            points.append(PointStruct(
                id=point_id,
                vector=vector,
                payload=payload,
            ))

        try:
            client.upsert(
                collection_name=collection_name,
                points=points,
            )

            logger.info(
                "points_added",
                collection=collection_name,
                count=len(points),
            )
            return True

        except Exception as e:
            logger.error("points_add_failed", error=str(e))
            return False

    def search(
        self,
        collection_name: str,
        query_text: str,
        limit: int = 10,
        score_threshold: float = 0.0,
    ) -> list[dict[str, Any]]:
        """
        Semantic search in a collection.

        Args:
            collection_name: Collection to search.
            query_text: Query text to embed and search.
            limit: Maximum results to return.
            score_threshold: Minimum similarity score (0.0-1.0).

        Returns:
            List of matching documents with scores.
        """
        client = self._get_client()

        # Check if collection exists
        if not client.collection_exists(collection_name):
            logger.warning("collection_not_found", collection=collection_name)
            return []

        # Generate query embedding
        query_vector = self._embed(query_text)

        try:
            results = client.search(
                collection_name=collection_name,
                query_vector=query_vector,
                limit=limit,
                score_threshold=score_threshold,
            )

            return [
                {
                    "id": str(hit.id),
                    "text": hit.payload.get("text", ""),
                    "score": hit.score,
                    "metadata": hit.payload.get("metadata", {}),
                    "timestamp": hit.payload.get("timestamp"),
                }
                for hit in results
            ]

        except Exception as e:
            logger.error("search_failed", error=str(e))
            return []

    def get_all(
        self,
        collection_name: str,
        limit: int = 100,
        memory_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Get all documents from a collection.

        Args:
            collection_name: Collection to query.
            limit: Maximum documents to return.
            memory_type: Optional filter by metadata.type field.

        Returns:
            List of all documents.
        """
        from qdrant_client.models import FieldCondition, Filter, MatchValue

        client = self._get_client()

        if not client.collection_exists(collection_name):
            return []

        try:
            # Build filter if memory_type specified
            scroll_filter = None
            if memory_type:
                scroll_filter = Filter(
                    must=[
                        FieldCondition(
                            key="metadata.type",
                            match=MatchValue(value=memory_type),
                        )
                    ]
                )

            results, _ = client.scroll(
                collection_name=collection_name,
                limit=limit,
                scroll_filter=scroll_filter,
            )

            return [
                {
                    "id": str(point.id),
                    "text": point.payload.get("text", ""),
                    "metadata": point.payload.get("metadata", {}),
                    "timestamp": point.payload.get("timestamp"),
                }
                for point in results
            ]

        except Exception as e:
            logger.error("get_all_failed", error=str(e))
            return []

    def delete_point(self, collection_name: str, point_id: str) -> bool:
        """Delete a point by ID."""
        client = self._get_client()

        try:
            client.delete(
                collection_name=collection_name,
                points_selector=[point_id],
            )
            return True
        except Exception as e:
            logger.error("delete_failed", error=str(e))
            return False

    def delete_collection(self, collection_name: str) -> bool:
        """Delete an entire collection."""
        client = self._get_client()

        try:
            client.delete_collection(collection_name=collection_name)
            self._collections.discard(collection_name)
            logger.info("collection_deleted", collection=collection_name)
            return True
        except Exception as e:
            logger.error("collection_delete_failed", error=str(e))
            return False

    def close(self) -> None:
        """Close the Qdrant client and release resources."""
        if self._client is not None:
            # QdrantClient doesn't have explicit close(), but we clear our reference
            self._client = None
            logger.info("qdrant_client_closed")
        if self._embedder is not None:
            self._embedder = None
            logger.info("embedder_released")
        if self._embedding_cache is not None:
            self._embedding_cache = None
        self._collections.clear()


# ============================================================================
# Dual Memory System Functions
# ============================================================================

# Global connector instance (lazy initialized)
_qdrant_connector: QdrantConnector | None = None


def _get_qdrant_connector() -> QdrantConnector:
    """Get or create the global Qdrant connector."""
    global _qdrant_connector

    if _qdrant_connector is None:
        # Read configuration from environment
        host = os.getenv("INFERNO_MEMORY__QDRANT_HOST", "localhost")
        port = int(os.getenv("INFERNO_MEMORY__QDRANT_PORT", "6333"))
        api_key = os.getenv("INFERNO_MEMORY__QDRANT_API_KEY")

        _qdrant_connector = QdrantConnector(
            host=host,
            port=port,
            api_key=api_key,
        )

    return _qdrant_connector


def cleanup_qdrant_connector() -> None:
    """
    Close and release the global Qdrant connector.

    Call this function during application shutdown to properly release resources.
    """
    global _qdrant_connector

    if _qdrant_connector is not None:
        _qdrant_connector.close()
        _qdrant_connector = None
        logger.info("global_qdrant_connector_closed")


def _sanitize_target_id(target: str) -> str:
    """
    Sanitize target string for use as collection name.

    Converts URLs like 'https://example.com:8080/path' to 'example_com'
    and handles special characters.
    """
    from urllib.parse import urlparse

    # Parse URL to extract hostname
    if "://" in target:
        parsed = urlparse(target)
        sanitized = parsed.netloc or parsed.path
    else:
        sanitized = target

    # Remove port if present
    sanitized = sanitized.split(":")[0]

    # Replace problematic characters with underscores
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', sanitized)

    # Remove leading/trailing underscores and collapse multiple underscores
    sanitized = re.sub(r'_+', '_', sanitized).strip('_')

    return sanitized.lower() or "unknown_target"


def get_episodic_collection_name(target: str) -> str:
    """Get the collection name for episodic memory (per-target)."""
    sanitized = _sanitize_target_id(target)
    return f"target_{sanitized}"


def get_semantic_collection_name() -> str:
    """Get the collection name for semantic memory (global)."""
    return "_all_"


def write_to_episodic_memory(
    target: str,
    content: str,
    metadata: dict[str, Any] | None = None,
    step: int = 0,
) -> bool:
    """
    Write to episodic memory (per-target collection).

    Episodic memory stores chronological records of interactions,
    findings, and progress for a specific target/assessment.

    Args:
        target: Target identifier (URL, hostname, IP).
        content: Content to store.
        metadata: Optional metadata dict.
        step: Step number in the assessment.

    Returns:
        True if write was successful.
    """
    connector = _get_qdrant_connector()
    collection_name = get_episodic_collection_name(target)

    # Enrich metadata
    enriched_metadata = {
        "target": target,
        "step": step,
        "memory_type": "episodic",
        **(metadata or {}),
    }

    return connector.add_points(
        collection_name=collection_name,
        texts=[content],
        metadata=[enriched_metadata],
        id_point=step if step > 0 else None,
    )


def write_to_semantic_memory(
    content: str,
    metadata: dict[str, Any] | None = None,
    source_target: str | None = None,
) -> bool:
    """
    Write to semantic memory (global "_all_" collection).

    Semantic memory stores generalizable knowledge that can transfer
    across different targets/assessments. This includes:
    - Attack techniques and procedures
    - Vulnerability patterns
    - Successful exploitation methods

    Note: Content should NOT include target-specific PII like IPs,
    hostnames, or credentials. Focus on techniques and patterns.

    Args:
        content: Content to store (techniques, not target-specific data).
        metadata: Optional metadata dict.
        source_target: Original target where this was learned (for reference).

    Returns:
        True if write was successful.
    """
    connector = _get_qdrant_connector()
    collection_name = get_semantic_collection_name()

    # Enrich metadata
    enriched_metadata = {
        "memory_type": "semantic",
        **(metadata or {}),
    }

    if source_target:
        enriched_metadata["source_target"] = _sanitize_target_id(source_target)

    return connector.add_points(
        collection_name=collection_name,
        texts=[content],
        metadata=[enriched_metadata],
    )


def search_episodic_memory(
    target: str,
    query: str,
    limit: int = 5,
    threshold: float = 0.5,
) -> list[dict[str, Any]]:
    """
    Search episodic memory for a specific target.

    Args:
        target: Target identifier.
        query: Search query.
        limit: Maximum results.
        threshold: Minimum similarity score.

    Returns:
        List of matching documents.
    """
    connector = _get_qdrant_connector()
    collection_name = get_episodic_collection_name(target)

    return connector.search(
        collection_name=collection_name,
        query_text=query,
        limit=limit,
        score_threshold=threshold,
    )


def search_semantic_memory(
    query: str,
    limit: int = 5,
    threshold: float = 0.5,
) -> list[dict[str, Any]]:
    """
    Search semantic memory (global knowledge).

    Args:
        query: Search query.
        limit: Maximum results.
        threshold: Minimum similarity score.

    Returns:
        List of matching documents.
    """
    connector = _get_qdrant_connector()
    collection_name = get_semantic_collection_name()

    return connector.search(
        collection_name=collection_name,
        query_text=query,
        limit=limit,
        score_threshold=threshold,
    )


def get_previous_memory(
    query: str,
    target: str | None = None,
    include_semantic: bool = True,
    include_episodic: bool = True,
    limit: int = 5,
    threshold: float = 0.3,
) -> str:
    """
    Get previous memory for RAG (Retrieval Augmented Generation).

    This function retrieves relevant context from both episodic and
    semantic memory to augment the agent's prompt with historical
    knowledge.

    Args:
        query: Query describing what to retrieve.
        target: Optional target for episodic memory search.
        include_semantic: Include global semantic memory.
        include_episodic: Include target-specific episodic memory.
        limit: Maximum results per memory type.
        threshold: Minimum similarity score.

    Returns:
        Formatted string with relevant memories for prompt injection.
    """
    results = []

    # Search semantic memory (global knowledge)
    if include_semantic:
        semantic_results = search_semantic_memory(
            query=query,
            limit=limit,
            threshold=threshold,
        )

        if semantic_results:
            results.append("=== Global Knowledge (Semantic Memory) ===")
            for i, doc in enumerate(semantic_results, 1):
                score = doc.get("score", 0)
                text = doc.get("text", "")
                results.append(f"[{i}] (score: {score:.2f}) {text[:500]}")
            results.append("")

    # Search episodic memory (target-specific)
    if include_episodic and target:
        episodic_results = search_episodic_memory(
            target=target,
            query=query,
            limit=limit,
            threshold=threshold,
        )

        if episodic_results:
            results.append(f"=== Target History (Episodic Memory: {target}) ===")
            for i, doc in enumerate(episodic_results, 1):
                score = doc.get("score", 0)
                text = doc.get("text", "")
                step = doc.get("metadata", {}).get("step", "?")
                results.append(f"[{i}] (step {step}, score: {score:.2f}) {text[:500]}")
            results.append("")

    if not results:
        return "No relevant memories found."

    return "\n".join(results)


def write_key_findings(
    target: str,
    findings: str,
    severity: str = "info",
    category: str = "general",
    metadata: dict[str, Any] | None = None,
) -> bool:
    """
    Write key findings to BOTH episodic and semantic memory.

    Key findings are important enough to store in both:
    - Episodic: Full details with target-specific context
    - Semantic: Generalized technique/pattern (stripped of PII)

    Args:
        target: Target identifier.
        findings: The findings content.
        severity: Severity level (critical, high, medium, low, info).
        category: Finding category (vuln, credential, foothold, etc.).
        metadata: Additional metadata.

    Returns:
        True if both writes succeeded.
    """
    enriched_metadata = {
        "severity": severity,
        "category": category,
        **(metadata or {}),
    }

    # Write full findings to episodic memory (with target context)
    episodic_success = write_to_episodic_memory(
        target=target,
        content=findings,
        metadata=enriched_metadata,
    )

    # For semantic memory, strip target-specific details
    # The LLM should ideally do this, but we provide a basic version
    generalized_content = _generalize_for_semantic(findings, target)

    semantic_metadata = {
        **enriched_metadata,
        "source_target": _sanitize_target_id(target),
    }

    semantic_success = write_to_semantic_memory(
        content=generalized_content,
        metadata=semantic_metadata,
        source_target=target,
    )

    return episodic_success and semantic_success


def read_key_findings(
    target: str | None = None,
    query: str = "security findings vulnerabilities",
    limit: int = 10,
) -> list[dict[str, Any]]:
    """
    Read key findings from memory.

    If target is provided, reads from episodic memory.
    Otherwise, reads from semantic memory.

    Args:
        target: Optional target for episodic search.
        query: Search query.
        limit: Maximum results.

    Returns:
        List of finding documents.
    """
    if target:
        return search_episodic_memory(
            target=target,
            query=query,
            limit=limit,
            threshold=0.3,
        )
    else:
        return search_semantic_memory(
            query=query,
            limit=limit,
            threshold=0.3,
        )


def _generalize_for_semantic(content: str, target: str) -> str:
    """
    Generalize content for semantic memory by removing target-specific details.

    This is a basic implementation. For production, an LLM should do this
    to properly extract and generalize the technique/pattern.
    """
    # Remove IP addresses
    generalized = re.sub(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        '[IP_ADDRESS]',
        content
    )

    # Remove the target hostname/URL
    if target:
        sanitized_target = _sanitize_target_id(target)
        # Replace variations of the target
        patterns = [
            re.escape(target),
            re.escape(sanitized_target),
            re.escape(target.replace('.', '_')),
        ]
        for pattern in patterns:
            generalized = re.sub(
                pattern,
                '[TARGET]',
                generalized,
                flags=re.IGNORECASE,
            )

    # Remove common port patterns that might be specific
    generalized = re.sub(
        r':\d{2,5}\b',
        ':[PORT]',
        generalized
    )

    return generalized


# ============================================================================
# Fallback Storage (used when Qdrant is unavailable)
# ============================================================================

class InMemoryStorage:
    """
    In-memory storage fallback when Qdrant is unavailable.

    This provides basic memory functionality for testing and
    environments without Qdrant.
    """

    def __init__(self) -> None:
        self._memories: dict[str, dict[str, Any]] = {}
        self._counter = 0

    def add(
        self,
        content: str,
        user_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Add a memory."""
        self._counter += 1
        memory_id = f"mem_{self._counter}"

        self._memories[memory_id] = {
            "id": memory_id,
            "memory": content,
            "user_id": user_id,
            "metadata": metadata or {},
        }

        return {"id": memory_id}

    def search(
        self,
        query: str,
        user_id: str,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Search memories (basic substring match for fallback)."""
        results = []
        query_lower = query.lower()

        for memory in self._memories.values():
            if memory["user_id"] == user_id:
                content = memory["memory"].lower()
                if query_lower in content:
                    results.append({**memory, "score": 0.8})

        return results[:limit]

    def get(self, memory_id: str) -> dict[str, Any] | None:
        """Get a memory by ID."""
        return self._memories.get(memory_id)

    def get_all(self, user_id: str) -> list[dict[str, Any]]:
        """Get all memories for a user."""
        return [m for m in self._memories.values() if m["user_id"] == user_id]

    def delete(self, memory_id: str) -> None:
        """Delete a memory."""
        if memory_id in self._memories:
            del self._memories[memory_id]


# ============================================================================
# Memory Tool
# ============================================================================

class MemoryTool(HybridTool):
    """
    Dual memory tool for persistent knowledge storage and retrieval.

    This is a hybrid tool that can be called both directly by Claude
    and from the code execution sandbox. It uses the dual memory system:

    1. Episodic Memory (per-target): Target-specific findings and progress
    2. Semantic Memory (global): Generalizable techniques and patterns

    Memory types:
    - findings: Security findings, vulnerabilities, misconfigurations
    - context: Target context, environment info, credentials discovered
    - knowledge: General knowledge, techniques, attack patterns
    - checkpoint: Assessment progress checkpoints
    - hypothesis: Vulnerability hypotheses with confidence levels
    - todo: Things to test later, follow-up items
    - dead_end: Approaches that didn't work (prevent loops)
    - interesting: Interesting observations not yet exploitable
    - identifier: Discovered IDs for cross-reference testing
    - credential: Structured credential vault with testing state tracking
    - attack_chain: Multi-step exploitation paths linking findings
    - foothold: Active access points (shells, sessions, persistence)
    - defense: WAF/security observations and bypass strategies
    - payload: Successful payloads for reuse
    - enumeration: Track what's been enumerated vs pending
    - evidence: Request/response pairs and proof artifacts
    - false_positive: Things that looked promising but weren't
    """

    @property
    def name(self) -> str:
        return "memory"

    @property
    def description(self) -> str:
        return (
            "Store and retrieve information using dual memory (episodic + semantic). "
            "Use this to persist findings, target context, credentials, and progress. "
            "Operations: store (save to episodic/semantic), search (semantic search), "
            "recall (get by ID), list (show recent), delete (remove memory). "
            "Memory persists across sessions with semantic similarity search."
        )

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["store", "search", "recall", "list", "delete", "checkpoint", "key_finding"],
                    "description": "Memory operation to perform",
                },
                "content": {
                    "type": "string",
                    "description": "Content to store (for store operation) or search query (for search)",
                },
                "memory_type": {
                    "type": "string",
                    "enum": [
                        # Core types
                        "findings", "context", "knowledge", "checkpoint",
                        "hypothesis", "todo", "dead_end", "interesting", "identifier",
                        # Pentester-focused types
                        "credential", "attack_chain", "foothold", "defense",
                        "payload", "enumeration", "evidence", "false_positive"
                    ],
                    "description": "Type of memory for categorization.",
                    "default": "findings",
                },
                "memory_scope": {
                    "type": "string",
                    "enum": ["episodic", "semantic", "both"],
                    "description": "Memory scope: episodic (per-target), semantic (global), or both",
                    "default": "episodic",
                },
                "target": {
                    "type": "string",
                    "description": "Target identifier for episodic memory (URL, hostname, IP)",
                },
                "memory_id": {
                    "type": "string",
                    "description": "Memory ID (for recall/delete operations)",
                },
                "metadata": {
                    "type": "object",
                    "description": "Additional metadata to store with the memory",
                    "additionalProperties": True,
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return",
                    "default": 10,
                    "minimum": 1,
                    "maximum": 100,
                },
                "threshold": {
                    "type": "number",
                    "description": "Minimum similarity threshold for search (0.0-1.0)",
                    "default": 0.5,
                    "minimum": 0.0,
                    "maximum": 1.0,
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "Severity level for key findings",
                    "default": "info",
                },
            },
            "required": ["operation"],
        }

    @property
    def examples(self) -> list[ToolExample]:
        return [
            ToolExample(
                description="Store a finding to episodic memory (per-target)",
                input={
                    "operation": "store",
                    "content": "SQL injection vulnerability in /api/users endpoint. Parameter 'id' is vulnerable to UNION-based injection.",
                    "memory_type": "findings",
                    "memory_scope": "episodic",
                    "target": "https://example.com",
                    "metadata": {
                        "severity": "high",
                        "endpoint": "/api/users",
                        "technique": "UNION-based SQLi",
                    },
                },
            ),
            ToolExample(
                description="Store a technique to semantic memory (global knowledge)",
                input={
                    "operation": "store",
                    "content": "When WAF blocks UNION SELECT, try XML-based injection with EXTRACTVALUE() or UpdateXML() functions.",
                    "memory_type": "knowledge",
                    "memory_scope": "semantic",
                    "metadata": {
                        "category": "waf_bypass",
                        "technique": "XML-based SQLi",
                    },
                },
            ),
            ToolExample(
                description="Store key finding to BOTH memories",
                input={
                    "operation": "key_finding",
                    "content": "Critical RCE via command injection in filename parameter. Payload: '; whoami #' returns www-data.",
                    "target": "https://example.com",
                    "severity": "critical",
                    "metadata": {
                        "endpoint": "/upload",
                        "parameter": "filename",
                        "technique": "command_injection",
                    },
                },
            ),
            ToolExample(
                description="Search for relevant findings across all targets",
                input={
                    "operation": "search",
                    "content": "SQL injection bypass techniques",
                    "memory_scope": "semantic",
                    "limit": 5,
                },
            ),
            ToolExample(
                description="Search for findings on specific target",
                input={
                    "operation": "search",
                    "content": "authentication vulnerabilities",
                    "memory_scope": "episodic",
                    "target": "https://example.com",
                    "limit": 5,
                },
            ),
            ToolExample(
                description="List recent findings for target",
                input={
                    "operation": "list",
                    "memory_type": "findings",
                    "target": "https://example.com",
                    "limit": 10,
                },
            ),
        ]

    def __init__(
        self,
        operation_id: str | None = None,
        qdrant_host: str = "localhost",
        qdrant_port: int = 6333,
        qdrant_collection: str = "inferno_memories",
        embedding_provider: str = "sentence_transformers",
        embedding_model: str | None = None,
        ollama_host: str = "http://localhost:11434",
        api_key: str | None = None,
    ) -> None:
        """
        Initialize the memory tool.

        Args:
            operation_id: Current operation identifier for scoping.
            qdrant_host: Qdrant server host.
            qdrant_port: Qdrant server port.
            qdrant_collection: Legacy Qdrant collection name.
            embedding_provider: Embedding provider (sentence_transformers recommended).
            embedding_model: Embedding model name.
            ollama_host: Ollama server URL (for ollama provider).
            api_key: API key for cloud providers.
        """
        self._operation_id = operation_id
        self._qdrant_host = qdrant_host
        self._qdrant_port = qdrant_port
        self._qdrant_collection = qdrant_collection
        self._embedding_provider = embedding_provider
        self._embedding_model = embedding_model
        self._ollama_host = ollama_host
        self._api_key = api_key

        # Current target for episodic memory scoping
        self._current_target: str | None = None

        # Initialize connector
        self._connector: QdrantConnector | None = None
        self._fallback: InMemoryStorage | None = None
        self._initialized = False

    def _get_connector(self) -> QdrantConnector | InMemoryStorage:
        """Get the memory storage backend."""
        if self._connector is None:
            try:
                self._connector = QdrantConnector(
                    host=self._qdrant_host,
                    port=self._qdrant_port,
                    api_key=self._api_key,
                )
                # Test connection
                self._connector._get_client()
                self._initialized = True

                logger.info(
                    "memory_qdrant_initialized",
                    host=self._qdrant_host,
                    port=self._qdrant_port,
                )

            except Exception as e:
                logger.warning(
                    "memory_qdrant_failed_using_fallback",
                    error=str(e)[:100],
                )
                self._connector = None

                if self._fallback is None:
                    self._fallback = InMemoryStorage()

                return self._fallback

        return self._connector

    def set_target(self, target: str) -> None:
        """Set the current target for episodic memory scoping."""
        self._current_target = target
        logger.debug("memory_target_set", target=target)

    def set_operation_id(self, operation_id: str) -> None:
        """Update the operation ID for scoping."""
        self._operation_id = operation_id
        logger.debug("operation_id_updated", operation_id=operation_id)

    async def execute(
        self,
        operation: str,
        content: str | None = None,
        memory_type: str = "findings",
        memory_scope: str = "episodic",
        target: str | None = None,
        memory_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        limit: int = 10,
        threshold: float = 0.5,
        severity: str = "info",
        **kwargs: Any,
    ) -> ToolResult:
        """
        Execute a memory operation.

        Args:
            operation: The operation to perform.
            content: Content to store or search query.
            memory_type: Type of memory.
            memory_scope: Memory scope (episodic, semantic, both).
            target: Target for episodic memory.
            memory_id: Memory ID for recall/delete.
            metadata: Additional metadata.
            limit: Maximum results.
            threshold: Similarity threshold.
            severity: Severity for key findings.

        Returns:
            ToolResult with operation output.
        """
        logger.info(
            "memory_operation",
            operation=operation,
            memory_type=memory_type,
            memory_scope=memory_scope,
        )

        # Use current target if not specified
        effective_target = target or self._current_target

        try:
            if operation == "store":
                return await self._store(
                    content, memory_type, memory_scope,
                    effective_target, metadata
                )
            elif operation == "search":
                return await self._search(
                    content, memory_scope, effective_target,
                    limit, threshold
                )
            elif operation == "recall":
                return await self._recall(memory_id)
            elif operation == "list":
                return await self._list(
                    memory_type, effective_target, limit
                )
            elif operation == "delete":
                return await self._delete(memory_id)
            elif operation == "checkpoint":
                return await self._checkpoint(content, metadata, effective_target)
            elif operation == "key_finding":
                return await self._key_finding(
                    content, effective_target, severity,
                    memory_type, metadata
                )
            else:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"Unknown operation: {operation}",
                )
        except Exception as e:
            logger.error("memory_error", operation=operation, error=str(e), exc_info=True)
            return ToolResult(
                success=False,
                output="",
                error=f"Memory operation failed: {e}",
            )

    async def _store(
        self,
        content: str | None,
        memory_type: str,
        memory_scope: str,
        target: str | None,
        metadata: dict[str, Any] | None,
    ) -> ToolResult:
        """Store a new memory."""
        if not content:
            return ToolResult(
                success=False,
                output="",
                error="Content is required for store operation",
            )

        enriched_metadata = {
            "type": memory_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "operation_id": self._operation_id,
            **(metadata or {}),
        }

        success = False
        stored_locations = []

        # Handle episodic memory (requires target)
        if memory_scope in ("episodic", "both") and target:
            episodic_success = write_to_episodic_memory(
                target=target,
                content=content,
                metadata=enriched_metadata,
            )
            if episodic_success:
                stored_locations.append(f"episodic:{get_episodic_collection_name(target)}")
                success = True
        elif memory_scope == "episodic" and not target:
            # Fall back to semantic when episodic requested but no target
            logger.warning("memory_fallback", reason="No target for episodic, using semantic only")
            memory_scope = "semantic"

        # Handle semantic memory (no target required)
        if memory_scope in ("semantic", "both"):
            semantic_success = write_to_semantic_memory(
                content=content,
                metadata=enriched_metadata,
                source_target=target,
            )
            if semantic_success:
                stored_locations.append("semantic:_all_")
                success = True

        if not success:
            return ToolResult(
                success=False,
                output="",
                error="Failed to store memory",
            )

        output = "Memory stored successfully\n"
        output += f"Type: {memory_type}\n"
        output += f"Scope: {memory_scope}\n"
        output += f"Locations: {', '.join(stored_locations)}\n"
        output += f"Content: {content[:200]}{'...' if len(content) > 200 else ''}"

        return ToolResult(
            success=True,
            output=output,
            metadata={
                "memory_type": memory_type,
                "memory_scope": memory_scope,
                "stored_locations": stored_locations,
            },
        )

    async def _search(
        self,
        query: str | None,
        memory_scope: str,
        target: str | None,
        limit: int,
        threshold: float,
    ) -> ToolResult:
        """Search memories by semantic similarity."""
        if not query:
            return ToolResult(
                success=False,
                output="",
                error="Query content is required for search operation",
            )

        results = []

        if memory_scope in ("semantic", "both"):
            semantic_results = search_semantic_memory(
                query=query,
                limit=limit,
                threshold=threshold,
            )
            for r in semantic_results:
                r["source"] = "semantic"
                results.append(r)

        if memory_scope in ("episodic", "both") and target:
            episodic_results = search_episodic_memory(
                target=target,
                query=query,
                limit=limit,
                threshold=threshold,
            )
            for r in episodic_results:
                r["source"] = "episodic"
                results.append(r)

        if not results:
            return ToolResult(
                success=True,
                output=f"No memories found matching '{query}' with threshold {threshold}",
                metadata={"count": 0, "query": query},
            )

        # Sort by score descending
        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        results = results[:limit]

        # Format results
        output_parts = [f"Found {len(results)} relevant memories:\n"]

        for i, result in enumerate(results, 1):
            text = result.get("text", "")
            score = result.get("score", 0)
            source = result.get("source", "unknown")
            mem_metadata = result.get("metadata", {})

            score_pct = f"{score * 100:.0f}%"
            content_preview = text[:300] + "..." if len(text) > 300 else text

            output_parts.append(f"\n[{i}] Score: {score_pct} | Source: {source}")
            output_parts.append(f"    {content_preview}")

            # Show key metadata
            if mem_metadata:
                key_fields = ["type", "severity", "endpoint", "technique"]
                meta_parts = [f"{k}={v}" for k, v in mem_metadata.items() if k in key_fields]
                if meta_parts:
                    output_parts.append(f"    [{', '.join(meta_parts)}]")

        return ToolResult(
            success=True,
            output="\n".join(output_parts),
            metadata={"count": len(results), "query": query},
        )

    async def _recall(self, memory_id: str | None) -> ToolResult:
        """Recall a specific memory by ID."""
        if not memory_id:
            return ToolResult(
                success=False,
                output="",
                error="memory_id is required for recall operation",
            )

        # Not implemented for direct Qdrant - would need scroll with filter
        return ToolResult(
            success=False,
            output="",
            error="Recall by ID not supported in dual memory mode. Use search instead.",
        )

    async def _list(
        self,
        memory_type: str,
        target: str | None,
        limit: int,
    ) -> ToolResult:
        """List recent memories."""
        connector = self._get_connector()

        if isinstance(connector, InMemoryStorage):
            # Fallback
            results = connector.get_all(user_id=memory_type)
            results = results[:limit]
        else:
            # Use episodic collection if target provided
            if target:
                collection_name = get_episodic_collection_name(target)
            else:
                collection_name = get_semantic_collection_name()

            results = connector.get_all(
                collection_name=collection_name,
                limit=limit,
                memory_type=memory_type if memory_type != "all" else None,
            )

        if not results:
            return ToolResult(
                success=True,
                output=f"No memories found for type: {memory_type}",
                metadata={"count": 0, "memory_type": memory_type},
            )

        output_parts = [f"Memories ({memory_type}): {len(results)} items\n"]

        for i, result in enumerate(results, 1):
            text = result.get("text", result.get("memory", ""))
            mem_id = result.get("id", "N/A")
            mem_metadata = result.get("metadata", {}) or {}
            timestamp = result.get("timestamp", mem_metadata.get("timestamp", "N/A"))

            content_preview = text[:250] + "..." if len(str(text)) > 250 else text

            output_parts.append(f"\n[{i}] {timestamp}")
            output_parts.append(f"    ID: {str(mem_id)[:36]}")
            output_parts.append(f"    {content_preview}")

        return ToolResult(
            success=True,
            output="\n".join(output_parts),
            metadata={"count": len(results), "memory_type": memory_type},
        )

    async def _delete(self, memory_id: str | None) -> ToolResult:
        """Delete a memory by ID."""
        if not memory_id:
            return ToolResult(
                success=False,
                output="",
                error="memory_id is required for delete operation",
            )

        # Note: Would need to specify collection to delete from
        return ToolResult(
            success=False,
            output="",
            error="Delete by ID not fully supported. Use collection management instead.",
        )

    async def _checkpoint(
        self,
        content: str | None,
        metadata: dict[str, Any] | None,
        target: str | None,
    ) -> ToolResult:
        """Create an assessment checkpoint."""
        if not content:
            return ToolResult(
                success=False,
                output="",
                error="Content is required for checkpoint operation",
            )

        checkpoint_metadata = {
            "checkpoint": True,
            "checkpoint_time": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        }

        return await self._store(
            content, "checkpoint", "episodic",
            target, checkpoint_metadata
        )

    async def _key_finding(
        self,
        content: str | None,
        target: str | None,
        severity: str,
        memory_type: str,
        metadata: dict[str, Any] | None,
    ) -> ToolResult:
        """Store a key finding to BOTH episodic and semantic memory."""
        if not content:
            return ToolResult(
                success=False,
                output="",
                error="Content is required for key_finding operation",
            )

        if not target:
            return ToolResult(
                success=False,
                output="",
                error="Target is required for key_finding operation",
            )

        success = write_key_findings(
            target=target,
            findings=content,
            severity=severity,
            category=memory_type,
            metadata=metadata,
        )

        if success:
            return ToolResult(
                success=True,
                output=f"Key finding stored to both episodic and semantic memory\n"
                       f"Target: {target}\n"
                       f"Severity: {severity}\n"
                       f"Content: {content[:200]}...",
                metadata={
                    "memory_scope": "both",
                    "severity": severity,
                },
            )
        else:
            return ToolResult(
                success=False,
                output="",
                error="Failed to store key finding",
            )


class MemoryToolWithFallback(MemoryTool):
    """
    Memory tool with automatic fallback chain.

    Fallback order:
    1. QdrantConnector (direct Qdrant + sentence_transformers)
    2. InMemoryStorage (if Qdrant is unavailable)

    This is now the default MemoryTool behavior, kept for backwards compatibility.
    """
    pass
