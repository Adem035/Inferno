"""
Shared Knowledge Graph for Inferno.

This module provides a centralized knowledge store that ALL agents can access,
solving the "telephone game" problem where context is lost between sub-agents.

Key features:
- Global singleton - one knowledge graph for entire swarm
- No operation scoping - truly shared across all agents
- Agent attribution - track who discovered what
- Instant availability - no copy-paste needed
- Semantic search - find related knowledge automatically
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

import structlog

logger = structlog.get_logger(__name__)


class KnowledgeType(str, Enum):
    """Types of knowledge entries."""

    FINDING = "finding"  # Security vulnerability, weakness
    CREDENTIAL = "credential"  # Discovered credentials
    ENDPOINT = "endpoint"  # Discovered endpoint/URL
    TECHNOLOGY = "technology"  # Tech stack info
    CONFIGURATION = "configuration"  # Config/setting found
    CONTEXT = "context"  # General context about target
    HYPOTHESIS = "hypothesis"  # Unconfirmed suspicion
    EVIDENCE = "evidence"  # Proof/screenshot/response
    RELATIONSHIP = "relationship"  # Connection between entities
    HINT = "hint"  # Extracted hint from response/content
    BYPASS = "bypass"  # Successful bypass technique
    BASELINE = "baseline"  # Response baseline for differential analysis


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class KnowledgeEntry:
    """A single piece of knowledge in the graph."""

    id: str
    content: str
    knowledge_type: KnowledgeType
    source_agent: str  # Who discovered this
    target: str  # Which target this relates to
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Optional enrichment
    severity: Severity | None = None
    confidence: float = 1.0  # 0.0-1.0 how confident we are
    location: str | None = None  # Specific location (URL, file, etc.)
    evidence: str | None = None  # Supporting evidence
    metadata: dict[str, Any] = field(default_factory=dict)

    # Relationships
    related_to: list[str] = field(default_factory=list)  # IDs of related entries
    tags: list[str] = field(default_factory=list)

    # Vector embedding (populated by KnowledgeGraph)
    embedding: list[float] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "content": self.content,
            "knowledge_type": self.knowledge_type.value,
            "source_agent": self.source_agent,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "severity": self.severity.value if self.severity else None,
            "confidence": self.confidence,
            "location": self.location,
            "evidence": self.evidence,
            "metadata": self.metadata,
            "related_to": self.related_to,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KnowledgeEntry:
        """Create from dictionary."""
        return cls(
            id=data["id"],
            content=data["content"],
            knowledge_type=KnowledgeType(data["knowledge_type"]),
            source_agent=data["source_agent"],
            target=data["target"],
            created_at=datetime.fromisoformat(data["created_at"]),
            severity=Severity(data["severity"]) if data.get("severity") else None,
            confidence=data.get("confidence", 1.0),
            location=data.get("location"),
            evidence=data.get("evidence"),
            metadata=data.get("metadata", {}),
            related_to=data.get("related_to", []),
            tags=data.get("tags", []),
        )


class KnowledgeGraph:
    """
    Shared knowledge graph accessible by all agents.

    This is the "shared brain" that solves the context loss problem.
    When Agent A discovers something, Agent B can immediately query for it.

    Uses Qdrant for vector storage and semantic search.
    """

    # Singleton instance
    _instance: KnowledgeGraph | None = None
    _lock: threading.Lock = threading.Lock()

    def __new__(cls, *args: Any, **kwargs: Any) -> KnowledgeGraph:
        """Ensure singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        qdrant_host: str = "localhost",
        qdrant_port: int = 6333,
        collection_name: str = "inferno_knowledge_graph",
    ) -> None:
        """Initialize the knowledge graph."""
        # Only initialize once
        if getattr(self, "_initialized", False):
            return

        self._qdrant_host = qdrant_host
        self._qdrant_port = qdrant_port
        self._collection_name = collection_name

        # In-memory cache for fast lookups
        self._entries: dict[str, KnowledgeEntry] = {}
        self._by_type: dict[KnowledgeType, list[str]] = {t: [] for t in KnowledgeType}
        self._by_target: dict[str, list[str]] = {}
        self._by_agent: dict[str, list[str]] = {}

        # Qdrant client and embedder (lazy init)
        self._client = None
        self._embedder = None
        self._embedding_dim = 384  # all-MiniLM-L6-v2

        # Async lock for thread safety
        self._async_lock = asyncio.Lock()

        # Flag to track if we've loaded from Qdrant
        self._loaded_from_storage = False

        self._initialized = True
        logger.info(
            "knowledge_graph_initialized",
            qdrant_host=qdrant_host,
            collection=collection_name,
        )

    async def _load_from_qdrant(self) -> int:
        """Load existing knowledge from Qdrant into memory cache."""
        if self._loaded_from_storage:
            return len(self._entries)

        client = self._get_client()
        if not client:
            self._loaded_from_storage = True
            return 0

        try:
            # Scroll through all points in the collection
            offset = None
            loaded_count = 0

            while True:
                results, offset = client.scroll(
                    collection_name=self._collection_name,
                    limit=100,
                    offset=offset,
                    with_payload=True,
                    with_vectors=False,
                )

                if not results:
                    break

                for point in results:
                    try:
                        entry = KnowledgeEntry.from_dict(point.payload)
                        entry_id = str(point.id)

                        # Add to in-memory caches
                        self._entries[entry_id] = entry
                        self._by_type[entry.knowledge_type].append(entry_id)

                        if entry.target not in self._by_target:
                            self._by_target[entry.target] = []
                        self._by_target[entry.target].append(entry_id)

                        if entry.source_agent not in self._by_agent:
                            self._by_agent[entry.source_agent] = []
                        self._by_agent[entry.source_agent].append(entry_id)

                        loaded_count += 1
                    except Exception as e:
                        logger.warning("failed_to_load_entry", error=str(e))
                        continue

                if offset is None:
                    break

            self._loaded_from_storage = True
            logger.info(
                "knowledge_loaded_from_qdrant",
                count=loaded_count,
                collection=self._collection_name,
            )
            return loaded_count

        except Exception as e:
            logger.warning("qdrant_load_failed", error=str(e))
            self._loaded_from_storage = True
            return 0

    def _load_from_qdrant_sync(self) -> int:
        """Synchronous version for non-async contexts."""
        if self._loaded_from_storage:
            return len(self._entries)

        client = self._get_client()
        if not client:
            self._loaded_from_storage = True
            return 0

        try:
            offset = None
            loaded_count = 0

            while True:
                results, offset = client.scroll(
                    collection_name=self._collection_name,
                    limit=100,
                    offset=offset,
                    with_payload=True,
                    with_vectors=False,
                )

                if not results:
                    break

                for point in results:
                    try:
                        entry = KnowledgeEntry.from_dict(point.payload)
                        entry_id = str(point.id)

                        self._entries[entry_id] = entry
                        self._by_type[entry.knowledge_type].append(entry_id)

                        if entry.target not in self._by_target:
                            self._by_target[entry.target] = []
                        self._by_target[entry.target].append(entry_id)

                        if entry.source_agent not in self._by_agent:
                            self._by_agent[entry.source_agent] = []
                        self._by_agent[entry.source_agent].append(entry_id)

                        loaded_count += 1
                    except Exception:
                        continue

                if offset is None:
                    break

            self._loaded_from_storage = True
            logger.info("knowledge_loaded_from_qdrant", count=loaded_count)
            return loaded_count

        except Exception as e:
            logger.warning("qdrant_load_failed", error=str(e))
            self._loaded_from_storage = True
            return 0

    def _get_client(self):
        """Get or create Qdrant client."""
        if self._client is None:
            try:
                from qdrant_client import QdrantClient
                from qdrant_client.models import Distance, VectorParams

                self._client = QdrantClient(
                    host=self._qdrant_host,
                    port=self._qdrant_port,
                    check_compatibility=False,
                )

                # Ensure collection exists
                if not self._client.collection_exists(self._collection_name):
                    self._client.create_collection(
                        collection_name=self._collection_name,
                        vectors_config=VectorParams(
                            size=self._embedding_dim,
                            distance=Distance.COSINE,
                        ),
                    )
                    logger.info("knowledge_collection_created", collection=self._collection_name)

            except Exception as e:
                logger.warning("qdrant_connection_failed", error=str(e))
                self._client = None

        return self._client

    def _get_embedder(self):
        """Get or create sentence transformer embedder."""
        if self._embedder is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._embedder = SentenceTransformer("all-MiniLM-L6-v2")
            except ImportError:
                logger.warning("sentence_transformers_not_available")
        return self._embedder

    def _embed(self, text: str) -> list[float] | None:
        """Generate embedding for text."""
        embedder = self._get_embedder()
        if embedder is None:
            return None
        try:
            embedding = embedder.encode(text, convert_to_numpy=True)
            return embedding.tolist()
        except Exception as e:
            logger.warning("embedding_failed", error=str(e))
            return None

    def _generate_id(self, content: str, source_agent: str) -> str:
        """Generate unique UUID for knowledge entry."""
        # Qdrant requires UUID format, not arbitrary hex strings
        hash_input = f"{content}:{source_agent}:{datetime.now(timezone.utc).isoformat()}"
        # Create a UUID from the hash (version 5, using DNS namespace as base)
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, hash_input))

    def _generate_content_hash(self, content: str, target: str, knowledge_type: KnowledgeType) -> str:
        """Generate a hash for content-based deduplication."""
        # Normalize content for comparison
        normalized = f"{content.lower().strip()}:{target}:{knowledge_type.value}"
        return hashlib.sha256(normalized.encode()).hexdigest()[:32]

    def _find_duplicate(
        self,
        content: str,
        target: str,
        knowledge_type: KnowledgeType,
    ) -> KnowledgeEntry | None:
        """Find an existing duplicate entry."""
        content_hash = self._generate_content_hash(content, target, knowledge_type)
        content_lower = content.lower().strip()

        # Check existing entries for similar content
        for entry in self._entries.values():
            if entry.target != target:
                continue
            if entry.knowledge_type != knowledge_type:
                continue
            # Check for exact or near-exact match
            existing_lower = entry.content.lower().strip()
            if existing_lower == content_lower:
                return entry
            # Check hash match (for faster comparison)
            existing_hash = self._generate_content_hash(entry.content, entry.target, entry.knowledge_type)
            if existing_hash == content_hash:
                return entry

        return None

    async def add(
        self,
        content: str,
        knowledge_type: KnowledgeType | str,
        source_agent: str,
        target: str,
        severity: Severity | str | None = None,
        confidence: float = 1.0,
        location: str | None = None,
        evidence: str | None = None,
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        related_to: list[str] | None = None,
        skip_duplicate_check: bool = False,
    ) -> KnowledgeEntry:
        """
        Add knowledge to the graph.

        This is immediately available to ALL agents.

        Args:
            content: The knowledge content
            knowledge_type: Type of knowledge
            source_agent: Which agent discovered this
            target: Target this relates to
            severity: Severity level (for findings)
            confidence: Confidence level 0.0-1.0
            location: Specific location
            evidence: Supporting evidence
            metadata: Additional metadata
            tags: Searchable tags
            related_to: IDs of related entries
            skip_duplicate_check: Skip duplicate detection (use for related entries)

        Returns:
            The created KnowledgeEntry (or existing duplicate if found)
        """
        async with self._async_lock:
            # Normalize types
            if isinstance(knowledge_type, str):
                knowledge_type = KnowledgeType(knowledge_type)
            if isinstance(severity, str):
                severity = Severity(severity)

            # Check for duplicates unless explicitly skipped
            if not skip_duplicate_check:
                existing = self._find_duplicate(content, target, knowledge_type)
                if existing:
                    logger.debug(
                        "duplicate_knowledge_skipped",
                        existing_id=existing.id,
                        content_preview=content[:50],
                    )
                    # Update existing entry's confidence if new one is higher
                    if confidence > existing.confidence:
                        existing.confidence = confidence
                    # Merge tags
                    if tags:
                        for tag in tags:
                            if tag not in existing.tags:
                                existing.tags.append(tag)
                    return existing

            # Generate ID
            entry_id = self._generate_id(content, source_agent)

            # Create entry
            entry = KnowledgeEntry(
                id=entry_id,
                content=content,
                knowledge_type=knowledge_type,
                source_agent=source_agent,
                target=target,
                severity=severity,
                confidence=confidence,
                location=location,
                evidence=evidence,
                metadata=metadata or {},
                tags=tags or [],
                related_to=related_to or [],
            )

            # Generate embedding
            entry.embedding = self._embed(content)

            # Store in-memory
            self._entries[entry_id] = entry
            self._by_type[knowledge_type].append(entry_id)

            if target not in self._by_target:
                self._by_target[target] = []
            self._by_target[target].append(entry_id)

            if source_agent not in self._by_agent:
                self._by_agent[source_agent] = []
            self._by_agent[source_agent].append(entry_id)

            # Store in Qdrant if available
            client = self._get_client()
            if client and entry.embedding:
                try:
                    from qdrant_client.models import PointStruct

                    client.upsert(
                        collection_name=self._collection_name,
                        points=[
                            PointStruct(
                                id=entry_id,
                                vector=entry.embedding,
                                payload=entry.to_dict(),
                            )
                        ],
                    )
                except Exception as e:
                    logger.warning("qdrant_store_failed", error=str(e))

            logger.info(
                "knowledge_added",
                id=entry_id,
                type=knowledge_type.value,
                source=source_agent,
                target=target,
            )

            return entry

    async def search(
        self,
        query: str,
        target: str | None = None,
        knowledge_types: list[KnowledgeType | str] | None = None,
        min_confidence: float = 0.0,
        limit: int = 10,
    ) -> list[KnowledgeEntry]:
        """
        Search for relevant knowledge using semantic similarity.

        Args:
            query: Search query
            target: Filter by target
            knowledge_types: Filter by types
            min_confidence: Minimum confidence threshold
            limit: Maximum results

        Returns:
            List of matching KnowledgeEntry objects
        """
        # Load existing data from Qdrant first
        await self._load_from_qdrant()

        # Try Qdrant semantic search first
        client = self._get_client()
        if client:
            try:
                query_embedding = self._embed(query)
                if query_embedding:
                    from qdrant_client.models import Filter, FieldCondition, MatchValue

                    # Build filter conditions
                    must_conditions = []
                    if target:
                        must_conditions.append(
                            FieldCondition(key="target", match=MatchValue(value=target))
                        )

                    if knowledge_types:
                        type_values = [
                            t.value if isinstance(t, KnowledgeType) else t
                            for t in knowledge_types
                        ]
                        # Use should for OR logic across types
                        must_conditions.append(
                            FieldCondition(key="knowledge_type", match=MatchValue(value=type_values[0]))
                        )

                    results = client.search(
                        collection_name=self._collection_name,
                        query_vector=query_embedding,
                        query_filter=Filter(must=must_conditions) if must_conditions else None,
                        limit=limit,
                    )

                    entries = []
                    for hit in results:
                        entry = KnowledgeEntry.from_dict(hit.payload)
                        if entry.confidence >= min_confidence:
                            entries.append(entry)

                    return entries

            except Exception as e:
                logger.warning("qdrant_search_failed", error=str(e))

        # Fallback to in-memory search
        query_lower = query.lower()
        results = []

        for entry in self._entries.values():
            if target and entry.target != target:
                continue
            if knowledge_types:
                type_values = [
                    t.value if isinstance(t, KnowledgeType) else t
                    for t in knowledge_types
                ]
                if entry.knowledge_type.value not in type_values:
                    continue
            if entry.confidence < min_confidence:
                continue

            # Basic text match
            if query_lower in entry.content.lower():
                results.append(entry)

        return results[:limit]

    async def get(self, entry_id: str) -> KnowledgeEntry | None:
        """Get a specific knowledge entry by ID."""
        await self._load_from_qdrant()
        return self._entries.get(entry_id)

    async def get_by_type(
        self,
        knowledge_type: KnowledgeType | str,
        target: str | None = None,
        limit: int = 100,
    ) -> list[KnowledgeEntry]:
        """Get all entries of a specific type."""
        await self._load_from_qdrant()

        if isinstance(knowledge_type, str):
            knowledge_type = KnowledgeType(knowledge_type)

        entry_ids = self._by_type.get(knowledge_type, [])
        entries = []

        for eid in entry_ids:
            entry = self._entries.get(eid)
            if entry:
                if target and entry.target != target:
                    continue
                entries.append(entry)
                if len(entries) >= limit:
                    break

        return entries

    async def get_by_target(self, target: str, limit: int = 100) -> list[KnowledgeEntry]:
        """Get all knowledge for a specific target."""
        await self._load_from_qdrant()
        entry_ids = self._by_target.get(target, [])
        return [
            self._entries[eid]
            for eid in entry_ids[:limit]
            if eid in self._entries
        ]

    async def get_by_agent(self, agent_id: str, limit: int = 100) -> list[KnowledgeEntry]:
        """Get all knowledge discovered by a specific agent."""
        await self._load_from_qdrant()
        entry_ids = self._by_agent.get(agent_id, [])
        return [
            self._entries[eid]
            for eid in entry_ids[:limit]
            if eid in self._entries
        ]

    async def get_findings(
        self,
        target: str | None = None,
        min_severity: Severity | None = None,
    ) -> list[KnowledgeEntry]:
        """Get all security findings, optionally filtered."""
        await self._load_from_qdrant()
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        min_idx = severity_order.index(min_severity) if min_severity else len(severity_order)

        findings = await self.get_by_type(KnowledgeType.FINDING, target=target)

        if min_severity:
            findings = [
                f for f in findings
                if f.severity and severity_order.index(f.severity) <= min_idx
            ]

        # Sort by severity (critical first)
        return sorted(
            findings,
            key=lambda f: severity_order.index(f.severity) if f.severity else 999,
        )

    async def get_credentials(self, target: str | None = None) -> list[KnowledgeEntry]:
        """Get all discovered credentials."""
        await self._load_from_qdrant()
        return await self.get_by_type(KnowledgeType.CREDENTIAL, target=target)

    async def get_context(self, target: str) -> str:
        """
        Get a formatted summary of all knowledge for a target.

        This is what should be passed to sub-agents instead of text summaries.
        """
        await self._load_from_qdrant()
        entries = await self.get_by_target(target)

        if not entries:
            return f"No knowledge available for target: {target}"

        sections = {
            "Findings": [],
            "Credentials": [],
            "Endpoints": [],
            "Technology": [],
            "Context": [],
        }

        type_to_section = {
            KnowledgeType.FINDING: "Findings",
            KnowledgeType.CREDENTIAL: "Credentials",
            KnowledgeType.ENDPOINT: "Endpoints",
            KnowledgeType.TECHNOLOGY: "Technology",
            KnowledgeType.CONTEXT: "Context",
            KnowledgeType.CONFIGURATION: "Context",
            KnowledgeType.HYPOTHESIS: "Context",
        }

        for entry in entries:
            section = type_to_section.get(entry.knowledge_type, "Context")
            line = f"  - [{entry.source_agent}] {entry.content}"
            if entry.severity:
                line = f"  - [{entry.severity.value.upper()}] [{entry.source_agent}] {entry.content}"
            if entry.location:
                line += f" (at {entry.location})"
            sections[section].append(line)

        output = [f"=== Knowledge Graph: {target} ===\n"]

        for section_name, items in sections.items():
            if items:
                output.append(f"\n## {section_name}")
                output.extend(items)

        return "\n".join(output)

    async def link(self, entry_id: str, related_id: str) -> bool:
        """Create a relationship between two entries."""
        if entry_id not in self._entries or related_id not in self._entries:
            return False

        entry = self._entries[entry_id]
        if related_id not in entry.related_to:
            entry.related_to.append(related_id)

        related = self._entries[related_id]
        if entry_id not in related.related_to:
            related.related_to.append(entry_id)

        return True

    async def get_related(self, entry_id: str) -> list[KnowledgeEntry]:
        """Get all entries related to a given entry."""
        entry = await self.get(entry_id)
        if not entry:
            return []

        return [
            self._entries[rid]
            for rid in entry.related_to
            if rid in self._entries
        ]

    def stats(self) -> dict[str, Any]:
        """Get statistics about the knowledge graph."""
        # Load from Qdrant first (sync version for non-async method)
        self._load_from_qdrant_sync()
        return {
            "total_entries": len(self._entries),
            "by_type": {t.value: len(ids) for t, ids in self._by_type.items()},
            "targets": list(self._by_target.keys()),
            "agents": list(self._by_agent.keys()),
        }

    async def clear(self, target: str | None = None) -> int:
        """Clear knowledge, optionally for a specific target only."""
        async with self._async_lock:
            if target:
                # Clear only for specific target
                entry_ids = self._by_target.pop(target, [])
                count = len(entry_ids)

                for eid in entry_ids:
                    entry = self._entries.pop(eid, None)
                    if entry:
                        self._by_type[entry.knowledge_type].remove(eid)
                        if entry.source_agent in self._by_agent:
                            if eid in self._by_agent[entry.source_agent]:
                                self._by_agent[entry.source_agent].remove(eid)
            else:
                # Clear everything
                count = len(self._entries)
                self._entries.clear()
                self._by_type = {t: [] for t in KnowledgeType}
                self._by_target.clear()
                self._by_agent.clear()

            # Clear from Qdrant if available
            client = self._get_client()
            if client:
                try:
                    if target:
                        from qdrant_client.models import Filter, FieldCondition, MatchValue
                        client.delete(
                            collection_name=self._collection_name,
                            points_selector=Filter(
                                must=[FieldCondition(key="target", match=MatchValue(value=target))]
                            ),
                        )
                    else:
                        client.delete_collection(self._collection_name)
                except Exception as e:
                    logger.warning("qdrant_clear_failed", error=str(e))

            logger.info("knowledge_cleared", target=target, count=count)
            return count


# Global singleton accessor
_knowledge_graph: KnowledgeGraph | None = None


def get_knowledge_graph(
    qdrant_host: str = "localhost",
    qdrant_port: int = 6333,
) -> KnowledgeGraph:
    """Get the global knowledge graph instance."""
    global _knowledge_graph
    if _knowledge_graph is None:
        _knowledge_graph = KnowledgeGraph(
            qdrant_host=qdrant_host,
            qdrant_port=qdrant_port,
        )
    return _knowledge_graph
