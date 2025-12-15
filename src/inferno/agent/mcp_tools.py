"""
Custom MCP tools for Inferno.

This module provides Inferno-specific tools as MCP servers
that integrate with the Claude Agent SDK. These tools wrap
the existing Inferno infrastructure (Mem0/Qdrant for semantic memory).
"""

from __future__ import annotations

from typing import Any

import structlog
from claude_agent_sdk import create_sdk_mcp_server, tool

logger = structlog.get_logger(__name__)

# Global NVD tool instance
_nvd_tool_instance = None

# Global state for the memory tool instance
_memory_tool_instance = None
_operation_id: str | None = None
_current_target: str | None = None


def set_operation_id(op_id: str) -> None:
    """Set the current operation ID for memory storage."""
    global _operation_id, _memory_tool_instance
    _operation_id = op_id
    if _memory_tool_instance:
        _memory_tool_instance.set_operation_id(op_id)


def set_target(target: str) -> None:
    """Set the current target for memory scoping."""
    global _current_target, _memory_tool_instance
    _current_target = target
    if _memory_tool_instance:
        _memory_tool_instance.set_target(target)
    logger.info("mcp_memory_target_set", target=target)


def configure_memory(
    qdrant_host: str = "localhost",
    qdrant_port: int = 6333,
    qdrant_collection: str = "inferno_memories",
    embedding_provider: str = "sentence_transformers",
    embedding_model: str | None = None,
    ollama_host: str = "http://localhost:11434",
    api_key: str | None = None,
) -> None:
    """
    Configure the Mem0/Qdrant memory backend.

    This should be called before creating the MCP server to
    configure the semantic memory system.
    """
    global _memory_tool_instance, _operation_id

    from inferno.tools.memory import MemoryToolWithFallback

    _memory_tool_instance = MemoryToolWithFallback(
        operation_id=_operation_id,
        qdrant_host=qdrant_host,
        qdrant_port=qdrant_port,
        qdrant_collection=qdrant_collection,
        embedding_provider=embedding_provider,
        embedding_model=embedding_model,
        ollama_host=ollama_host,
        api_key=api_key,
    )

    logger.info(
        "mcp_memory_configured",
        qdrant_host=qdrant_host,
        embedding_provider=embedding_provider,
    )


def _get_memory_tool():
    """Get or create the memory tool instance."""
    global _memory_tool_instance, _operation_id, _current_target

    if _memory_tool_instance is None:
        from inferno.tools.memory import MemoryToolWithFallback

        _memory_tool_instance = MemoryToolWithFallback(
            operation_id=_operation_id,
        )
        # Set target if already configured
        if _current_target:
            _memory_tool_instance.set_target(_current_target)

    return _memory_tool_instance


# -------------------------------------------------------------------------
# Swarm Tool Configuration - for spawning subagents
# -------------------------------------------------------------------------

_swarm_model = "claude-opus-4-5-20251101"
_swarm_target = None
_swarm_configured = False


def configure_swarm(
    model: str = "claude-opus-4-5-20251101",
    target: str | None = None,
) -> None:
    """
    Configure the swarm tool.

    Swarm tool now uses Claude SDK internally (supports OAuth automatically).

    Args:
        model: Model to use for subagents
        target: Target URL for context
    """
    global _swarm_model, _swarm_target, _swarm_configured
    _swarm_model = model
    _swarm_target = target
    _swarm_configured = True
    logger.info(
        "swarm_configured",
        model=model,
        target=target,
    )


def _get_swarm_tool():
    """Get or create the swarm tool instance."""
    global _swarm_model, _swarm_target, _operation_id, _swarm_configured

    if not _swarm_configured:
        # Auto-configure with defaults
        _swarm_configured = True

    from inferno.swarm.tool import SwarmTool

    return SwarmTool(
        model=_swarm_model,
        operation_id=_operation_id,
        target=_swarm_target,
    )


@tool(
    "memory_store",
    "Store a PROVEN finding or observation. "
    "IMPORTANT: For findings with severity, you MUST include proof of exploitation. "
    "Observable ≠ Exploitable - only store as 'finding' if you PROVED impact. "
    "Use 'observation' type for unproven discoveries that need more testing.",
    {
        "content": str,
        "memory_type": str,  # "finding" (proven), "observation" (unproven), "context", "credential"
        "severity": str,  # "critical", "high", "medium", "low" - ONLY for proven findings
        "proof": str,  # REQUIRED for findings: what you did to prove exploitation
        "metadata": str,  # JSON string of additional metadata
    }
)
async def memory_store(args: dict[str, Any]) -> dict[str, Any]:
    """Store information in Mem0/Qdrant semantic memory."""
    import json

    mem_tool = _get_memory_tool()

    # Parse metadata if provided as JSON string
    metadata = {}
    if args.get("metadata"):
        try:
            metadata = json.loads(args["metadata"])
        except json.JSONDecodeError:
            metadata = {"raw": args["metadata"]}

    # Add severity to metadata
    if args.get("severity"):
        metadata["severity"] = args["severity"]

    # Add proof to metadata
    if args.get("proof"):
        metadata["proof"] = args["proof"]

    # Key findings with severity should go to both episodic and semantic
    memory_type = args.get("memory_type", "findings")
    has_severity = bool(args.get("severity"))
    memory_scope = "both" if (has_severity or memory_type == "findings") else "episodic"

    result = await mem_tool.execute(
        operation="store",
        content=args["content"],
        memory_type=memory_type,
        memory_scope=memory_scope,  # Key findings go to BOTH for cross-session access
        metadata=metadata,
        target=_current_target,  # Pass global target for episodic memory
    )

    if result.success:
        return {
            "content": [{
                "type": "text",
                "text": result.output
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"Error storing memory: {result.error}"
            }],
            "is_error": True
        }


@tool(
    "memory_search",
    "Search stored memories using semantic similarity. "
    "Uses vector embeddings to find contextually relevant information, "
    "not just keyword matching. Use this to recall previously discovered findings.",
    {
        "query": str,
        "memory_type": str,  # "findings", "context", "knowledge", "checkpoint" or empty for all
        "limit": int,  # max results (default 10)
        "threshold": float,  # similarity threshold 0.0-1.0 (default 0.25 for good recall)
    }
)
async def memory_search(args: dict[str, Any]) -> dict[str, Any]:
    """Search Mem0/Qdrant semantic memory with similarity matching."""
    mem_tool = _get_memory_tool()

    # Default to 0.25 threshold for better recall of similar memories
    threshold = args.get("threshold", 0.25)

    result = await mem_tool.execute(
        operation="search",
        content=args["query"],
        memory_type=args.get("memory_type", "findings"),
        memory_scope="both",  # Search BOTH episodic (target-specific) and semantic (global)
        limit=args.get("limit", 10),
        threshold=threshold,
        target=_current_target,  # Pass global target for episodic memory
    )

    if result.success:
        return {
            "content": [{
                "type": "text",
                "text": result.output
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"Error searching memory: {result.error}"
            }],
            "is_error": True
        }


@tool(
    "memory_list",
    "List all stored memories of a specific type. "
    "Use to review what has been discovered so far.",
    {
        "memory_type": str,  # "findings", "context", "knowledge", "checkpoint"
        "limit": int,  # max results (default 10)
    }
)
async def memory_list(args: dict[str, Any]) -> dict[str, Any]:
    """List memories from Mem0/Qdrant."""
    mem_tool = _get_memory_tool()

    result = await mem_tool.execute(
        operation="list",
        memory_type=args.get("memory_type", "findings"),
        limit=args.get("limit", 10),
        target=_current_target,  # Pass global target for episodic memory
    )

    if result.success:
        return {
            "content": [{
                "type": "text",
                "text": result.output
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"Error listing memories: {result.error}"
            }],
            "is_error": True
        }


@tool(
    "memory_recall",
    "⚠️ DEPRECATED - DO NOT USE. Recall by ID is NOT supported in dual memory mode. "
    "Use memory_search instead to find memories by content.",
    {
        "memory_id": str,
    }
)
async def memory_recall(args: dict[str, Any]) -> dict[str, Any]:
    """Recall a specific memory by ID. DEPRECATED - use memory_search instead."""
    mem_tool = _get_memory_tool()

    result = await mem_tool.execute(
        operation="recall",
        memory_id=args["memory_id"],
    )

    if result.success:
        return {
            "content": [{
                "type": "text",
                "text": result.output
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"Error recalling memory: {result.error}"
            }],
            "is_error": True
        }


@tool(
    "checkpoint",
    "Create an assessment checkpoint to summarize progress. "
    "Use at 20%, 40%, 60%, and 80% budget consumption to track progress "
    "and ensure important findings are not lost.",
    {
        "phase": str,  # "reconnaissance", "scanning", "exploitation", "reporting"
        "summary": str,
        "findings_count": int,
        "next_steps": str,
        "progress_percent": int,  # 0-100
    }
)
async def checkpoint(args: dict[str, Any]) -> dict[str, Any]:
    """Create an assessment checkpoint in semantic memory."""
    mem_tool = _get_memory_tool()

    # Build checkpoint content
    content = (
        f"CHECKPOINT - {args['phase'].upper()} PHASE\n"
        f"Progress: {args.get('progress_percent', 0)}%\n"
        f"Summary: {args['summary']}\n"
        f"Findings so far: {args.get('findings_count', 0)}\n"
        f"Next steps: {args.get('next_steps', 'Continue assessment')}"
    )

    metadata = {
        "phase": args["phase"],
        "progress_percent": args.get("progress_percent", 0),
        "findings_count": args.get("findings_count", 0),
        "next_steps": args.get("next_steps"),
    }

    result = await mem_tool.execute(
        operation="checkpoint",
        content=content,
        metadata=metadata,
        target=_current_target,  # Pass target for episodic memory
    )

    if result.success:
        return {
            "content": [{
                "type": "text",
                "text": f"Checkpoint saved for {args['phase']} phase ({args.get('progress_percent', 0)}% complete)\n{result.output}"
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"Error creating checkpoint: {result.error}"
            }],
            "is_error": True
        }


# Global evaluation metrics
_evaluation_metrics = {
    "vulnerabilities_found": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "tools_used": [],
    "swarm_deployments": 0,
    "meta_tools_created": 0,
    "confidence_history": [],
}


@tool(
    "store_evidence",
    "Store a confirmed vulnerability finding with full evidence. "
    "Use this for ALL confirmed vulnerabilities. Automatically categorizes and tracks metrics.",
    {
        "vulnerability_type": str,  # "sqli", "xss", "rce", "ssrf", "idor", "auth_bypass", etc.
        "severity": str,  # "critical", "high", "medium", "low"
        "endpoint": str,  # The affected endpoint/URL
        "payload": str,  # The payload that triggered the vulnerability
        "evidence": str,  # Proof of exploitation (response, error, etc.)
        "cvss_score": float,  # CVSS score if known (0.0-10.0)
        "remediation": str,  # Suggested fix
    }
)
async def store_evidence(args: dict[str, Any]) -> dict[str, Any]:
    """Store a vulnerability finding with evidence."""
    # Update metrics first (always succeeds)
    global _evaluation_metrics
    _evaluation_metrics["vulnerabilities_found"] += 1
    severity = args.get("severity", "medium").lower()
    if severity in _evaluation_metrics:
        _evaluation_metrics[severity] += 1

    # Extract fields with defaults to avoid KeyError
    vuln_type = args.get("vulnerability_type", "Unknown")
    severity_str = args.get("severity", "medium")
    endpoint = args.get("endpoint", "Unknown")
    payload = args.get("payload", "N/A")
    evidence = args.get("evidence", "N/A")
    cvss = args.get("cvss_score", "N/A")
    remediation = args.get("remediation", "Not specified")

    # Build structured evidence content
    content = f"""VULNERABILITY: {vuln_type.upper()}
Severity: {severity_str.upper()}
Endpoint: {endpoint}
Payload: {payload}
Evidence: {evidence}
CVSS: {cvss}
Remediation: {remediation}"""

    # Try to store in memory (may fail due to Mem0 bugs, but metrics are already updated)
    try:
        mem_tool = _get_memory_tool()
        metadata = {
            "category": "vulnerability",
            "vulnerability_type": vuln_type,
            "severity": severity_str,
            "endpoint": endpoint,
            "cvss_score": cvss,
            "has_payload": bool(payload and payload != "N/A"),
            "has_evidence": bool(evidence and evidence != "N/A"),
        }

        result = await mem_tool.execute(
            operation="store",
            content=content,
            memory_type="finding",
            memory_scope="both",  # Store to BOTH episodic and semantic for key findings
            metadata=metadata,
            target=_current_target,  # CRITICAL: Pass target for episodic memory
        )

        if result.success:
            return {
                "content": [{
                    "type": "text",
                    "text": f"Evidence stored: {vuln_type.upper()} ({severity_str}) at {endpoint}\n"
                            f"Total vulnerabilities found: {_evaluation_metrics['vulnerabilities_found']}"
                }]
            }
    except Exception:
        # Memory storage failed but metrics are updated - don't crash
        pass

    # Return success even if memory failed (metrics were updated)
    return {
        "content": [{
            "type": "text",
            "text": f"Evidence recorded: {vuln_type.upper()} ({severity_str}) at {endpoint}\n"
                    f"Total vulnerabilities found: {_evaluation_metrics['vulnerabilities_found']}\n"
                    f"(Note: Memory storage may have partial persistence)"
        }]
    }


@tool(
    "update_confidence",
    "Update and track your current confidence level. "
    "Use this after each major action to maintain metacognitive awareness. "
    "The system will suggest strategy changes based on confidence trends.",
    {
        "confidence": int,  # 0-100
        "reason": str,  # Why this confidence level
        "next_action": str,  # What you plan to do next
    }
)
async def update_confidence(args: dict[str, Any]) -> dict[str, Any]:
    """Track confidence levels for metacognitive assessment."""
    global _evaluation_metrics

    confidence = args.get("confidence", 50)
    reason = args.get("reason", "")
    next_action = args.get("next_action", "")

    # Track confidence history
    _evaluation_metrics["confidence_history"].append({
        "confidence": confidence,
        "reason": reason,
    })

    # Generate strategy recommendation based on confidence
    if confidence >= 80:
        recommendation = "HIGH confidence - proceed with direct exploitation using specialized tools"
    elif confidence >= 50:
        recommendation = "MEDIUM confidence - validate findings with multiple approaches before exploitation"
    elif confidence >= 20:
        recommendation = "LOW confidence - consider deploying Task subagents for parallel exploration"
    else:
        recommendation = "VERY LOW confidence - STRONGLY recommend deploying swarm or creating meta-tools"

    # Check for declining confidence trend
    history = _evaluation_metrics["confidence_history"]
    if len(history) >= 3:
        recent = [h["confidence"] for h in history[-3:]]
        if all(recent[i] > recent[i+1] for i in range(len(recent)-1)):
            recommendation += "\n⚠️ WARNING: Confidence declining - consider changing approach"

    return {
        "content": [{
            "type": "text",
            "text": f"CONFIDENCE: {confidence}%\n"
                    f"Reason: {reason}\n"
                    f"Next action: {next_action}\n\n"
                    f"📊 Recommendation: {recommendation}"
        }]
    }


@tool(
    "get_metrics",
    "Get current assessment metrics and performance evaluation. "
    "Use to review progress and adjust strategy.",
    {}
)
async def get_metrics(args: dict[str, Any]) -> dict[str, Any]:
    """Get assessment metrics."""
    global _evaluation_metrics

    history = _evaluation_metrics["confidence_history"]
    avg_confidence = sum(h["confidence"] for h in history) / len(history) if history else 0

    metrics_text = f"""📊 ASSESSMENT METRICS

Vulnerabilities Found: {_evaluation_metrics['vulnerabilities_found']}
  - Critical: {_evaluation_metrics['critical']}
  - High: {_evaluation_metrics['high']}
  - Medium: {_evaluation_metrics['medium']}
  - Low: {_evaluation_metrics['low']}

Confidence Tracking:
  - Current: {history[-1]['confidence'] if history else 'N/A'}%
  - Average: {avg_confidence:.1f}%
  - Samples: {len(history)}

Operations:
  - Swarm Deployments: {_evaluation_metrics['swarm_deployments']}
  - Meta-tools Created: {_evaluation_metrics['meta_tools_created']}
  - Tools Used: {len(set(_evaluation_metrics['tools_used']))} unique
"""

    return {
        "content": [{
            "type": "text",
            "text": metrics_text
        }]
    }


@tool(
    "register_swarm",
    "Register that a swarm/subagent was deployed. "
    "Call this when using Task tool for parallel exploration.",
    {
        "task_description": str,
    }
)
async def register_swarm(args: dict[str, Any]) -> dict[str, Any]:
    """Register swarm deployment for metrics."""
    global _evaluation_metrics
    _evaluation_metrics["swarm_deployments"] += 1

    return {
        "content": [{
            "type": "text",
            "text": f"Swarm deployment #{_evaluation_metrics['swarm_deployments']} registered: {args['task_description']}"
        }]
    }


@tool(
    "swarm",
    "Spawn a specialized sub-agent to handle a specific task. Sub-agents are "
    "autonomous agents with focused capabilities. Use this to delegate tasks like "
    "reconnaissance, vulnerability scanning, exploitation attempts, IoT device discovery, "
    "firmware analysis, or reverse engineering. "
    "The sub-agent will execute independently and return results when complete. "
    "Available types: "
    "WEB/NETWORK: reconnaissance, scanner, exploiter, post_exploitation, analyzer, researcher, validator, waf_bypass, token_forgery, api_flow, business_logic, privesc. "
    "IOT/HARDWARE: iot_scanner, firmware_analyst, memory_forensics, radio_analyst, reverse_engineer.",
    {
        "agent_type": str,  # Type of sub-agent (see description for available types)
        "task": str,  # Specific task description for the sub-agent
        "context": str,  # Additional context (findings, target info)
        "max_turns": int,  # Maximum turns (default: 20, max: 50)
    }
)
async def swarm_spawn(args: dict[str, Any]) -> dict[str, Any]:
    """
    Spawn a specialized sub-agent to handle a specific task.

    This is the META-AGENT pattern - the main agent can spawn specialized
    workers for parallel task execution.
    """
    global _evaluation_metrics

    swarm_tool = _get_swarm_tool()
    if swarm_tool is None:
        return {
            "content": [{
                "type": "text",
                "text": "ERROR: Swarm tool not configured. Cannot spawn subagents."
            }],
            "is_error": True,
        }

    # Track deployment
    _evaluation_metrics["swarm_deployments"] += 1

    agent_type = args.get("agent_type", "reconnaissance")
    task = args.get("task", "")
    context = args.get("context", "")
    max_turns = min(args.get("max_turns", 20), 50)

    logger.info(
        "spawning_subagent_via_mcp",
        agent_type=agent_type,
        task=task[:100],
        max_turns=max_turns,
    )

    try:
        result = await swarm_tool.execute(
            agent_type=agent_type,
            task=task,
            context=context,
            max_turns=max_turns,
        )

        if result.success:
            return {
                "content": [{
                    "type": "text",
                    "text": result.output or "Subagent completed successfully"
                }]
            }
        else:
            return {
                "content": [{
                    "type": "text",
                    "text": f"Subagent error: {result.error}"
                }],
                "is_error": True,
            }

    except Exception as e:
        logger.error("swarm_spawn_error", error=str(e))
        return {
            "content": [{
                "type": "text",
                "text": f"Failed to spawn subagent: {e}"
            }],
            "is_error": True,
        }


@tool(
    "nvd_lookup",
    "Query NVD for known CVEs when you detect ANY software version. "
    "CRITICAL: Use this IMMEDIATELY when you see version strings like 'nginx/1.18.0', "
    "'Express', 'WordPress 6.4.1', 'Apache/2.4.41', etc. Returns CVEs sorted by severity "
    "with exploit availability indicators.",
    {
        "software": str,  # Software name (e.g., "nginx", "wordpress", "express")
        "version": str,  # Version string (e.g., "1.18.0", "6.4.1")
        "auto_detect": str,  # OR raw version string to auto-detect (e.g., "nginx/1.18.0")
    }
)
async def nvd_lookup(args: dict[str, Any]) -> dict[str, Any]:
    """Query NVD for known CVEs for a software/version."""
    global _nvd_tool_instance

    # Lazy load NVD tool
    if _nvd_tool_instance is None:
        from inferno.tools.security.nvd import NVDTool
        _nvd_tool_instance = NVDTool()

    try:
        result = await _nvd_tool_instance.execute(
            software=args.get("software"),
            version=args.get("version"),
            auto_detect=args.get("auto_detect"),
        )

        if result.success:
            return {
                "content": [{
                    "type": "text",
                    "text": result.output
                }]
            }
        else:
            return {
                "content": [{
                    "type": "text",
                    "text": f"NVD lookup failed: {result.error}"
                }],
                "is_error": True
            }
    except Exception as e:
        logger.error("nvd_lookup_error", error=str(e))
        return {
            "content": [{
                "type": "text",
                "text": f"NVD lookup error: {e!s}"
            }],
            "is_error": True
        }


@tool(
    "register_meta_tool",
    "Register that a custom meta-tool was created. "
    "Call this after creating a custom script/tool.",
    {
        "tool_name": str,
        "tool_path": str,
        "description": str,
    }
)
async def register_meta_tool(args: dict[str, Any]) -> dict[str, Any]:
    """Register meta-tool creation for metrics."""
    global _evaluation_metrics
    _evaluation_metrics["meta_tools_created"] += 1

    # Also store in memory for cross-session reuse
    mem_tool = _get_memory_tool()
    await mem_tool.execute(
        operation="store",
        content=f"META-TOOL: {args['tool_name']}\nPath: {args['tool_path']}\nDescription: {args['description']}",
        memory_type="knowledge",
        metadata={"category": "meta_tool", "tool_name": args["tool_name"]},
    )

    return {
        "content": [{
            "type": "text",
            "text": f"Meta-tool #{_evaluation_metrics['meta_tools_created']} registered: {args['tool_name']} at {args['tool_path']}"
        }]
    }


# -------------------------------------------------------------------------
# Key Findings Persistence (CAI-inspired)
# -------------------------------------------------------------------------
# Simple file-based persistence for maintaining findings across turns
# This prevents the agent from "forgetting" important discoveries

_key_findings_file: str | None = None


def set_key_findings_file(filepath: str) -> None:
    """Set the path for key findings persistence file."""
    global _key_findings_file
    _key_findings_file = filepath


def _get_findings_file() -> str:
    """Get the key findings file path, creating default if needed."""
    global _key_findings_file
    if _key_findings_file is None:
        import os
        import tempfile
        # Use temp dir with operation ID if available
        if _operation_id:
            _key_findings_file = os.path.join(tempfile.gettempdir(), f"inferno_findings_{_operation_id}.txt")
        else:
            _key_findings_file = os.path.join(tempfile.gettempdir(), "inferno_findings.txt")
    return _key_findings_file


@tool(
    "write_key_findings",
    "Write key findings to persistent state file. Use this to record important discoveries "
    "that MUST NOT be forgotten: confirmed vulnerabilities, credentials, attack paths, "
    "or any critical information. This persists across conversation turns and prevents "
    "context loss. Call this EVERY TIME you discover something important.",
    {
        "content": str,  # The findings to write (will be appended)
        "overwrite": bool,  # If True, replace entire file. If False (default), append.
    }
)
async def write_key_findings(args: dict[str, Any]) -> dict[str, Any]:
    """Write key findings to persistent file (CAI-inspired state.txt)."""
    filepath = _get_findings_file()
    content = args.get("content", "")
    overwrite = args.get("overwrite", False)

    if not content:
        return {
            "content": [{
                "type": "text",
                "text": "Error: No content provided to write"
            }],
            "is_error": True
        }

    try:
        import os
        from datetime import datetime

        # Add timestamp to entry
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"\n[{timestamp}]\n{content}\n{'='*50}"

        mode = "w" if overwrite else "a"
        with open(filepath, mode, encoding="utf-8") as f:
            if overwrite:
                f.write(f"# INFERNO KEY FINDINGS\n# Operation: {_operation_id or 'unknown'}\n{'='*50}")
            f.write(entry)

        # Get file size for feedback
        size = os.path.getsize(filepath)

        return {
            "content": [{
                "type": "text",
                "text": f"Key findings written to state file ({size} bytes)\n"
                        f"File: {filepath}\n"
                        f"Mode: {'overwrite' if overwrite else 'append'}"
            }]
        }
    except Exception as e:
        logger.error("write_key_findings_error", error=str(e))
        return {
            "content": [{
                "type": "text",
                "text": f"Error writing findings: {e!s}"
            }],
            "is_error": True
        }


@tool(
    "read_key_findings",
    "Read all key findings from persistent state file. Use this to recall important "
    "discoveries from earlier in the assessment. Call this at the START of each major "
    "phase to refresh your context on what has been found.",
    {}
)
async def read_key_findings(args: dict[str, Any]) -> dict[str, Any]:
    """Read key findings from persistent file (CAI-inspired state.txt)."""
    filepath = _get_findings_file()

    try:
        import os

        if not os.path.exists(filepath):
            return {
                "content": [{
                    "type": "text",
                    "text": "No key findings recorded yet. Use write_key_findings to persist important discoveries."
                }]
            }

        with open(filepath, encoding="utf-8") as f:
            content = f.read()

        if not content.strip():
            return {
                "content": [{
                    "type": "text",
                    "text": "Key findings file is empty. Use write_key_findings to persist important discoveries."
                }]
            }

        # Count entries
        entry_count = content.count("[20")  # Rough count of timestamped entries

        return {
            "content": [{
                "type": "text",
                "text": f"=== KEY FINDINGS ({entry_count} entries) ===\n\n{content}"
            }]
        }
    except Exception as e:
        logger.error("read_key_findings_error", error=str(e))
        return {
            "content": [{
                "type": "text",
                "text": f"Error reading findings: {e!s}"
            }],
            "is_error": True
        }


def reset_metrics() -> None:
    """Reset evaluation metrics for a new assessment."""
    global _evaluation_metrics
    _evaluation_metrics = {
        "vulnerabilities_found": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "tools_used": [],
        "swarm_deployments": 0,
        "meta_tools_created": 0,
        "confidence_history": [],
    }


def get_final_metrics() -> dict:
    """Get final metrics for reporting."""
    global _evaluation_metrics
    history = _evaluation_metrics["confidence_history"]
    avg_confidence = sum(h["confidence"] for h in history) / len(history) if history else 0

    return {
        **_evaluation_metrics,
        "avg_confidence": avg_confidence,
    }


def create_inferno_mcp_server():
    """
    Create the Inferno MCP server with semantic memory and metacognitive tools.

    Includes:
    - Memory tools (store, search, list)
    - Evidence collection (store_evidence)
    - Metacognitive tools (update_confidence, get_metrics)
    - Swarm/meta-tool registration

    Returns:
        McpSdkServerConfig for use with ClaudeAgentOptions.
    """
    # Reset metrics for new session
    reset_metrics()

    return create_sdk_mcp_server(
        name="inferno",
        version="1.0.0",
        tools=[
            # Memory tools
            memory_store,
            memory_search,
            memory_list,
            # memory_recall - REMOVED: not supported in dual memory mode, use memory_search
            checkpoint,
            # Evidence collection
            store_evidence,
            # Key findings persistence (CAI-inspired)
            write_key_findings,
            read_key_findings,
            # Intelligence tools
            nvd_lookup,
            # Metacognitive tools
            update_confidence,
            get_metrics,
            # Swarm - spawn subagents (META-AGENT PATTERN)
            swarm_spawn,
            # Swarm/meta-tool registration (metrics only)
            register_swarm,
            register_meta_tool,
        ]
    )
