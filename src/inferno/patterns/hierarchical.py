"""
Hierarchical pattern for Inferno.

This module provides the HIERARCHICAL pattern implementation for
coordinated agent execution with a root coordinator that delegates
tasks to child agents and aggregates their results.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Set

import structlog

from inferno.patterns.pattern import Pattern, PatternType, hierarchical_pattern

if TYPE_CHECKING:
    from inferno.swarm.message_bus import MessageBus

logger = structlog.get_logger(__name__)


@dataclass
class HierarchyNode:
    """
    A node in the agent hierarchy.

    Represents an agent and its children in the hierarchical structure.
    """

    agent: Any
    name: str
    children: List[HierarchyNode] = field(default_factory=list)
    parent: Optional[HierarchyNode] = None
    depth: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_child(self, child: HierarchyNode) -> HierarchyNode:
        """Add a child node."""
        child.parent = self
        child.depth = self.depth + 1
        self.children.append(child)
        return self

    def get_all_descendants(self) -> List[HierarchyNode]:
        """Get all descendants of this node."""
        descendants: List[HierarchyNode] = []
        for child in self.children:
            descendants.append(child)
            descendants.extend(child.get_all_descendants())
        return descendants

    def is_leaf(self) -> bool:
        """Check if this is a leaf node (no children)."""
        return len(self.children) == 0

    def is_root(self) -> bool:
        """Check if this is the root node (no parent)."""
        return self.parent is None


@dataclass
class DelegationTask:
    """A task delegated from root to child agent."""

    task_id: str
    parent_task_id: Optional[str]
    agent_name: str
    description: str
    context: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class HierarchicalExecutionContext:
    """Context for hierarchical pattern execution."""

    root_agent: str
    target: Optional[str] = None
    operation_id: Optional[str] = None
    tasks: List[DelegationTask] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    active_agents: Set[str] = field(default_factory=set)
    completed_agents: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_task(self, task: DelegationTask) -> None:
        """Add a delegated task."""
        self.tasks.append(task)

    def get_pending_tasks(self, agent_name: str) -> List[DelegationTask]:
        """Get pending tasks for an agent."""
        return [
            t for t in self.tasks
            if t.agent_name == agent_name and t.status == "pending"
        ]

    def mark_task_complete(
        self,
        task_id: str,
        result: Any,
    ) -> None:
        """Mark a task as completed."""
        for task in self.tasks:
            if task.task_id == task_id:
                task.status = "completed"
                task.result = result
                break

    def mark_task_failed(
        self,
        task_id: str,
        error: str,
    ) -> None:
        """Mark a task as failed."""
        for task in self.tasks:
            if task.task_id == task_id:
                task.status = "failed"
                task.error = error
                break


@dataclass
class HierarchicalExecutionResult:
    """Result from hierarchical pattern execution."""

    pattern_name: str
    root_agent: str
    total_agents: int
    completed_agents: int
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    findings: List[Dict[str, Any]] = field(default_factory=list)
    aggregated_results: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error: Optional[str] = None
    duration_seconds: float = 0.0


class HierarchicalExecutor:
    """
    Executor for hierarchical patterns.

    Manages a tree structure of agents where the root coordinator
    delegates tasks to child agents and aggregates their results.
    """

    def __init__(
        self,
        max_depth: int = 5,
        parallel_children: bool = True,
        message_bus: Optional[MessageBus] = None,
    ) -> None:
        """
        Initialize the hierarchical executor.

        Args:
            max_depth: Maximum hierarchy depth.
            parallel_children: Whether to run children in parallel.
            message_bus: Optional message bus for communication.
        """
        self._max_depth = max_depth
        self._parallel_children = parallel_children
        self._message_bus = message_bus
        self._task_counter = 0

    def _generate_task_id(self) -> str:
        """Generate unique task ID."""
        self._task_counter += 1
        return f"task_{self._task_counter:06d}"

    async def execute_pattern(
        self,
        pattern: Pattern,
        agent_executor: Callable[[Any, HierarchicalExecutionContext], Any],
        initial_task: str,
        target: Optional[str] = None,
        operation_id: Optional[str] = None,
    ) -> HierarchicalExecutionResult:
        """
        Execute a hierarchical pattern.

        Args:
            pattern: The hierarchical pattern to execute.
            agent_executor: Async callable that executes a single agent.
            initial_task: The initial task for the root agent.
            target: Target URL/host.
            operation_id: Operation ID for memory sharing.

        Returns:
            HierarchicalExecutionResult with execution details.

        Raises:
            ValueError: If pattern is not HIERARCHICAL type.
        """
        if pattern.type != PatternType.HIERARCHICAL:
            raise ValueError(
                f"HierarchicalExecutor only handles HIERARCHICAL patterns, "
                f"got {pattern.type.value}"
            )

        import time
        start_time = time.time()

        # Get root agent
        root_agent = pattern.root_agent
        root_name = getattr(root_agent, "name", str(root_agent))

        # Build hierarchy tree
        root_node = self._build_hierarchy(pattern)

        # Initialize context
        context = HierarchicalExecutionContext(
            root_agent=root_name,
            target=target,
            operation_id=operation_id,
        )

        logger.info(
            "starting_hierarchical_execution",
            pattern=pattern.name,
            root_agent=root_name,
            total_agents=len(pattern.agents),
        )

        try:
            # Execute root agent first (coordinator)
            root_result = await agent_executor(root_agent, context)

            # Process delegated tasks from root
            delegation_tasks = self._extract_delegations(root_result, context)

            # Execute children
            if self._parallel_children:
                child_results = await self._execute_children_parallel(
                    root_node.children,
                    delegation_tasks,
                    agent_executor,
                    context,
                )
            else:
                child_results = await self._execute_children_sequential(
                    root_node.children,
                    delegation_tasks,
                    agent_executor,
                    context,
                )

            # Aggregate results back at root
            aggregated = await self._aggregate_results(
                root_agent,
                child_results,
                context,
            )

            duration = time.time() - start_time

            # Count task statistics
            completed_tasks = sum(
                1 for t in context.tasks if t.status == "completed"
            )
            failed_tasks = sum(
                1 for t in context.tasks if t.status == "failed"
            )

            return HierarchicalExecutionResult(
                pattern_name=pattern.name,
                root_agent=root_name,
                total_agents=len(pattern.agents),
                completed_agents=len(context.completed_agents),
                total_tasks=len(context.tasks),
                completed_tasks=completed_tasks,
                failed_tasks=failed_tasks,
                findings=context.findings,
                aggregated_results=aggregated,
                success=True,
                duration_seconds=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                "hierarchical_execution_error",
                pattern=pattern.name,
                error=str(e),
            )
            return HierarchicalExecutionResult(
                pattern_name=pattern.name,
                root_agent=root_name,
                total_agents=len(pattern.agents),
                completed_agents=len(context.completed_agents),
                total_tasks=len(context.tasks),
                completed_tasks=0,
                failed_tasks=len(context.tasks),
                findings=context.findings,
                aggregated_results={},
                success=False,
                error=str(e),
                duration_seconds=duration,
            )

    def _build_hierarchy(self, pattern: Pattern) -> HierarchyNode:
        """Build the hierarchy tree from pattern."""
        root_agent = pattern.root_agent
        root_name = getattr(root_agent, "name", str(root_agent))

        root_node = HierarchyNode(
            agent=root_agent,
            name=root_name,
            depth=0,
        )

        # Add children (all non-root agents)
        for agent in pattern.agents:
            if agent != root_agent:
                agent_name = getattr(agent, "name", str(agent))
                child_node = HierarchyNode(
                    agent=agent,
                    name=agent_name,
                    depth=1,
                )
                root_node.add_child(child_node)

        return root_node

    def _extract_delegations(
        self,
        root_result: Any,
        context: HierarchicalExecutionContext,
    ) -> List[DelegationTask]:
        """Extract delegation tasks from root result."""
        tasks: List[DelegationTask] = []

        # Check for explicit delegations
        if hasattr(root_result, "delegations"):
            for delegation in root_result.delegations:
                task = DelegationTask(
                    task_id=self._generate_task_id(),
                    parent_task_id=None,
                    agent_name=delegation.get("agent", ""),
                    description=delegation.get("task", ""),
                    context=delegation.get("context", {}),
                )
                tasks.append(task)
                context.add_task(task)

        # Check for dict-based delegations
        if isinstance(root_result, dict) and "delegations" in root_result:
            for delegation in root_result["delegations"]:
                task = DelegationTask(
                    task_id=self._generate_task_id(),
                    parent_task_id=None,
                    agent_name=delegation.get("agent", ""),
                    description=delegation.get("task", ""),
                    context=delegation.get("context", {}),
                )
                tasks.append(task)
                context.add_task(task)

        return tasks

    async def _execute_children_parallel(
        self,
        children: List[HierarchyNode],
        tasks: List[DelegationTask],
        executor: Callable[[Any, HierarchicalExecutionContext], Any],
        context: HierarchicalExecutionContext,
    ) -> Dict[str, Any]:
        """Execute child agents in parallel."""
        results: Dict[str, Any] = {}

        # Create task groups by agent
        async_tasks = []
        for child in children:
            child_tasks = [t for t in tasks if t.agent_name == child.name]
            if child_tasks or not tasks:  # Execute even without explicit task
                async_tasks.append(
                    self._execute_child(child, child_tasks, executor, context)
                )

        # Execute all in parallel
        child_results = await asyncio.gather(*async_tasks, return_exceptions=True)

        for child, result in zip(children, child_results):
            if isinstance(result, Exception):
                results[child.name] = {
                    "success": False,
                    "error": str(result),
                }
            else:
                results[child.name] = result
                context.completed_agents.add(child.name)

        return results

    async def _execute_children_sequential(
        self,
        children: List[HierarchyNode],
        tasks: List[DelegationTask],
        executor: Callable[[Any, HierarchicalExecutionContext], Any],
        context: HierarchicalExecutionContext,
    ) -> Dict[str, Any]:
        """Execute child agents sequentially."""
        results: Dict[str, Any] = {}

        for child in children:
            child_tasks = [t for t in tasks if t.agent_name == child.name]
            try:
                result = await self._execute_child(
                    child, child_tasks, executor, context
                )
                results[child.name] = result
                context.completed_agents.add(child.name)
            except Exception as e:
                results[child.name] = {
                    "success": False,
                    "error": str(e),
                }

        return results

    async def _execute_child(
        self,
        child: HierarchyNode,
        tasks: List[DelegationTask],
        executor: Callable[[Any, HierarchicalExecutionContext], Any],
        context: HierarchicalExecutionContext,
    ) -> Any:
        """Execute a single child agent."""
        context.active_agents.add(child.name)

        # Mark tasks as running
        for task in tasks:
            task.status = "running"

        try:
            result = await executor(child.agent, context)

            # Mark tasks as complete
            for task in tasks:
                context.mark_task_complete(task.task_id, result)

            return result

        except Exception as e:
            # Mark tasks as failed
            for task in tasks:
                context.mark_task_failed(task.task_id, str(e))
            raise

        finally:
            context.active_agents.discard(child.name)

    async def _aggregate_results(
        self,
        root_agent: Any,
        child_results: Dict[str, Any],
        context: HierarchicalExecutionContext,
    ) -> Dict[str, Any]:
        """Aggregate child results at the root."""
        aggregated: Dict[str, Any] = {
            "child_results": child_results,
            "findings": context.findings,
            "summary": {
                "total_children": len(child_results),
                "successful": sum(
                    1 for r in child_results.values()
                    if not isinstance(r, dict) or r.get("success", True)
                ),
                "failed": sum(
                    1 for r in child_results.values()
                    if isinstance(r, dict) and not r.get("success", True)
                ),
            },
        }

        return aggregated


# Pre-defined hierarchical patterns for Inferno


def create_coordinated_assessment_pattern(
    coordinator: Any,
    workers: List[Any],
) -> Pattern:
    """
    Create a coordinated assessment pattern.

    The coordinator delegates tasks to workers and aggregates results.
    This matches Inferno's MetaCoordinator architecture.

    Args:
        coordinator: The root coordinator agent.
        workers: List of worker agents.

    Returns:
        Configured hierarchical Pattern.

    Example:
        >>> pattern = create_coordinated_assessment_pattern(
        ...     coordinator=meta_coordinator,
        ...     workers=[recon_worker, exploit_worker, validator_worker]
        ... )
    """
    return hierarchical_pattern(
        name="coordinated_assessment",
        root_agent=coordinator,
        description=(
            "MetaCoordinator delegates to specialized workers: "
            "recon, exploit, validate, report"
        ),
        children=workers,
    )


def create_red_team_hierarchy(
    team_lead: Any,
    specialists: List[Any],
) -> Pattern:
    """
    Create a red team hierarchical pattern.

    Team lead coordinates specialists for comprehensive assessment.

    Args:
        team_lead: Team lead coordinator.
        specialists: List of specialist agents.

    Returns:
        Configured hierarchical Pattern.
    """
    return hierarchical_pattern(
        name="red_team_hierarchy",
        root_agent=team_lead,
        description="Red team hierarchy with lead and specialists",
        children=specialists,
    )
