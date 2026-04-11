"""Execution dispatcher for Kernels.

The dispatcher handles tool invocation with explicit validation and
error handling. No implicit execution occurs.
"""

from dataclasses import dataclass
from typing import Any, Optional, Union

from kernels.common.types import ToolCall
from kernels.common.errors import ToolError
from kernels.execution.tools import ToolRegistry


@dataclass
class ExecutionResult:
    """Result of a tool execution."""

    success: bool
    tool_name: str
    result: Optional[Any] = None
    error: Optional[str] = None


class Dispatcher:
    """Dispatcher for tool execution.

    The dispatcher validates tool calls and invokes tools through
    the registry. All execution is explicit and synchronous.
    """

    def __init__(self, registry: ToolRegistry) -> None:
        """Initialize dispatcher with a tool registry.

        Args:
            registry: Tool registry to use for lookups.
        """
        self._registry = registry

    @property
    def registry(self) -> ToolRegistry:
        """Return the tool registry."""
        return self._registry

    def validate_tool_call(
        self, tool_call: Union[ToolCall, dict[str, Any]]
    ) -> list[str]:
        """Validate a tool call before execution.

        Args:
            tool_call: Tool call to validate.

        Returns:
            List of validation errors. Empty if valid.
        """
        errors: list[str] = []

        # Extract name
        if isinstance(tool_call, ToolCall):
            name = tool_call.name
            params = tool_call.params
        elif isinstance(tool_call, dict):
            name = tool_call.get("name", "")
            params = tool_call.get("params", {})
        else:
            return ["Invalid tool call structure"]

        # Check name
        if not name:
            errors.append("Tool name is required")
            return errors

        # Check tool exists
        if not self._registry.has(name):
            errors.append(f"Tool '{name}' is not registered")
            return errors

        # Check params is dict
        if not isinstance(params, dict):
            errors.append("Tool params must be a dictionary")

        return errors

    def execute(self, tool_call: Union[ToolCall, dict[str, Any]]) -> ExecutionResult:
        """Execute a tool call.

        Args:
            tool_call: Tool call to execute.

        Returns:
            ExecutionResult with success status and result or error.
        """
        # Extract name and params
        if isinstance(tool_call, ToolCall):
            name = tool_call.name
            params = dict(tool_call.params)
        elif isinstance(tool_call, dict):
            name = tool_call.get("name", "")
            params = dict(tool_call.get("params", {}))
        else:
            return ExecutionResult(
                success=False,
                tool_name="",
                error="Invalid tool call structure",
            )

        # Validate
        errors = self.validate_tool_call(tool_call)
        if errors:
            return ExecutionResult(
                success=False,
                tool_name=name,
                error="; ".join(errors),
            )

        # Execute
        try:
            result = self._registry.invoke(name, params)
            return ExecutionResult(
                success=True,
                tool_name=name,
                result=result,
            )
        except ToolError as e:
            return ExecutionResult(
                success=False,
                tool_name=name,
                error=str(e),
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                tool_name=name,
                error=f"Unexpected error: {e}",
            )

    def list_available_tools(self) -> list[str]:
        """List all available tools.

        Returns:
            List of tool names.
        """
        return self._registry.list_tools()
