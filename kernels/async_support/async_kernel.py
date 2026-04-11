"""
KERNELS Async Kernel Implementations

Provides async/await versions of all kernel variants.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from kernels.common.types import Request, Receipt, Decision, KernelState
from kernels.common.errors import StateError, ValidationError
from kernels.common.time import monotonic_ms
from kernels.audit.ledger import AuditLedger, AuditEntry
from kernels.jurisdiction.policy import JurisdictionPolicy
from kernels.state.machine import StateMachine
from kernels.execution.tools import ToolRegistry
from kernels.execution.dispatcher import Dispatcher


class AsyncBaseKernel:
    """
    Base class for async kernel implementations.

    Provides async/await support for kernel operations while
    maintaining all invariants of the synchronous version.
    """

    def __init__(
        self,
        kernel_id: str,
        policy: Optional[JurisdictionPolicy] = None,
        tool_registry: Optional[ToolRegistry] = None,
    ):
        self.kernel_id = kernel_id
        self.policy = policy or JurisdictionPolicy()
        self.tool_registry = tool_registry or ToolRegistry()

        self._state_machine = StateMachine()
        self._ledger = AuditLedger()
        self._dispatcher = Dispatcher(self.tool_registry)
        self._lock = asyncio.Lock()

        # Boot sequence
        self._state_machine.transition_to(KernelState.IDLE)

    @property
    def state(self) -> KernelState:
        """Current kernel state."""
        return self._state_machine.current_state

    async def submit(self, request: Request) -> Receipt:
        """
        Submit a request for processing.

        This is the main entry point for async request processing.
        Uses a lock to ensure serialized processing.

        Args:
            request: The request to process

        Returns:
            Receipt with decision and result
        """
        async with self._lock:
            return await self._process_request(request)

    async def _process_request(self, request: Request) -> Receipt:
        """Process a single request through the kernel pipeline."""
        start_ts = monotonic_ms()

        try:
            # Check if halted
            if self.state == KernelState.HALTED:
                raise StateError("Kernel is halted")

            # VALIDATING
            self._state_machine.transition_to(KernelState.VALIDATING)
            await self._validate_request(request)

            # ARBITRATING
            self._state_machine.transition_to(KernelState.ARBITRATING)
            decision, reason = await self._arbitrate_request(request)

            if decision == Decision.DENY:
                # Record denial and return
                entry = self._create_audit_entry(
                    request=request,
                    decision=decision,
                    reason=reason,
                    duration_ms=monotonic_ms() - start_ts,
                )
                self._ledger.append(entry)
                self._state_machine.transition_to(KernelState.IDLE)

                return Receipt(
                    request_id=request.request_id,
                    status="DENIED",
                    decision=decision,
                    error=reason,
                )

            # EXECUTING
            self._state_machine.transition_to(KernelState.EXECUTING)
            result, error = await self._execute_request(request)

            # AUDITING
            self._state_machine.transition_to(KernelState.AUDITING)
            entry = self._create_audit_entry(
                request=request,
                decision=decision,
                result=result,
                error=error,
                duration_ms=monotonic_ms() - start_ts,
            )
            self._ledger.append(entry)

            # Back to IDLE
            self._state_machine.transition_to(KernelState.IDLE)

            return Receipt(
                request_id=request.request_id,
                status="ACCEPTED" if not error else "ERROR",
                decision=decision,
                result=result,
                error=error,
            )

        except ValidationError as e:
            self._state_machine.transition_to(KernelState.IDLE)
            return Receipt(
                request_id=request.request_id,
                status="INVALID",
                decision=Decision.DENY,
                error=str(e),
            )
        except Exception as e:
            # Fail closed on any error
            self._state_machine.transition_to(KernelState.IDLE)
            return Receipt(
                request_id=request.request_id,
                status="ERROR",
                decision=Decision.DENY,
                error=str(e),
            )

    async def _validate_request(self, request: Request) -> None:
        """Validate request structure. Override in subclasses."""
        if not request.request_id:
            raise ValidationError("request_id is required")
        if not request.actor:
            raise ValidationError("actor is required")
        if not request.intent:
            raise ValidationError("intent is required")

    async def _arbitrate_request(
        self, request: Request
    ) -> tuple[Decision, Optional[str]]:
        """Evaluate request against policy. Override in subclasses."""
        # Check actor
        if request.actor not in self.policy.allowed_actors:
            return Decision.DENY, f"Actor {request.actor} not allowed"

        # Check tool
        if request.tool_call:
            if request.tool_call.name not in self.policy.allowed_tools:
                return Decision.DENY, f"Tool {request.tool_call.name} not allowed"
        elif self.policy.require_tool_call:
            return Decision.DENY, "tool_call is required"

        # Check intent length
        if len(request.intent) > self.policy.max_intent_length:
            return (
                Decision.DENY,
                f"Intent exceeds max length {self.policy.max_intent_length}",
            )

        return Decision.ALLOW, None

    async def _execute_request(
        self, request: Request
    ) -> tuple[Optional[Dict], Optional[str]]:
        """Execute the tool call. Override in subclasses."""
        if not request.tool_call:
            return None, None

        try:
            # Check if tool is async
            tool_fn = self.tool_registry.get(request.tool_call.name)
            if tool_fn:
                if asyncio.iscoroutinefunction(tool_fn):
                    result = await tool_fn(request.tool_call.params)
                else:
                    # Run sync tool in executor
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(
                        None, tool_fn, request.tool_call.params
                    )
                return result, None
            else:
                return None, f"Tool {request.tool_call.name} not found"
        except Exception as e:
            return None, str(e)

    def _create_audit_entry(
        self,
        request: Request,
        decision: Decision,
        reason: Optional[str] = None,
        result: Optional[Dict] = None,
        error: Optional[str] = None,
        duration_ms: int = 0,
    ) -> AuditEntry:
        """Create an audit entry for the request."""
        return AuditEntry(
            request_id=request.request_id,
            actor=request.actor,
            intent=request.intent,
            tool_name=request.tool_call.name if request.tool_call else None,
            decision=decision,
            reason=reason,
            error=error,
            ts_ms=monotonic_ms(),
            duration_ms=duration_ms,
        )

    def halt(self) -> None:
        """Immediately halt the kernel."""
        self._state_machine.transition_to(KernelState.HALTED)

    async def halt_async(self) -> None:
        """Async halt - waits for lock before halting."""
        async with self._lock:
            self.halt()

    def export_evidence(self) -> Dict[str, Any]:
        """Export audit evidence for external verification."""
        entries = self._ledger.export()
        return {
            "kernel_id": self.kernel_id,
            "exported_at": monotonic_ms(),
            "ledger_entries": entries,
            "root_hash": self._ledger.root_hash,
            "entry_count": len(entries),
        }

    async def export_evidence_async(self) -> Dict[str, Any]:
        """Async evidence export - waits for lock."""
        async with self._lock:
            return self.export_evidence()


class AsyncStrictKernel(AsyncBaseKernel):
    """
    Async version of StrictKernel.

    Maximum enforcement with strict validation.
    """

    async def _validate_request(self, request: Request) -> None:
        await super()._validate_request(request)

        # Strict: require tool_call
        if not request.tool_call:
            raise ValidationError("tool_call is required in strict mode")

        # Strict: check intent length
        if len(request.intent) < 3:
            raise ValidationError("intent too short")


class AsyncPermissiveKernel(AsyncBaseKernel):
    """
    Async version of PermissiveKernel.

    Relaxed thresholds for development.
    """

    def __init__(
        self,
        kernel_id: str,
        policy: Optional[JurisdictionPolicy] = None,
        tool_registry: Optional[ToolRegistry] = None,
    ):
        # Create permissive policy if none provided
        if policy is None:
            policy = JurisdictionPolicy(
                allowed_actors=["*"],
                allowed_tools=["*"],
                require_tool_call=False,
                max_intent_length=10000,
            )
        super().__init__(kernel_id, policy, tool_registry)

    async def _arbitrate_request(
        self, request: Request
    ) -> tuple[Decision, Optional[str]]:
        # Permissive: allow wildcards
        if (
            "*" in self.policy.allowed_actors
            or request.actor in self.policy.allowed_actors
        ):
            if request.tool_call:
                if (
                    "*" in self.policy.allowed_tools
                    or request.tool_call.name in self.policy.allowed_tools
                ):
                    return Decision.ALLOW, None
                return Decision.DENY, f"Tool {request.tool_call.name} not allowed"
            return Decision.ALLOW, None
        return Decision.DENY, f"Actor {request.actor} not allowed"


class AsyncEvidenceFirstKernel(AsyncBaseKernel):
    """
    Async version of EvidenceFirstKernel.

    Requires evidence field for all requests.
    """

    async def _validate_request(self, request: Request) -> None:
        await super()._validate_request(request)

        # Evidence required
        if not request.evidence:
            raise ValidationError("evidence field is required")


class AsyncDualChannelKernel(AsyncBaseKernel):
    """
    Async version of DualChannelKernel.

    Requires constraints dict for all requests.
    """

    async def _validate_request(self, request: Request) -> None:
        await super()._validate_request(request)

        # Constraints required
        if not request.constraints:
            raise ValidationError("constraints field is required")

        # Check required constraint fields
        required_fields = ["scope", "non_goals", "success_criteria"]
        for field in required_fields:
            if field not in request.constraints:
                raise ValidationError(f"constraints.{field} is required")


# Utility functions for async operations


async def submit_batch(
    kernel: AsyncBaseKernel,
    requests: List[Request],
    concurrency: int = 10,
) -> List[Receipt]:
    """
    Submit multiple requests with controlled concurrency.

    Args:
        kernel: The async kernel to use
        requests: List of requests to submit
        concurrency: Maximum concurrent requests

    Returns:
        List of receipts in same order as requests
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def submit_with_semaphore(request: Request) -> Receipt:
        async with semaphore:
            return await kernel.submit(request)

    tasks = [submit_with_semaphore(req) for req in requests]
    return await asyncio.gather(*tasks)


async def submit_with_timeout(
    kernel: AsyncBaseKernel,
    request: Request,
    timeout: float,
) -> Receipt:
    """
    Submit a request with timeout.

    Args:
        kernel: The async kernel to use
        request: The request to submit
        timeout: Timeout in seconds

    Returns:
        Receipt if completed within timeout

    Raises:
        asyncio.TimeoutError: If timeout exceeded
    """
    return await asyncio.wait_for(kernel.submit(request), timeout=timeout)


async def submit_with_retry(
    kernel: AsyncBaseKernel,
    request: Request,
    max_retries: int = 3,
    backoff: float = 1.0,
) -> Receipt:
    """
    Submit a request with retry on transient errors.

    Args:
        kernel: The async kernel to use
        request: The request to submit
        max_retries: Maximum retry attempts
        backoff: Initial backoff in seconds (doubles each retry)

    Returns:
        Receipt from successful submission
    """
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            receipt = await kernel.submit(request)
            if receipt.status != "ERROR":
                return receipt
            last_error = receipt.error
        except Exception as e:
            last_error = str(e)

        if attempt < max_retries:
            await asyncio.sleep(backoff * (2**attempt))

    return Receipt(
        request_id=request.request_id,
        status="ERROR",
        decision=Decision.DENY,
        error=f"Max retries exceeded: {last_error}",
    )
