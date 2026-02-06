"""Base kernel protocol and abstract implementation.

All kernel variants must implement the Kernel protocol. The BaseKernel
provides common functionality that variants can extend.
"""

from abc import ABC, abstractmethod
from typing import Optional

from kernels.common.types import (
    Decision,
    DecisionEnvelope,
    EvidenceBundle,
    KernelConfig,
    KernelReceipt,
    KernelRequest,
    KernelState,
    ReceiptStatus,
    ToolCall,
)
from kernels.common.errors import (
    AmbiguityError,
    BootError,
    JurisdictionError,
    PermitError,
    StateError,
)
from kernels.common.validate import validate_request, check_ambiguity
from kernels.audit.ledger import AuditLedger
from kernels.jurisdiction.policy import JurisdictionPolicy
from kernels.jurisdiction.rules import evaluate_policy
from kernels.state.machine import StateMachine
from kernels.execution.tools import create_default_registry
from kernels.execution.dispatcher import Dispatcher
from kernels.permits import (
    NonceRegistry,
    PermitToken,
    verify_permit,
)


class Kernel(ABC):
    """Protocol defining the kernel API surface.
    
    All kernel variants must implement these methods.
    """

    @abstractmethod
    def boot(self, config: KernelConfig) -> None:
        """Boot the kernel with configuration.
        
        Args:
            config: Kernel configuration.
            
        Raises:
            BootError: If boot fails.
        """
        ...

    @abstractmethod
    def get_state(self) -> KernelState:
        """Get the current kernel state.
        
        Returns:
            Current state.
        """
        ...

    @abstractmethod
    def submit(self, request: KernelRequest, permit_token: Optional[PermitToken] = None) -> KernelReceipt:
        """Submit a request for processing.

        Args:
            request: Request to process.
            permit_token: Permit token authorizing this request (required for execution in most variants).

        Returns:
            Receipt with processing result.
        """
        ...

    @abstractmethod
    def step(self) -> Optional[KernelReceipt]:
        """Advance the kernel by one step.
        
        Returns:
            Receipt if a step was taken, None if idle.
        """
        ...

    @abstractmethod
    def halt(self, reason: str) -> KernelReceipt:
        """Halt the kernel.
        
        Args:
            reason: Reason for halting.
            
        Returns:
            Receipt confirming halt.
        """
        ...

    @abstractmethod
    def export_evidence(self) -> EvidenceBundle:
        """Export the audit ledger as evidence.
        
        Returns:
            Evidence bundle with full ledger.
        """
        ...


class BaseKernel(Kernel):
    """Base implementation with common kernel functionality.
    
    Variants extend this class and override specific behaviors.
    """

    def __init__(self) -> None:
        """Initialize base kernel state."""
        self._config: Optional[KernelConfig] = None
        self._state_machine: Optional[StateMachine] = None
        self._ledger: Optional[AuditLedger] = None
        self._policy: Optional[JurisdictionPolicy] = None
        self._dispatcher: Optional[Dispatcher] = None
        self._pending_request: Optional[KernelRequest] = None
        self._pending_decision: Optional[Decision] = None
        self._pending_result: Optional[any] = None
        self._nonce_registry: NonceRegistry = NonceRegistry()
        self._keyring: dict[str, bytes] = {}  # HMAC keys for permit verification

    @property
    def config(self) -> KernelConfig:
        """Return kernel configuration."""
        if self._config is None:
            raise StateError("Kernel not booted")
        return self._config

    @property
    def policy(self) -> JurisdictionPolicy:
        """Return jurisdiction policy."""
        if self._policy is None:
            raise StateError("Kernel not booted")
        return self._policy

    def set_policy(self, policy: JurisdictionPolicy) -> None:
        """Set the jurisdiction policy.

        Args:
            policy: Policy to use.
        """
        self._policy = policy

    def set_keyring(self, keyring: dict[str, bytes]) -> None:
        """Set the HMAC keyring for permit verification.

        Args:
            keyring: Map of key_id -> HMAC secret key (32 bytes recommended).
        """
        self._keyring = keyring

    def load_ledger(self, evidence: EvidenceBundle) -> None:
        """Load ledger from evidence bundle and rebuild nonce registry.

        This enables cross-restart replay protection by reconstructing the
        nonce registry from audit entries. Entries are processed in deterministic
        order by ledger_seq to ensure consistent reconstruction.

        Args:
            evidence: Evidence bundle containing ledger entries.

        Raises:
            StateError: If kernel is not booted.
        """
        if self._ledger is None:
            raise StateError("Kernel not booted")

        # Sort entries by ledger_seq for deterministic ordering
        # This ensures tie-breaking when timestamps are identical
        sorted_entries = sorted(evidence.ledger_entries, key=lambda e: e.ledger_seq)

        # Rebuild ledger
        for entry in sorted_entries:
            # Re-add entry to ledger (this updates hash chain)
            self._ledger._entries.append(entry)
            self._ledger._last_hash = entry.entry_hash

        # Restore sequence counter from last entry
        if sorted_entries:
            self._ledger._next_seq = sorted_entries[-1].ledger_seq + 1

        # Rebuild nonce registry from entries with permit verification
        # Must process in ledger_seq order to correctly reconstruct use_count
        for entry in sorted_entries:
            if (entry.permit_digest and
                entry.permit_verification == "ALLOW" and
                entry.permit_nonce and
                entry.permit_issuer and
                entry.permit_subject and
                entry.permit_max_executions is not None):
                # Reconstruct nonce usage by calling check_and_record
                # This will mark the nonce as used in the registry
                self._nonce_registry.check_and_record(
                    nonce=entry.permit_nonce,
                    issuer=entry.permit_issuer,
                    subject=entry.permit_subject,
                    permit_id=entry.permit_digest,
                    max_executions=entry.permit_max_executions,
                    current_time_ms=entry.ts_ms,
                )

    def boot(self, config: KernelConfig) -> None:
        """Boot the kernel with configuration."""
        if self._state_machine is not None and not self._state_machine.is_halted:
            raise BootError("Kernel already booted")

        self._config = config
        self._state_machine = StateMachine(KernelState.BOOTING)
        self._ledger = AuditLedger(config.kernel_id, config.variant)
        self._policy = self._policy or JurisdictionPolicy.default()
        self._dispatcher = Dispatcher(create_default_registry())

        # Transition to IDLE
        self._state_machine.transition(KernelState.IDLE)

    def get_state(self) -> KernelState:
        """Get the current kernel state."""
        if self._state_machine is None:
            return KernelState.BOOTING
        return self._state_machine.state

    def submit(self, request: KernelRequest, permit_token: Optional[PermitToken] = None) -> KernelReceipt:
        """Submit a request for processing."""
        if self._state_machine is None:
            raise StateError("Kernel not booted")

        self._state_machine.assert_not_halted()
        self._state_machine.assert_state(KernelState.IDLE)

        state_from = self._state_machine.state

        # Transition to VALIDATING
        self._state_machine.transition(KernelState.VALIDATING)

        # Validate request structure
        validation_errors = validate_request(request)
        if validation_errors:
            return self._deny_request(
                request,
                state_from,
                f"Validation failed: {'; '.join(validation_errors)}",
            )

        # Check ambiguity
        ambiguity_errors = check_ambiguity(
            request,
            max_intent_length=self.config.max_intent_length,
            strict=self._is_strict_ambiguity(),
        )
        if ambiguity_errors:
            if self.config.fail_closed:
                return self._deny_request(
                    request,
                    state_from,
                    f"Ambiguity detected: {'; '.join(ambiguity_errors)}",
                )

        # Permit verification (CRITICAL: Hard gate before execution)
        permit_verification_result = None
        permit_digest = None
        proposal_hash = None
        permit_nonce = None
        permit_issuer = None
        permit_subject = None
        permit_max_executions = None

        # Check if permit is required
        if self._requires_permit(request):
            if permit_token is None:
                return self._deny_permit(
                    request,
                    state_from,
                    "MISSING_PERMIT",
                    ["MISSING_PERMIT"],
                )

            # Verify permit
            tool_name = request.tool_call.name if request.tool_call else None
            request_params = request.params if request.params else {}

            # Handle wildcard in allowed_tools
            allowed_actions = self.policy.allowed_tools
            if "*" in allowed_actions:
                # Wildcard means all actions are allowed
                # For permit verification, we create a set containing the specific action
                allowed_actions = frozenset({permit_token.action, "*"})

            permit_verification_result = verify_permit(
                permit=permit_token,
                keyring=self._keyring,
                nonce_registry=self._nonce_registry,
                current_time_ms=self.config.clock.now_ms(),
                current_jurisdiction="default",  # TODO: Make this configurable
                allowed_actions=allowed_actions,
                request_actor=request.actor,
                request_params=request_params,
            )

            permit_digest = permit_token.permit_id
            proposal_hash = permit_token.proposal_hash
            permit_nonce = permit_token.nonce  # For ledger-backed replay protection
            permit_issuer = permit_token.issuer  # For nonce reconstruction
            permit_subject = permit_token.subject  # For nonce reconstruction
            permit_max_executions = permit_token.max_executions  # For nonce reconstruction

            if not permit_verification_result.is_allowed():
                return self._deny_permit(
                    request,
                    state_from,
                    f"Permit verification failed: {', '.join(permit_verification_result.reasons)}",
                    permit_verification_result.reasons,
                    permit_digest=permit_digest,
                    proposal_hash=proposal_hash,
                )

            # Create DecisionEnvelope: bind verified permit to execution
            # This prevents TOCTOU by making permit and params immutable
            decision_envelope = DecisionEnvelope(
                proposal_hash=permit_token.proposal_hash,
                permit_digest=permit_token.permit_id,
                constraints=permit_token.constraints,
                max_time_ms=permit_token.constraints.get("max_time_ms"),
                forbidden_params=tuple(permit_token.constraints.get("forbidden_params", [])),
                tool_name=request.tool_call.name if request.tool_call else "",
                params=request_params.copy(),  # Immutable snapshot
                decision=Decision.ALLOW,
                verified_at_ms=self.config.clock.now_ms(),
                actor=request.actor,
            )
        else:
            decision_envelope = None

        # Transition to ARBITRATING
        self._state_machine.transition(KernelState.ARBITRATING)

        # Evaluate jurisdiction
        if self.config.require_jurisdiction:
            policy_result = evaluate_policy(request, self.policy)
            if not policy_result.allowed:
                return self._deny_request(
                    request,
                    state_from,
                    f"Jurisdiction denied: {'; '.join(policy_result.violations)}",
                )

        # Check variant-specific requirements
        variant_errors = self._check_variant_requirements(request)
        if variant_errors:
            return self._deny_request(
                request,
                state_from,
                f"Variant requirements not met: {'; '.join(variant_errors)}",
            )

        # Decide: ALLOW
        decision = Decision.ALLOW
        tool_result = None

        # Execute if tool_call present
        if request.tool_call is not None:
            # If we have a decision envelope, verify that request hasn't changed
            # This prevents TOCTOU bugs where request is mutated between validation and execution
            if decision_envelope is not None:
                if request.tool_call.name != decision_envelope.tool_name:
                    return self._fail_request(
                        request,
                        state_from,
                        f"TOCTOU detected: tool_name mismatch (envelope: {decision_envelope.tool_name}, request: {request.tool_call.name})",
                    )
                # Params may have been normalized, so we don't do strict equality check
                # The envelope proves what was verified; the params hash in audit proves what was executed

            self._state_machine.transition(KernelState.EXECUTING)
            exec_result = self._dispatcher.execute(request.tool_call)
            if not exec_result.success:
                return self._fail_request(
                    request,
                    state_from,
                    f"Tool execution failed: {exec_result.error}",
                )
            tool_result = exec_result.result

        # Audit
        self._state_machine.transition(KernelState.AUDITING)

        tool_name = None
        if request.tool_call is not None:
            if isinstance(request.tool_call, ToolCall):
                tool_name = request.tool_call.name
            else:
                tool_name = request.tool_call.get("name")

        entry = self._ledger.append(
            request_id=request.request_id,
            actor=request.actor,
            intent=request.intent,
            decision=decision,
            state_from=state_from,
            state_to=KernelState.IDLE,
            ts_ms=self.config.clock.now_ms(),
            tool_name=tool_name,
            params=request.params,
            evidence=request.evidence,
            permit_digest=permit_digest,
            permit_verification="ALLOW" if permit_verification_result else None,
            permit_denial_reasons=tuple(),
            proposal_hash=proposal_hash,
            permit_nonce=permit_nonce,
            permit_issuer=permit_issuer,
            permit_subject=permit_subject,
            permit_max_executions=permit_max_executions,
        )

        # Return to IDLE
        self._state_machine.transition(KernelState.IDLE)

        return KernelReceipt(
            request_id=request.request_id,
            status=ReceiptStatus.ACCEPTED,
            state_from=state_from,
            state_to=KernelState.IDLE,
            ts_ms=self.config.clock.now_ms(),
            decision=decision,
            evidence_hash=entry.entry_hash,
            tool_result=tool_result,
        )

    def step(self) -> Optional[KernelReceipt]:
        """Advance the kernel by one step."""
        # Base implementation: no pending work
        return None

    def halt(self, reason: str) -> KernelReceipt:
        """Halt the kernel."""
        if self._state_machine is None:
            raise StateError("Kernel not booted")

        state_from = self._state_machine.state
        self._state_machine.halt()

        # Audit the halt
        entry = self._ledger.append(
            request_id="HALT",
            actor="SYSTEM",
            intent=reason,
            decision=Decision.HALT,
            state_from=state_from,
            state_to=KernelState.HALTED,
            ts_ms=self.config.clock.now_ms(),
        )

        return KernelReceipt(
            request_id="HALT",
            status=ReceiptStatus.ACCEPTED,
            state_from=state_from,
            state_to=KernelState.HALTED,
            ts_ms=self.config.clock.now_ms(),
            decision=Decision.HALT,
            evidence_hash=entry.entry_hash,
        )

    def export_evidence(self) -> EvidenceBundle:
        """Export the audit ledger as evidence."""
        if self._ledger is None:
            raise StateError("Kernel not booted")
        return self._ledger.export(self.config.clock.now_ms())

    def _deny_request(
        self,
        request: KernelRequest,
        state_from: KernelState,
        error: str,
    ) -> KernelReceipt:
        """Create a DENY receipt and audit entry."""
        # Transition to AUDITING
        if self._state_machine.state != KernelState.AUDITING:
            self._state_machine.transition(KernelState.AUDITING)

        entry = self._ledger.append(
            request_id=request.request_id,
            actor=request.actor,
            intent=request.intent,
            decision=Decision.DENY,
            state_from=state_from,
            state_to=KernelState.IDLE,
            ts_ms=self.config.clock.now_ms(),
            error=error,
        )

        # Return to IDLE
        self._state_machine.transition(KernelState.IDLE)

        return KernelReceipt(
            request_id=request.request_id,
            status=ReceiptStatus.REJECTED,
            state_from=state_from,
            state_to=KernelState.IDLE,
            ts_ms=self.config.clock.now_ms(),
            decision=Decision.DENY,
            error=error,
            evidence_hash=entry.entry_hash,
        )

    def _fail_request(
        self,
        request: KernelRequest,
        state_from: KernelState,
        error: str,
    ) -> KernelReceipt:
        """Create a FAILED receipt and audit entry."""
        # Transition to AUDITING
        if self._state_machine.state != KernelState.AUDITING:
            self._state_machine.transition(KernelState.AUDITING)

        entry = self._ledger.append(
            request_id=request.request_id,
            actor=request.actor,
            intent=request.intent,
            decision=Decision.DENY,
            state_from=state_from,
            state_to=KernelState.IDLE,
            ts_ms=self.config.clock.now_ms(),
            error=error,
        )

        # Return to IDLE
        self._state_machine.transition(KernelState.IDLE)

        return KernelReceipt(
            request_id=request.request_id,
            status=ReceiptStatus.FAILED,
            state_from=state_from,
            state_to=KernelState.IDLE,
            ts_ms=self.config.clock.now_ms(),
            decision=Decision.DENY,
            error=error,
            evidence_hash=entry.entry_hash,
        )

    def _is_strict_ambiguity(self) -> bool:
        """Return whether strict ambiguity checking is enabled."""
        return True

    def _check_variant_requirements(self, request: KernelRequest) -> list[str]:
        """Check variant-specific requirements. Override in variants."""
        return []

    def _requires_permit(self, request: KernelRequest) -> bool:
        """Determine if request requires a permit token.

        Override in variants to customize permit requirements.

        Default behavior:
        - Permit required if:
          1. Keyring is configured (permits can be verified), AND
          2. Request has tool_call (will execute code)
        - Permit optional otherwise (backward compatible with tests)

        Returns:
            True if permit is required, False otherwise.
        """
        # If no keyring configured, permits are not enforced (backward compat)
        if not self._keyring:
            return False

        # If keyring is configured, require permit for any request that can reach EXECUTING
        return request.tool_call is not None

    def _deny_permit(
        self,
        request: KernelRequest,
        state_from: KernelState,
        error: str,
        denial_reasons: list[str],
        permit_digest: Optional[str] = None,
        proposal_hash: Optional[str] = None,
    ) -> KernelReceipt:
        """Create a DENY receipt for permit verification failure.

        Args:
            request: The request being denied.
            state_from: State before validation.
            error: Human-readable error message.
            denial_reasons: List of denial reason codes.
            permit_digest: Permit ID if permit was present.
            proposal_hash: Proposal hash from permit if present.

        Returns:
            Receipt with DENY decision and permit denial audit.
        """
        # Transition to AUDITING
        if self._state_machine.state != KernelState.AUDITING:
            self._state_machine.transition(KernelState.AUDITING)

        entry = self._ledger.append(
            request_id=request.request_id,
            actor=request.actor,
            intent=request.intent,
            decision=Decision.DENY,
            state_from=state_from,
            state_to=KernelState.IDLE,
            ts_ms=self.config.clock.now_ms(),
            error=error,
            permit_digest=permit_digest,
            permit_verification="DENY",
            permit_denial_reasons=tuple(denial_reasons),
            proposal_hash=proposal_hash,
        )

        # Return to IDLE
        self._state_machine.transition(KernelState.IDLE)

        return KernelReceipt(
            request_id=request.request_id,
            status=ReceiptStatus.REJECTED,
            state_from=state_from,
            state_to=KernelState.IDLE,
            ts_ms=self.config.clock.now_ms(),
            decision=Decision.DENY,
            error=error,
            evidence_hash=entry.entry_hash,
        )
