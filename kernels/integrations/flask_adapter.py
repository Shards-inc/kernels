"""
KERNELS Flask Integration

Provides Flask app factory for kernel servers.
"""

from __future__ import annotations

from typing import Optional

try:
    from flask import Flask, request, jsonify

    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

from kernels.common.types import Request, ToolCall
from kernels.variants.base import BaseKernel
from kernels.variants.strict_kernel import StrictKernel
from kernels.jurisdiction.policy import JurisdictionPolicy


def create_flask_app(
    kernel: Optional[BaseKernel] = None,
    kernel_id: str = "flask-kernel",
    policy: Optional[JurisdictionPolicy] = None,
) -> "Flask":
    """
    Create a Flask app for the kernel.

    Args:
        kernel: Existing kernel to use (creates new if None)
        kernel_id: Kernel ID if creating new kernel
        policy: Policy for new kernel

    Returns:
        Flask app instance
    """
    if not HAS_FLASK:
        raise ImportError("Flask not installed. Run: pip install flask")

    # Create kernel if not provided
    if kernel is None:
        kernel = StrictKernel(kernel_id=kernel_id, policy=policy)

    # Create app
    app = Flask(__name__)
    app.config["kernel"] = kernel

    @app.route("/", methods=["GET"])
    def info():
        """Get API info."""
        return jsonify(
            {
                "name": "KERNELS",
                "version": "0.1.0",
                "kernel_id": app.config["kernel"].kernel_id,
            }
        )

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint."""
        k = app.config["kernel"]
        return jsonify(
            {
                "status": "healthy",
                "kernel_state": k.state.value,
            }
        )

    @app.route("/status", methods=["GET"])
    def status():
        """Get kernel status."""
        k = app.config["kernel"]
        return jsonify(
            {
                "kernel_id": k.kernel_id,
                "state": k.state.value,
            }
        )

    @app.route("/submit", methods=["POST"])
    def submit():
        """Submit a request to the kernel."""
        k = app.config["kernel"]
        data = request.get_json()

        # Build tool call
        tool_call = None
        if "tool_call" in data:
            tool_call = ToolCall(
                name=data["tool_call"]["name"],
                params=data["tool_call"].get("params", {}),
            )

        # Build request
        req = Request(
            request_id=data["request_id"],
            actor=data["actor"],
            intent=data["intent"],
            tool_call=tool_call,
            evidence=data.get("evidence"),
            constraints=data.get("constraints"),
        )

        # Submit
        receipt = k.submit(req)

        return jsonify(
            {
                "request_id": receipt.request_id,
                "status": receipt.status,
                "decision": receipt.decision.value,
                "result": receipt.result,
                "error": receipt.error,
            }
        )

    @app.route("/evidence", methods=["GET"])
    def evidence():
        """Export audit evidence."""
        k = app.config["kernel"]
        return jsonify(k.export_evidence())

    @app.route("/policy", methods=["GET"])
    def policy():
        """Get current policy."""
        k = app.config["kernel"]
        p = k.policy
        return jsonify(
            {
                "allowed_actors": p.allowed_actors,
                "allowed_tools": p.allowed_tools,
                "require_tool_call": p.require_tool_call,
                "max_intent_length": p.max_intent_length,
            }
        )

    @app.route("/halt", methods=["POST"])
    def halt():
        """Halt the kernel."""
        k = app.config["kernel"]
        k.halt()
        return jsonify(
            {
                "status": "halted",
                "kernel_state": k.state.value,
            }
        )

    return app


def run_flask_server(
    kernel_id: str = "flask-kernel",
    host: str = "0.0.0.0",
    port: int = 8080,
    policy: Optional[JurisdictionPolicy] = None,
    debug: bool = False,
) -> None:
    """
    Run Flask server.

    Args:
        kernel_id: Kernel identifier
        host: Host to bind to
        port: Port to listen on
        policy: Jurisdiction policy
        debug: Enable debug mode
    """
    app = create_flask_app(kernel_id=kernel_id, policy=policy)
    app.run(host=host, port=port, debug=debug)
