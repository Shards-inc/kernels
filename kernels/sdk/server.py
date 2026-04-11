"""
KERNELS SDK Server

HTTP server for exposing kernel functionality.
"""

from __future__ import annotations

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, Optional, Type
import threading

from kernels.common.types import Request, ToolCall
from kernels.variants.base import BaseKernel
from kernels.variants.strict_kernel import StrictKernel
from kernels.jurisdiction.policy import JurisdictionPolicy


class KernelRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for kernel server."""

    # Class-level kernel reference (set by server)
    kernel: Optional[BaseKernel] = None

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _read_json(self) -> Dict[str, Any]:
        """Read JSON from request body."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        return json.loads(body.decode("utf-8")) if body else {}

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == "/health":
            self._handle_health()
        elif self.path == "/status":
            self._handle_status()
        elif self.path == "/evidence":
            self._handle_evidence()
        elif self.path == "/policy":
            self._handle_policy()
        elif self.path == "/":
            self._handle_info()
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        """Handle POST requests."""
        if self.path == "/submit":
            self._handle_submit()
        elif self.path == "/halt":
            self._handle_halt()
        else:
            self._send_json(404, {"error": "Not found"})

    def _handle_info(self) -> None:
        """Handle info request."""
        self._send_json(
            200,
            {
                "name": "KERNELS",
                "version": "0.1.0",
                "kernel_id": self.kernel.kernel_id if self.kernel else None,
            },
        )

    def _handle_health(self) -> None:
        """Handle health check."""
        if not self.kernel:
            self._send_json(503, {"status": "unhealthy", "error": "No kernel"})
            return

        self._send_json(
            200,
            {
                "status": "healthy",
                "kernel_state": self.kernel.state.value,
            },
        )

    def _handle_status(self) -> None:
        """Handle status request."""
        if not self.kernel:
            self._send_json(503, {"error": "No kernel"})
            return

        self._send_json(
            200,
            {
                "kernel_id": self.kernel.kernel_id,
                "state": self.kernel.state.value,
            },
        )

    def _handle_evidence(self) -> None:
        """Handle evidence export."""
        if not self.kernel:
            self._send_json(503, {"error": "No kernel"})
            return

        evidence = self.kernel.export_evidence()
        self._send_json(200, evidence)

    def _handle_policy(self) -> None:
        """Handle policy request."""
        if not self.kernel:
            self._send_json(503, {"error": "No kernel"})
            return

        policy = self.kernel.policy
        self._send_json(
            200,
            {
                "allowed_actors": policy.allowed_actors,
                "allowed_tools": policy.allowed_tools,
                "require_tool_call": policy.require_tool_call,
                "max_intent_length": policy.max_intent_length,
            },
        )

    def _handle_submit(self) -> None:
        """Handle request submission."""
        if not self.kernel:
            self._send_json(503, {"error": "No kernel"})
            return

        try:
            data = self._read_json()

            # Build request
            tool_call = None
            if "tool_call" in data:
                tool_call = ToolCall(
                    name=data["tool_call"]["name"],
                    params=data["tool_call"].get("params", {}),
                )

            request = Request(
                request_id=data["request_id"],
                actor=data["actor"],
                intent=data["intent"],
                tool_call=tool_call,
                evidence=data.get("evidence"),
                constraints=data.get("constraints"),
            )

            # Submit to kernel
            receipt = self.kernel.submit(request)

            self._send_json(
                200,
                {
                    "request_id": receipt.request_id,
                    "status": receipt.status,
                    "decision": receipt.decision.value,
                    "result": receipt.result,
                    "error": receipt.error,
                },
            )

        except KeyError as e:
            self._send_json(400, {"error": f"Missing field: {e}"})
        except Exception as e:
            self._send_json(500, {"error": str(e)})

    def _handle_halt(self) -> None:
        """Handle halt request."""
        if not self.kernel:
            self._send_json(503, {"error": "No kernel"})
            return

        self.kernel.halt()
        self._send_json(
            200,
            {
                "status": "halted",
                "kernel_state": self.kernel.state.value,
            },
        )

    def log_message(self, format: str, *args) -> None:
        """Override to customize logging."""
        pass  # Suppress default logging


class KernelServer:
    """
    HTTP server for KERNELS.

    Exposes kernel functionality via REST API.

    Example:
        kernel = StrictKernel(kernel_id="server-001")
        server = KernelServer(kernel, port=8080)
        server.start()
    """

    def __init__(
        self,
        kernel: BaseKernel,
        host: str = "127.0.0.1",
        port: int = 8080,
    ):
        self.kernel = kernel
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def _create_handler(self) -> Type[KernelRequestHandler]:
        """Create handler class with kernel reference."""
        kernel = self.kernel

        class Handler(KernelRequestHandler):
            pass

        Handler.kernel = kernel
        return Handler

    def start(self, blocking: bool = True) -> None:
        """
        Start the server.

        Args:
            blocking: If True, block until server stops.
                     If False, run in background thread.
        """
        handler = self._create_handler()
        self._server = HTTPServer((self.host, self.port), handler)

        if blocking:
            print(f"KERNELS server running on http://{self.host}:{self.port}")
            self._server.serve_forever()
        else:
            self._thread = threading.Thread(target=self._server.serve_forever)
            self._thread.daemon = True
            self._thread.start()
            print(f"KERNELS server started on http://{self.host}:{self.port}")

    def stop(self) -> None:
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    @property
    def url(self) -> str:
        """Get server URL."""
        return f"http://{self.host}:{self.port}"


def run_server(
    kernel_id: str = "server-001",
    host: str = "127.0.0.1",
    port: int = 8080,
    policy: Optional[JurisdictionPolicy] = None,
) -> None:
    """
    Convenience function to run a kernel server.

    Args:
        kernel_id: Kernel identifier
        host: Host to bind to
        port: Port to listen on
        policy: Jurisdiction policy (uses default if not specified)
    """
    kernel = StrictKernel(kernel_id=kernel_id, policy=policy)
    server = KernelServer(kernel, host, port)

    try:
        server.start(blocking=True)
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    run_server()
