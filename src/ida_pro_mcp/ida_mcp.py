"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.

Architecture: Connects to the MCP server's WebSocket server as a client.
The MCP server routes tool calls to this instance through the WS connection.
An HTTP server is kept running for the config UI.
"""

import sys
import json
import uuid
import asyncio
import threading
import traceback
import idaapi
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


class McpWsClient:
    """WebSocket client that connects to the MCP server and handles tool calls."""

    def __init__(self, ws_url: str, registry_dispatch, metadata: dict):
        self.ws_url = ws_url
        self.registry_dispatch = registry_dispatch
        self.metadata = metadata
        self.client_id = str(uuid.uuid4())[:8]
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._ws = None

    def start(self):
        """Start the WebSocket client in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        """Background thread: run the asyncio event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._connect())
        except Exception as e:
            if self._running:
                print(f"[MCP] WebSocket client error: {e}")
        finally:
            self._running = False

    async def _connect(self):
        """Connect to the MCP server and handle messages."""
        import websockets

        try:
            async with websockets.connect(self.ws_url) as ws:
                self._ws = ws
                # Send register message
                register_msg = {
                    "type": "register",
                    "client_id": self.client_id,
                    "metadata": self.metadata,
                }
                await ws.send(json.dumps(register_msg))
                print(f"[MCP] Connected to MCP server at {self.ws_url}")

                # Receive loop: handle JSON-RPC requests from server
                async for raw in ws:
                    if not self._running:
                        break
                    try:
                        request = json.loads(raw)
                        ws_id = request.pop("_ws_id", None)

                        # Dispatch to local IDA registry
                        response = self.registry_dispatch(request)

                        if response is not None and ws_id is not None:
                            response["_ws_id"] = ws_id
                            await ws.send(json.dumps(response))
                    except Exception as e:
                        print(f"[MCP] Error handling request: {e}")
                        traceback.print_exc()

        except Exception as e:
            if self._running:
                print(f"[MCP] WebSocket connection failed: {e}")
                print(f"[MCP] Make sure the MCP server is running (uv run ida-pro-mcp)")

    def stop(self):
        """Stop the WebSocket client."""
        self._running = False
        if self._ws and self._loop:
            asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop)
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None


def _get_idb_metadata() -> dict:
    """Query current IDB metadata for registration."""
    import idautils
    import idc
    import ida_ida

    info = ida_ida.inf_get_procname()
    module = idc.get_input_file_path()
    if module:
        import os
        module = os.path.basename(module)
    else:
        module = "unknown"

    return {
        "module": module,
        "arch": info if info else "unknown",
        "base": hex(ida_ida.inf_get_min_ea()),
    }


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    # WebSocket server to connect to
    WS_HOST = "127.0.0.1"
    WS_PORT = 13336

    # HTTP server for config UI
    HTTP_HOST = "127.0.0.1"
    HTTP_PORT = 13337

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
        )
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.ws_client: McpWsClient | None = None
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # Stop existing connections
        if self.ws_client:
            self.ws_client.stop()
            self.ws_client = None
        if self.mcp:
            self.mcp.stop()
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, init_caches

        try:
            init_caches()
        except Exception as e:
            print(f"[MCP] Cache init failed: {e}")

        # Start HTTP server for config UI
        try:
            MCP_SERVER.serve(
                self.HTTP_HOST, self.HTTP_PORT, request_handler=IdaMcpHttpRequestHandler
            )
            print(f"  Config: http://{self.HTTP_HOST}:{self.HTTP_PORT}/config.html")
            self.mcp = MCP_SERVER
        except OSError as e:
            if e.errno in (48, 98, 10048):  # Address already in use
                print(f"[MCP] Warning: Config UI port {self.HTTP_PORT} already in use (config UI unavailable)")
            else:
                raise

        # Connect to MCP server via WebSocket
        metadata = _get_idb_metadata()
        ws_url = f"ws://{self.WS_HOST}:{self.WS_PORT}"
        self.ws_client = McpWsClient(
            ws_url=ws_url,
            registry_dispatch=MCP_SERVER.registry.dispatch,
            metadata=metadata,
        )
        self.ws_client.start()

    def term(self):
        if self.ws_client:
            self.ws_client.stop()
            self.ws_client = None
        if self.mcp:
            self.mcp.stop()
            self.mcp = None


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
