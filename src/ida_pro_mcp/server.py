import os
import sys
import json
import shutil
import argparse
import asyncio
import threading
import tempfile
import traceback
import tomllib
import tomli_w
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse
import glob

if TYPE_CHECKING:
    from ida_pro_mcp.ida_mcp.zeromcp import McpServer
    from ida_pro_mcp.ida_mcp.zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest
else:
    # Pre-load stdlib http before adding ida_mcp/ to sys.path, otherwise
    # ida_mcp/http.py shadows the stdlib http package and breaks imports.
    import http.server  # noqa: F401

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ida_mcp"))
    from zeromcp import McpServer
    from zeromcp.jsonrpc import JsonRpcResponse, JsonRpcRequest

    sys.path.pop(0)  # Clean up

WS_HOST = "127.0.0.1"
WS_PORT = 13336

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PKG = os.path.join(SCRIPT_DIR, "ida_mcp")
IDA_PLUGIN_LOADER = os.path.join(SCRIPT_DIR, "ida_mcp.py")

mcp = McpServer("ida-pro-mcp")
dispatch_original = mcp.registry.dispatch


# ============================================================================
# Instance Registry
# ============================================================================

class InstanceInfo:
    """Represents a connected IDA Pro instance."""
    def __init__(self, client_id: str, ws, metadata: dict):
        self.client_id = client_id
        self.ws = ws  # websockets connection
        self.module: str = metadata.get("module", "unknown")
        self.arch: str = metadata.get("arch", "unknown")
        self.base: str = metadata.get("base", "0x0")
        self.port: int = metadata.get("port", 0)
        self.metadata = metadata
        self._request_id = 0
        self._pending: dict[int, threading.Event] = {}
        self._responses: dict[int, Any] = {}
        self._lock = threading.Lock()

    def next_request_id(self) -> int:
        with self._lock:
            self._request_id += 1
            return self._request_id

    def to_dict(self) -> dict:
        return {
            "id": self.client_id,
            "module": self.module,
            "arch": self.arch,
            "base": self.base,
        }


instances: dict[str, InstanceInfo] = {}
instances_lock = threading.Lock()


# ============================================================================
# Instance param injection
# ============================================================================

INSTANCE_PARAM = {
    "type": "string",
    "description": "Target IDA instance (module name or ID from list_instances)",
}


def _inject_instance_param(tool_schema: dict) -> None:
    """Add required `instance` parameter to a tool's inputSchema."""
    input_schema = tool_schema.get("inputSchema", {})
    properties = input_schema.get("properties", {})
    if "instance" not in properties:
        properties["instance"] = INSTANCE_PARAM
        input_schema["properties"] = properties
        required = input_schema.get("required", [])
        required.insert(0, "instance")
        input_schema["required"] = required


# ============================================================================
# Static tool schema extraction (AST-based, no IDA imports needed)
# ============================================================================

def _parse_tools_from_source() -> list[dict]:
    """Parse @tool function schemas from api_*.py files using AST.

    Extracts function name, docstring, and parameter info (from Annotated types)
    without importing any IDA modules.
    """
    import ast as _ast

    api_dir = os.path.join(SCRIPT_DIR, "ida_mcp")
    tools = []

    for filename in sorted(os.listdir(api_dir)):
        if not filename.startswith("api_") or not filename.endswith(".py"):
            continue

        filepath = os.path.join(api_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                tree = _ast.parse(f.read(), filename)
        except Exception:
            continue

        for node in _ast.walk(tree):
            if not isinstance(node, _ast.FunctionDef):
                continue

            # Check if decorated with @tool
            is_tool = False
            for dec in node.decorator_list:
                if isinstance(dec, _ast.Name) and dec.id == "tool":
                    is_tool = True
                    break
            if not is_tool:
                continue

            # Extract docstring (first line only)
            docstring = _ast.get_docstring(node) or f"Call {node.name}"
            description = docstring.strip().split("\n")[0].strip()

            # Extract parameters
            properties = {}
            required = []

            for arg in node.args.args:
                param_name = arg.arg
                if param_name in ("self", "cls"):
                    continue

                param_schema: dict = {"type": "string"}

                # Try to extract description from Annotated[..., "desc"]
                annotation = arg.annotation
                if annotation and isinstance(annotation, _ast.Subscript):
                    # Annotated[type, "description"]
                    if isinstance(annotation.value, _ast.Name) and annotation.value.id == "Annotated":
                        if isinstance(annotation.slice, _ast.Tuple):
                            elts = annotation.slice.elts
                            if len(elts) >= 2:
                                # Get description from last element
                                desc_node = elts[-1]
                                if isinstance(desc_node, _ast.Constant) and isinstance(desc_node.value, str):
                                    param_schema["description"] = desc_node.value

                                # Get type from first element
                                type_node = elts[0]
                                param_schema["type"] = _ast_type_to_json(type_node)

                properties[param_name] = param_schema

                # Check if parameter has a default value
                # defaults are right-aligned to args
                n_args = len(node.args.args)
                n_defaults = len(node.args.defaults)
                arg_index = node.args.args.index(arg)
                has_default = arg_index >= (n_args - n_defaults)
                if not has_default:
                    required.append(param_name)

            tool_schema = {
                "name": node.name,
                "description": description,
                "inputSchema": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            }
            tools.append(tool_schema)

    return tools


def _ast_type_to_json(node) -> str:
    """Convert an AST type node to a simple JSON schema type string."""
    import ast as _ast

    if isinstance(node, _ast.Name):
        return {
            "str": "string",
            "int": "integer",
            "float": "number",
            "bool": "boolean",
            "list": "array",
            "dict": "object",
        }.get(node.id, "string")

    if isinstance(node, _ast.Constant) and isinstance(node.value, str):
        return "string"

    # For complex types (list[X] | Y, etc.) just use string
    return "string"


# Parse tool schemas at import time (no IDA needed)
_static_tools: list[dict] = _parse_tools_from_source()
for _t in _static_tools:
    _inject_instance_param(_t)


# ============================================================================
# WebSocket Server
# ============================================================================

_ws_loop: asyncio.AbstractEventLoop | None = None
_ws_thread: threading.Thread | None = None


def _send_ws_request_sync(instance: InstanceInfo, request_data: dict) -> dict:
    """Send a JSON-RPC request through WebSocket and wait for response synchronously.

    Schedules the WS send on the asyncio loop, then blocks on a threading.Event
    for the response (which arrives via the WS receive loop on the asyncio thread).
    """
    if _ws_loop is None:
        raise RuntimeError("WebSocket server not running")

    req_id = instance.next_request_id()
    request_data = {**request_data, "_ws_id": req_id}

    event = threading.Event()
    with instance._lock:
        instance._pending[req_id] = event

    try:
        # Schedule the send on the asyncio event loop
        send_future = asyncio.run_coroutine_threadsafe(
            instance.ws.send(json.dumps(request_data)), _ws_loop
        )
        send_future.result(timeout=10)  # Wait for send to complete

        # Block until response arrives (set by _handle_ws_client receive loop)
        if not event.wait(timeout=120):
            raise TimeoutError("IDA instance did not respond within 120 seconds")
        with instance._lock:
            return instance._responses.pop(req_id)
    finally:
        with instance._lock:
            instance._pending.pop(req_id, None)
            instance._responses.pop(req_id, None)


async def _handle_ws_client(websocket):
    """Handle a single WebSocket client (IDA instance) connection."""
    client_id: str | None = None

    try:
        # First message must be a register message
        raw = await websocket.recv()
        msg = json.loads(raw)

        if msg.get("type") != "register":
            await websocket.close(1002, "First message must be 'register'")
            return

        client_id = msg.get("client_id", "")
        metadata = msg.get("metadata", {})
        info = InstanceInfo(client_id, websocket, metadata)

        with instances_lock:
            instances[client_id] = info

        module = metadata.get("module", "unknown")
        print(f"[MCP] IDA instance connected: {module} ({client_id})", file=sys.stderr)

        # Receive loop: handle responses from IDA
        async for raw in websocket:
            msg = json.loads(raw)
            ws_id = msg.pop("_ws_id", None)
            if ws_id is not None:
                with info._lock:
                    info._responses[ws_id] = msg
                    event = info._pending.get(ws_id)
                    if event:
                        event.set()

    except Exception as e:
        if client_id:
            print(f"[MCP] IDA instance error ({client_id}): {e}", file=sys.stderr)
    finally:
        if client_id:
            with instances_lock:
                instances.pop(client_id, None)
            print(f"[MCP] IDA instance disconnected: {client_id}", file=sys.stderr)


async def _run_ws_server(host: str, port: int):
    """Run the WebSocket server."""
    import websockets
    async with websockets.serve(_handle_ws_client, host, port):
        print(f"[MCP] WebSocket server listening on {host}:{port}", file=sys.stderr)
        await asyncio.Future()  # run forever


def start_ws_server(host: str, port: int):
    """Start the WebSocket server in a background thread."""
    global _ws_loop, _ws_thread

    def run():
        global _ws_loop
        _ws_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_ws_loop)
        _ws_loop.run_until_complete(_run_ws_server(host, port))

    _ws_thread = threading.Thread(target=run, daemon=True)
    _ws_thread.start()


# ============================================================================
# Local tools
# ============================================================================

LOCAL_TOOLS = [
    {
        "name": "list_instances",
        "description": "List all connected IDA Pro instances. Call this first to get instance IDs/module names for other tools.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]


def handle_list_instances() -> dict:
    """Handle the list_instances tool call."""
    with instances_lock:
        result = [info.to_dict() for cid, info in instances.items()]
    return {
        "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
        "structuredContent": {"result": result},
        "isError": False,
    }


def _resolve_instance(instance_key: str) -> InstanceInfo | None:
    """Resolve an instance by ID or module name. Returns None if not found."""
    with instances_lock:
        # Auto-select if only one instance connected
        if not instance_key and len(instances) == 1:
            return next(iter(instances.values()))
        # Exact ID match
        if instance_key in instances:
            return instances[instance_key]
        # Module name match (case-insensitive)
        for cid, info in instances.items():
            if info.module.lower() == instance_key.lower():
                return info
    return None


# ============================================================================
# Dispatch proxy: route requests through WebSocket
# ============================================================================

def dispatch_proxy(request: dict | str | bytes | bytearray) -> JsonRpcResponse | None:
    """Dispatch JSON-RPC requests: local handling or WS routing to IDA."""
    if not isinstance(request, dict):
        request_obj: JsonRpcRequest = json.loads(request)
    else:
        request_obj: JsonRpcRequest = request  # type: ignore

    method = request_obj.get("method", "")

    # Handle locally: initialize, notifications
    if method == "initialize":
        return dispatch_original(request)
    if method.startswith("notifications/"):
        return dispatch_original(request)

    # Handle tools/call
    if method == "tools/call":
        params = request_obj.get("params", {})
        tool_name = params.get("name", "") if isinstance(params, dict) else ""
        tool_args = params.get("arguments", {}) if isinstance(params, dict) else {}

        # Local tool: list_instances
        if tool_name == "list_instances":
            request_id = request_obj.get("id")
            return {
                "jsonrpc": "2.0",
                "result": handle_list_instances(),
                "id": request_id,
            }

        # All other tools: resolve instance from required `instance` param, forward to IDA
        instance_key = tool_args.get("instance", "")
        instance = _resolve_instance(instance_key)
        if instance is None:
            request_id = request_obj.get("id")
            if not instance_key:
                msg = "Missing required parameter 'instance'. Use list_instances to see connected IDA instances."
            else:
                msg = f"Instance not found: '{instance_key}'. Use list_instances to see connected IDA instances."
            return {
                "jsonrpc": "2.0",
                "result": {
                    "content": [{"type": "text", "text": msg}],
                    "isError": True,
                },
                "id": request_id,
            }

        # Strip `instance` param before forwarding to IDA
        forward_args = {k: v for k, v in tool_args.items() if k != "instance"}
        forward_request = {**request_obj}
        forward_request["params"] = {**params, "arguments": forward_args}
        try:
            return _send_ws_request_sync(instance, forward_request)
        except Exception as e:
            request_id = request_obj.get("id")
            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": f"Failed to communicate with IDA instance ({instance.module}): {e}",
                },
                "id": request_id,
            }

    # Handle tools/list: return statically-parsed tool schemas (always available)
    if method == "tools/list":
        request_id = request_obj.get("id")
        return {
            "jsonrpc": "2.0",
            "result": {"tools": LOCAL_TOOLS + _static_tools},
            "id": request_id,
        }

    # All other requests: route to first available instance
    with instances_lock:
        instance = next(iter(instances.values()), None) if instances else None

    if instance is None:
        request_id = request_obj.get("id")
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": "No IDA instances connected.",
            },
            "id": request_id,
        }

    try:
        return _send_ws_request_sync(instance, request_obj)
    except Exception as e:
        request_id = request_obj.get("id")
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "error": {
                "code": -32000,
                "message": f"Failed to communicate with IDA instance: {e}",
            },
            "id": request_id,
        }


mcp.registry.dispatch = dispatch_proxy


# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PKG):
    raise RuntimeError(
        f"IDA plugin package not found at {IDA_PLUGIN_PKG} (did you move it?)"
    )
if not os.path.exists(IDA_PLUGIN_LOADER):
    raise RuntimeError(
        f"IDA plugin loader not found at {IDA_PLUGIN_LOADER} (did you move it?)"
    )


def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable


def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def generate_mcp_config(*, stdio: bool):
    if stdio:
        mcp_config = {
            "command": get_python_executable(),
            "args": [
                __file__,
            ],
        }
        env = {}
        if copy_python_env(env):
            print("[WARNING] Custom Python environment variables detected")
            mcp_config["env"] = env
        return mcp_config
    else:
        return {"type": "http", "url": f"http://{WS_HOST}:{WS_PORT}/mcp"}


def print_mcp_config():
    print("[HTTP MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=False)}}, indent=2
        )
    )
    print("\n[STDIO MCP CONFIGURATION]")
    print(
        json.dumps(
            {"mcpServers": {mcp.name: generate_mcp_config(stdio=True)}}, indent=2
        )
    )


def install_mcp_servers(*, stdio: bool = False, uninstall=False, quiet=False):
    # Map client names to their JSON key paths for clients that don't use "mcpServers"
    # Format: client_name -> (top_level_key, nested_key)
    # None means use default "mcpServers" at top level
    special_json_structures = {
        "VS Code": ("mcp", "servers"),
        "VS Code Insiders": ("mcp", "servers"),
        "Visual Studio 2022": (None, "servers"),  # servers at top level
    }

    if sys.platform == "win32":
        configs = {
            "Cline": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(os.getenv("APPDATA", ""), "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Zed": (
                os.path.join(os.getenv("APPDATA", ""), "Zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(
                    os.getenv("APPDATA", ""),
                    "Code - Insiders",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Claude": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Claude"
                ),
                "claude_desktop_config.json",
            ),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(
                    os.path.expanduser("~"), "Library", "Application Support", "Zed"
                ),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "BoltAI": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "BoltAI",
                ),
                "config.json",
            ),
            "Perplexity": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Perplexity",
                ),
                "mcp_config.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(
                    os.path.expanduser("~"),
                    "Library",
                    "Application Support",
                    "Code - Insiders",
                    "User",
                ),
                "settings.json",
            ),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "saoudrizwan.claude-dev",
                    "settings",
                ),
                "cline_mcp_settings.json",
            ),
            "Roo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "rooveterinaryinc.roo-cline",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            "Kilo Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                    "globalStorage",
                    "kilocode.kilo-code",
                    "settings",
                ),
                "mcp_settings.json",
            ),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (
                os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (
                os.path.join(os.path.expanduser("~"), ".lmstudio"),
                "mcp.json",
            ),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
            "Antigravity IDE": (
                os.path.join(os.path.expanduser("~"), ".gemini", "antigravity"),
                "mcp_config.json",
            ),
            "Zed": (
                os.path.join(os.path.expanduser("~"), ".config", "zed"),
                "settings.json",
            ),
            "Gemini CLI": (
                os.path.join(os.path.expanduser("~"), ".gemini"),
                "settings.json",
            ),
            "Qwen Coder": (
                os.path.join(os.path.expanduser("~"), ".qwen"),
                "settings.json",
            ),
            "Copilot CLI": (
                os.path.join(os.path.expanduser("~"), ".copilot"),
                "mcp-config.json",
            ),
            "Crush": (
                os.path.join(os.path.expanduser("~")),
                "crush.json",
            ),
            "Augment Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Qodo Gen": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "Warp": (
                os.path.join(os.path.expanduser("~"), ".warp"),
                "mcp_config.json",
            ),
            "Amazon Q": (
                os.path.join(os.path.expanduser("~"), ".aws", "amazonq"),
                "mcp_config.json",
            ),
            "Opencode": (
                os.path.join(os.path.expanduser("~"), ".opencode"),
                "mcp_config.json",
            ),
            "Kiro": (
                os.path.join(os.path.expanduser("~"), ".kiro"),
                "mcp_config.json",
            ),
            "Trae": (
                os.path.join(os.path.expanduser("~"), ".trae"),
                "mcp_config.json",
            ),
            "VS Code": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code",
                    "User",
                ),
                "settings.json",
            ),
            "VS Code Insiders": (
                os.path.join(
                    os.path.expanduser("~"),
                    ".config",
                    "Code - Insiders",
                    "User",
                ),
                "settings.json",
            ),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue

        # Read existing config
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(
                config_path,
                "rb" if is_toml else "r",
                encoding=None if is_toml else "utf-8",
            ) as f:
                if is_toml:
                    data = f.read()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = tomllib.loads(data.decode("utf-8"))
                        except tomllib.TOMLDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid TOML)"
                                )
                            continue
                else:
                    data = f.read().strip()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = json.loads(data)
                        except json.decoder.JSONDecodeError:
                            if not quiet:
                                print(
                                    f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)"
                                )
                            continue

        # Handle TOML vs JSON structure
        if is_toml:
            if "mcp_servers" not in config:
                config["mcp_servers"] = {}
            mcp_servers = config["mcp_servers"]
        else:
            # Check if this client uses a special JSON structure
            if name in special_json_structures:
                top_key, nested_key = special_json_structures[name]
                if top_key is None:
                    # servers at top level (e.g., Visual Studio 2022)
                    if nested_key not in config:
                        config[nested_key] = {}
                    mcp_servers = config[nested_key]
                else:
                    # nested structure (e.g., VS Code uses mcp.servers)
                    if top_key not in config:
                        config[top_key] = {}
                    if nested_key not in config[top_key]:
                        config[top_key][nested_key] = {}
                    mcp_servers = config[top_key][nested_key]
            else:
                # Default: mcpServers at top level
                if "mcpServers" not in config:
                    config["mcpServers"] = {}
                mcp_servers = config["mcpServers"]

        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]

        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(
                        f"Skipping {name} uninstall\n  Config: {config_path} (not installed)"
                    )
                continue
            del mcp_servers[mcp.name]
        else:
            mcp_servers[mcp.name] = generate_mcp_config(stdio=stdio)

        # Atomic write: temp file + rename
        suffix = ".toml" if is_toml else ".json"
        fd, temp_path = tempfile.mkstemp(
            dir=config_dir, prefix=".tmp_", suffix=suffix, text=True
        )
        try:
            with os.fdopen(
                fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8"
            ) as f:
                if is_toml:
                    f.write(tomli_w.dumps(config).encode("utf-8"))
                else:
                    json.dump(config, f, indent=2)
            os.replace(temp_path, config_path)
        except:
            os.unlink(temp_path)
            raise

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(
                f"{action} {name} MCP server (restart required)\n  Config: {config_path}"
            )
        installed += 1
    if not uninstall and installed == 0:
        print(
            "No MCP servers installed. For unsupported MCP clients, use the following config:\n"
        )
        print_mcp_config()


def install_ida_plugin(
    *, uninstall: bool = False, quiet: bool = False, allow_ida_free: bool = False
):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    if not allow_ida_free:
        free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if len(free_licenses) > 0:
            print(
                "IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead."
            )
            sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")

    # Install both the loader file and package directory
    loader_source = IDA_PLUGIN_LOADER
    loader_destination = os.path.join(ida_plugin_folder, "ida_mcp.py")

    pkg_source = IDA_PLUGIN_PKG
    pkg_destination = os.path.join(ida_plugin_folder, "ida_mcp")

    # Clean up old plugin if it exists
    old_plugin = os.path.join(ida_plugin_folder, "mcp-plugin.py")

    if uninstall:
        # Remove loader
        if os.path.lexists(loader_destination):
            os.remove(loader_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin loader\n  Path: {loader_destination}")

        # Remove package
        if os.path.exists(pkg_destination):
            if os.path.isdir(pkg_destination) and not os.path.islink(pkg_destination):
                shutil.rmtree(pkg_destination)
            else:
                os.remove(pkg_destination)
            if not quiet:
                print(f"Uninstalled IDA plugin package\n  Path: {pkg_destination}")

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin\n  Path: {old_plugin}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Remove old plugin if it exists
        if os.path.lexists(old_plugin):
            os.remove(old_plugin)
            if not quiet:
                print(f"Removed old plugin file\n  Path: {old_plugin}")

        installed_items = []

        # Install loader file
        loader_realpath = (
            os.path.realpath(loader_destination)
            if os.path.lexists(loader_destination)
            else None
        )
        if loader_realpath != loader_source:
            if os.path.lexists(loader_destination):
                os.remove(loader_destination)

            try:
                os.symlink(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")
            except OSError:
                shutil.copy(loader_source, loader_destination)
                installed_items.append(f"loader: {loader_destination}")

        # Install package directory
        pkg_realpath = (
            os.path.realpath(pkg_destination)
            if os.path.lexists(pkg_destination)
            else None
        )
        if pkg_realpath != pkg_source:
            if os.path.lexists(pkg_destination):
                if os.path.isdir(pkg_destination) and not os.path.islink(
                    pkg_destination
                ):
                    shutil.rmtree(pkg_destination)
                else:
                    os.remove(pkg_destination)

            try:
                os.symlink(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")
            except OSError:
                shutil.copytree(pkg_source, pkg_destination)
                installed_items.append(f"package: {pkg_destination}")

        if not quiet:
            if installed_items:
                print("Installed IDA Pro plugin (IDA restart required)")
                for item in installed_items:
                    print(f"  {item}")
            else:
                print("Skipping IDA plugin installation (already up to date)")


def main():
    global WS_HOST, WS_PORT
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument(
        "--install", action="store_true", help="Install the MCP Server and IDA plugin"
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Uninstall the MCP Server and IDA plugin",
    )
    parser.add_argument(
        "--allow-ida-free",
        action="store_true",
        help="Allow installation despite IDA Free being installed",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)",
    )
    parser.add_argument(
        "--ws-port",
        type=int,
        default=WS_PORT,
        help=f"WebSocket server port for IDA connections (default: {WS_PORT})",
    )
    parser.add_argument(
        "--config", action="store_true", help="Generate MCP config JSON"
    )
    args = parser.parse_args()

    WS_PORT = args.ws_port

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers(stdio=(args.transport == "stdio"))
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True, allow_ida_free=args.allow_ida_free)
        install_mcp_servers(uninstall=True)
        return

    if args.config:
        print_mcp_config()
        return

    # Start WebSocket server for IDA instances to connect to
    start_ws_server(WS_HOST, WS_PORT)

    try:
        if args.transport == "stdio":
            mcp.stdio()
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            # NOTE: npx -y @modelcontextprotocol/inspector for debugging
            mcp.serve(url.hostname, url.port)
            input("Server is running, press Enter or Ctrl+C to stop.")
    except (KeyboardInterrupt, EOFError):
        pass


if __name__ == "__main__":
    main()
