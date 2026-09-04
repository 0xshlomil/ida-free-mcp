# IDA Free MCP

A native C++ plugin that brings AI into your IDA reverse engineering workflow.

It exposes IDA's analysis capabilities through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) — a standard interface that lets LLMs talk to tools. The plugin runs an HTTP server inside IDA's process, so your AI assistant can read disassembly, decompile functions, follow cross-references, rename variables, patch bytes, and more.

## Usage

1. Open a binary in IDA
2. **Edit > Plugins > MCP** (or **Ctrl+Alt+M**) to start the server
3. Connect your MCP client to `http://0.0.0.0:13337/mcp`
4. Press **Ctrl+Alt+M** again to stop

### Connecting an MCP client

```bash
# Claude Code
claude mcp add --transport http ida-mcp http://127.0.0.1:13337/mcp
```

For other clients (Claude Desktop, Cursor, Windsurf, etc.), add to your MCP config:

```json
{
  "mcpServers": {
    "ida-mcp": {
      "url": "http://127.0.0.1:13337/mcp"
    }
  }
}
```

### Multiple IDA instances

Multiple IDA sessions can run MCP simultaneously — the port auto-increments if already in use (up to 10 attempts). Each instance writes its port, PID, and IDB path to `~/.ida-mcp/instances/<pid>.json`. Stale files from crashed sessions are cleaned up automatically.

### Environment variables

| Variable | Description | Default |
|---|---|---|
| `IDA_MCP_PORT` | Base port for the HTTP server | `13337` |
| `IDA_MCP_TOOL_TIMEOUT_SEC` | Tool execution timeout in seconds | — |
| `IDA_MCP_URL` | Download base URL for large outputs | `http://127.0.0.1:<port>` |

## Requirements

- **CMake** 3.16+, **C++17** compiler (GCC, Clang, or MSVC)
- **IDA SDK** (for building the plugin; not needed for tests)
- **IDA Pro / IDA Free** 9.0+

## Building

### Quick start

```bash
# Linux / macOS
./build.sh

# Windows (Developer Command Prompt)
build.bat
```

Both scripts build tests, run them, build the plugin, and install it. Set `IDASDK` to override the SDK path (default: `idasdk/src` submodule).

### Manual build

```bash
# Tests only (no IDA SDK required)
cmake -S . -B build/tests -DBUILD_PLUGIN=OFF -DBUILD_TESTS=ON
cmake --build build/tests --config Release

# Plugin
cmake -S . -B build/plugin -DBUILD_PLUGIN=ON -DBUILD_TESTS=OFF -DIDASDK=/path/to/idasdk
cmake --build build/plugin --config Release
```

Copy the built plugin (`ida_mcp.so` / `.dll` / `.dylib`) to your IDA `plugins/` directory.

Pre-built binaries are available on the [releases page](https://github.com/0xshlomil/ida-free-mcp/releases).

## Architecture

```
IDA Plugin (plugin.cpp)
  └─ McpPlugmod
       ├─ McpProtocol (mcp.h)        ← Tool/resource registry, MCP methods
       │    └─ JsonRpcRegistry        ← JSON-RPC 2.0 dispatch
       └─ McpHttpServer (server.h)    ← HTTP routes, CORS, SSE
```

All IDA SDK calls are marshalled to IDA's main thread via `execute_sync(MFF_WRITE)` with timeout and cancellation support.

**Transports:** Streamable HTTP (`POST /mcp`) and SSE (`GET /sse`).

## Tools & Resources

**37 tools** organized into 7 groups. Every tool runs on IDA's main thread via `execute_sync` for thread safety.

| Group | Tools |
|---|---|
| **Core** | `int_convert`, `lookup_funcs`, `list_funcs`, `list_globals`, `imports`, `find_regex` |
| **Analysis** | `disasm`, `xrefs_to`, `xrefs_to_field`, `callees`, `callgraph`, `basic_blocks`, `find`, `find_bytes`, `export_funcs` |
| **Memory** | `get_bytes`, `get_string`, `get_int`, `get_global_value`, `patch`, `put_int` |
| **Modify** | `set_comments`, `rename`, `patch_asm`, `define_func`, `define_code`, `undefine` |
| **Types** | `declare_type`, `read_struct`, `search_structs`, `set_type` |
| **Stack** | `stack_frame`, `declare_stack`, `delete_stack` |
| **Decompiler** | `decompile`, `hexrays_diag`, `debug_mode` |

> **Note:** The `decompile` tool works on both IDA Pro and IDA Free. It uses GUI-based decompilation (triggers F5 and reads the pseudocode widget) — no Hex-Rays SDK initialization required. The `hexrays_diag` tool reports SDK status for diagnostics only; `init_hexrays_plugin: false` is expected on IDA Free and does not affect decompilation.

**11 MCP resources** for read access to IDA state: `ida://idb/metadata`, `ida://idb/segments`, `ida://idb/entrypoints`, `ida://cursor`, `ida://selection`, `ida://types`, `ida://structs`, `ida://struct/{name}`, `ida://import/{name}`, `ida://export/{name}`, `ida://xrefs/from/{addr}`.

## Dependencies

All vendored in `deps/` (header-only): [nlohmann/json](https://github.com/nlohmann/json), [cpp-httplib](https://github.com/yhirose/cpp-httplib), [doctest](https://github.com/doctest/doctest).

## License

See [LICENSE](LICENSE) file.
