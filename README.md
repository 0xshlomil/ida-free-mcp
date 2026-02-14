# IDA Free MCP

A native C++ IDA Pro plugin that exposes IDA's reverse engineering capabilities through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), enabling LLMs to analyze binaries directly inside IDA.

The plugin runs an HTTP server on `127.0.0.1:13337` within IDA's process, giving AI assistants access to disassembly, decompilation, cross-references, type information, memory, and more — all through a standard MCP interface.

## Features

### Tools (32 total)

**Core** — `int_convert`, `lookup_funcs`, `list_funcs`, `list_globals`, `imports`, `find_regex`

**Analysis** — `disasm`, `xrefs_to`, `callees`, `find_bytes`, `basic_blocks`, `find`, `export_funcs`, `callgraph`, `xrefs_to_field`

**Memory** — `get_bytes`, `get_string`, `get_int`, `get_global_value`, `patch`, `put_int`

**Modify** — `set_comments`, `rename`, `patch_asm`, `define_func`, `define_code`, `undefine`

**Types** — `declare_type`, `read_struct`, `search_structs`, `set_type`

**Stack** — `stack_frame`, `declare_stack`, `delete_stack`

### Resources

| Resource | Description |
|---|---|
| `ida://idb/metadata` | IDB file metadata (path, arch, base address, size, hashes) |
| `ida://idb/segments` | All memory segments with permissions |
| `ida://idb/entrypoints` | All entry points (exports) of the binary |
| `ida://cursor` | Current cursor position and function |
| `ida://selection` | Current selection range |
| `ida://types` | All types in the type library |
| `ida://structs` | All structures/unions in the type library |
| `ida://struct/{name}` | Structure definition by name |
| `ida://import/{name}` | Find import by name |
| `ida://export/{name}` | Find export by name |
| `ida://xrefs/from/{addr}` | Cross-references from an address |

### Transports

- **Streamable HTTP** — `POST /mcp` (MCP protocol version `2025-06-18`)
- **SSE** — `GET /sse` (MCP protocol version `2024-11-05`)

## Requirements

- **CMake** 3.16+
- **C++17** compiler (GCC, Clang, or MSVC)
- **IDA SDK** (for building the plugin; not needed for tests)
- **IDA Pro / IDA Free** 9.0+ (for running the plugin)

## Building

### Quick start

```bash
# Set IDA SDK path (default: ../idasdk/src)
export IDASDK=/path/to/idasdk

# Build everything, run tests, and install
./build.sh
```

### Manual build

**Tests only** (no IDA SDK required):

```bash
cmake -S . -B build/tests -DBUILD_PLUGIN=OFF -DBUILD_TESTS=ON
cmake --build build/tests -j$(nproc)
./build/tests/ida_mcp_tests
```

**Plugin only**:

```bash
cmake -S . -B build/plugin -DBUILD_PLUGIN=ON -DBUILD_TESTS=OFF -DIDASDK=/path/to/idasdk
cmake --build build/plugin -j$(nproc)
```

### Install

Copy the built plugin to your IDA plugins directory:

```bash
# Linux
cp build/plugin/ida_mcp.so ~/ida-free-pc-9.2/plugins/

# macOS
cp build/plugin/ida_mcp.dylib ~/ida-free-pc-9.2/plugins/

# Windows
copy build\plugin\ida_mcp.dll "%APPDATA%\Hex-Rays\IDA Pro\plugins\"
```

## Usage

1. Open a binary in IDA
2. Start the server: **Edit > Plugins > MCP** (or press **Ctrl+Alt+M**)
3. The MCP server starts on `http://127.0.0.1:13337`
4. Connect your MCP client to `http://127.0.0.1:13337/mcp`
5. Press **Ctrl+Alt+M** again to stop the server

### Client configuration

Add to your MCP client config (e.g. Claude Desktop, Claude Code):

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "url": "http://127.0.0.1:13337/mcp"
    }
  }
}
```

### Environment variables

| Variable | Description | Default |
|---|---|---|
| `IDA_MCP_TOOL_TIMEOUT_SEC` | Tool execution timeout in seconds | — |
| `IDA_MCP_URL` | Download base URL for large outputs | `http://127.0.0.1:13337` |

## Architecture

```
IDA Plugin (plugin.cpp)
  └─ McpPlugmod
       ├─ McpProtocol (mcp.h)        ← Tool/resource registry, MCP methods
       │    └─ JsonRpcRegistry        ← JSON-RPC 2.0 dispatch
       └─ McpHttpServer (server.h)    ← HTTP routes, CORS, SSE
            └─ POST /mcp             ← Main MCP endpoint
```

All IDA SDK calls are marshalled to IDA's main thread via `execute_on_main_thread()` (sync.h), which uses `execute_sync(MFF_WRITE)` with timeout and cancellation support. Tool handlers are wrapped with `ida_sync_tool()` to enforce this automatically.

Large tool outputs are automatically truncated with a preview and cached in-memory. The full output is available via `GET /output/{id}.json`.

## Dependencies

All dependencies are vendored in `deps/` (header-only, zero external packages):

- [nlohmann/json](https://github.com/nlohmann/json) — JSON parsing
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) — HTTP server
- [doctest](https://github.com/doctest/doctest) — Unit testing

## License

See [LICENSE](LICENSE) file.
