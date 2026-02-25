# IDA Free MCP

A native C++ plugin that brings AI into your IDA reverse engineering workflow.

It exposes IDA's analysis capabilities through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) — a standard interface that lets LLMs talk to tools. The plugin spins up an HTTP server on `127.0.0.1:13337` right inside IDA's process, so your AI assistant can read disassembly, decompile functions, follow cross-references, rename variables, patch bytes, and much more — all without leaving your IDA session.

Think of it as giving your LLM a seat next to you at the disassembler.

## Features

### Tools

37 tools organized into 7 groups. Every tool runs on IDA's main thread (via `execute_sync`) so you never have to worry about thread safety.

#### Core

| Tool | What it does |
|---|---|
| `int_convert` | Convert numbers between hex, decimal, octal, and binary |
| `lookup_funcs` | Get functions by address or name (auto-detects which you meant) |
| `list_funcs` | List functions in the database |
| `list_globals` | List global variables |
| `imports` | List imported functions |
| `find_regex` | Search strings in the database by regex (case-insensitive) |

#### Analysis

| Tool | What it does |
|---|---|
| `disasm` | Disassemble a function to assembly instructions |
| `xrefs_to` | Get cross-references to specified addresses |
| `xrefs_to_field` | Get cross-references to a structure field |
| `callees` | Get functions called by a function |
| `callgraph` | Build a call graph from root functions |
| `basic_blocks` | Get control flow graph basic blocks for a function |
| `find` | Unified search — strings, immediates, data refs, code refs |
| `find_bytes` | Search for byte patterns with wildcards (e.g. `48 8B ? ?`) |
| `export_funcs` | Export function data in various formats |

#### Memory

| Tool | What it does |
|---|---|
| `get_bytes` | Read raw bytes from memory addresses |
| `get_string` | Read strings from memory addresses |
| `get_int` | Read integer values with type specification |
| `get_global_value` | Read global variable values by name or address |
| `patch` | Patch bytes in memory |
| `put_int` | Write integer values to memory |

#### Modify

| Tool | What it does |
|---|---|
| `set_comments` | Set comments at addresses (disassembly and decompiler views) |
| `rename` | Rename functions, globals, locals, and stack variables |
| `patch_asm` | Assemble and patch instructions at addresses |
| `define_func` | Define a function at an address |
| `define_code` | Convert bytes to code (create an instruction) |
| `undefine` | Undefine items back to raw bytes |

#### Types

| Tool | What it does |
|---|---|
| `declare_type` | Parse C type declarations and add them to the type library |
| `read_struct` | Read a structure definition, optionally with memory values |
| `search_structs` | Search structures by name (case-insensitive substring match) |
| `set_type` | Apply a type to a function, global, or stack variable |

#### Stack

| Tool | What it does |
|---|---|
| `stack_frame` | Get stack frame variables for a function |
| `declare_stack` | Create a stack variable in a function frame |
| `delete_stack` | Delete a stack variable from a function frame |

#### Decompiler

| Tool | What it does |
|---|---|
| `decompile` | Decompile a function to pseudocode (works in both IDA Pro and IDA Free) |
| `hexrays_diag` | Check Hex-Rays decompiler SDK status and loaded plugins |
| `debug_mode` | Toggle verbose debug logging to the IDA console |

### Resources

MCP resources give the LLM read access to IDA's database state without calling tools.

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

**Linux / macOS:**

```bash
# Set IDA SDK path (default: ../idasdk/src)
export IDASDK=/path/to/idasdk

# Build everything, run tests, and install
./build.sh
```

**Windows** (from a Developer Command Prompt or Developer PowerShell):

```bat
:: Set IDA SDK path (default: ..\idasdk\src)
set IDASDK=C:\path\to\idasdk

:: Build everything, run tests, and install
build.bat
```

### Manual build

**Tests only** (no IDA SDK required):

```bash
# Linux / macOS
cmake -S . -B build/tests -DBUILD_PLUGIN=OFF -DBUILD_TESTS=ON
cmake --build build/tests -j$(nproc)
./build/tests/ida_mcp_tests
```

```bat
:: Windows
cmake -S . -B build\tests -DBUILD_PLUGIN=OFF -DBUILD_TESTS=ON
cmake --build build\tests --config Release -j %NUMBER_OF_PROCESSORS%
build\tests\Release\ida_mcp_tests.exe
```

**Plugin only**:

```bash
# Linux / macOS
cmake -S . -B build/plugin -DBUILD_PLUGIN=ON -DBUILD_TESTS=OFF -DIDASDK=/path/to/idasdk
cmake --build build/plugin -j$(nproc)
```

```bat
:: Windows
cmake -S . -B build\plugin -DBUILD_PLUGIN=ON -DBUILD_TESTS=OFF -DIDASDK=C:\path\to\idasdk
cmake --build build\plugin --config Release -j %NUMBER_OF_PROCESSORS%
```

### Install

Copy the built plugin to your IDA plugins directory:

```bash
# Linux
cp build/plugin/ida_mcp.so ~/ida-free-9.3/plugins/

# macOS
cp build/plugin/ida_mcp.dylib ~/ida-free-9.3/plugins/
```

```bat
:: Windows
copy build\plugin\Release\ida_mcp.dll "%USERPROFILE%\ida-free-9.3\plugins\"
```

## Usage

1. Open a binary in IDA
2. Start the server: **Edit > Plugins > MCP** (or press **Ctrl+Alt+M**)
3. The MCP server starts on `http://127.0.0.1:13337`
4. Connect your MCP client to `http://127.0.0.1:13337/mcp`
5. Press **Ctrl+Alt+M** again to stop the server

### Connecting an MCP client

#### Claude Code

```bash
claude mcp add --transport http ida-mcp http://127.0.0.1:13337/mcp
```

#### Any MCP client (Claude Desktop, Cursor, Windsurf, etc.)

Add to your MCP config file — the location depends on your client:

| Client | Config file |
|---|---|
| Claude Code | `.mcp.json` in your project root |
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | `.cursor/mcp.json` in your project root |

The config is the same for all of them:

```json
{
  "mcpServers": {
    "ida-mcp": {
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
