# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IDA Free MCP is a C++17 IDA Pro plugin that exposes IDA's analysis capabilities via an MCP (Model Context Protocol) server over HTTP, enabling LLMs to perform reverse engineering tasks. It runs an HTTP server on `127.0.0.1:13337` inside IDA's process.

## Build Commands

```bash
# Build tests only (no IDA SDK required)
cmake -S . -B build/tests -DBUILD_PLUGIN=OFF -DBUILD_TESTS=ON
cmake --build build/tests -j$(nproc)

# Run tests
./build/tests/ida_mcp_tests
# Or via ctest:
cd build/tests && ctest --output-on-failure

# Build plugin (requires IDA SDK path)
cmake -S . -B build/plugin -DBUILD_PLUGIN=ON -DBUILD_TESTS=OFF -DIDASDK=../idasdk/src
cmake --build build/plugin -j$(nproc)

# Install plugin to IDA
cp build/plugin/ida_mcp.so ~/.ida-free-pc-9.2/plugins/
```

The convenience script `build.sh` wraps these steps.

## Architecture

**Protocol stack** (bottom to top):
```
JSON-RPC 2.0 (jsonrpc.h)  →  MCP Protocol (mcp.h)  →  HTTP Server (server.h)
```

**Plugin lifecycle**: `plugin.cpp` defines `McpPlugmod` which creates `McpProtocol`, registers all tools and resources, then starts `McpHttpServer`. Toggled via Ctrl+Alt+M in IDA.

**Thread synchronization** (`sync.h`): All IDA SDK calls must run on the main thread. `execute_on_main_thread()` uses IDA's `execute_sync(MFF_WRITE)` with timeout and cancellation support. Tool handlers are wrapped with `ida_sync_tool()` to enforce this.

**Tool groups** (each in `src/tools/`): core, analysis, memory, modify, types, stack. Each file exports a `register_*_tools(McpProtocol&)` function called from `plugin.cpp`.

**Resources** (`src/resources/`): MCP resources like `ida://idb/metadata` and `ida://functions/{pattern}`.

**Output limiting**: Large outputs are cached in-memory and served via `/download/{id}` instead of inline. Configurable max chars (50K default).

## Key Design Constraints

- **`ida_pre.h` must be included before IDA headers**: It wraps `<ida.hpp>` and `#undef`s dangerous macros (`snprintf`, `getenv`, etc.) that IDA's `pro.h` redefines. This allows third-party headers (json, httplib) to compile. In plugin code, use IDA-prefixed functions (`qsnprintf`, `qgetenv`) instead.

- **`IDA_MCP_TESTING` define**: When set, IDA SDK includes are disabled so tests compile standalone. Tests only cover non-IDA code (jsonrpc, utils).

- **All dependencies are vendored** in `deps/`: nlohmann/json (`json.hpp`), cpp-httplib (`httplib.h`), doctest (`doctest.h`). No package manager.

## Namespaces

`mcp` (protocol/tools), `server` (HTTP), `jsonrpc` (JSON-RPC), `idasync` (thread sync), `utils` (utilities)

## Environment Variables

- `IDA_MCP_TOOL_TIMEOUT_SEC`: Tool execution timeout (default varies)
- `IDA_MCP_URL`: Download base URL (default `http://127.0.0.1:13337`)

## HTTP Routes

- `POST /mcp` — JSON-RPC dispatch
- `GET /download/{id}` — Cached large outputs
- `GET /events` — SSE stream
- `GET /health` — Health check
