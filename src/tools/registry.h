#pragma once

#include "../mcp.h"
#include "../sync.h"
#include "../jsonrpc.h"

#include <functional>

/// Wrap a tool handler to execute on IDA's main thread.
/// The inner handler receives (const json& arguments) and returns json.
inline mcp::ToolHandler ida_sync_tool(
    std::function<json(const json&)> handler,
    double timeout_sec = -1.0) {

    return [handler = std::move(handler), timeout_sec](const json& arguments) -> json {
        return idasync::execute_on_main_thread(
            [&handler, &arguments]() -> json {
                return handler(arguments);
            },
            nullptr, // cancel_flag (TODO: wire from request context)
            timeout_sec
        );
    };
}

/// Registration functions for each tool group.
void register_core_tools(mcp::McpProtocol& mcp);
void register_analysis_tools(mcp::McpProtocol& mcp);
void register_memory_tools(mcp::McpProtocol& mcp);
void register_modify_tools(mcp::McpProtocol& mcp);
void register_type_tools(mcp::McpProtocol& mcp);
void register_stack_tools(mcp::McpProtocol& mcp);
void register_decompiler_tools(mcp::McpProtocol& mcp);
