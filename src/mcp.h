#pragma once

#include "jsonrpc.h"

#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

using json = nlohmann::json;

namespace mcp {

// ═══════════════════════════════════════════════════════════════════
// Tool Schema
// ═══════════════════════════════════════════════════════════════════

struct ToolSchema {
    std::string name;
    std::string description;
    json input_schema;   // JSON Schema object for parameters
    json output_schema;  // JSON Schema object for return type (optional)
};

/// Helper for building JSON Schema objects.
class SchemaBuilder {
public:
    SchemaBuilder() : schema_({{"type", "object"}, {"properties", json::object()}, {"required", json::array()}}) {}

    SchemaBuilder& string_prop(const std::string& name, const std::string& desc, bool required = true) {
        schema_["properties"][name] = {{"type", "string"}, {"description", desc}};
        if (required) schema_["required"].push_back(name);
        return *this;
    }

    SchemaBuilder& int_prop(const std::string& name, const std::string& desc, bool required = true) {
        schema_["properties"][name] = {{"type", "integer"}, {"description", desc}};
        if (required) schema_["required"].push_back(name);
        return *this;
    }

    SchemaBuilder& bool_prop(const std::string& name, const std::string& desc, bool required = false) {
        schema_["properties"][name] = {{"type", "boolean"}, {"description", desc}};
        if (required) schema_["required"].push_back(name);
        return *this;
    }

    SchemaBuilder& prop(const std::string& name, const json& schema, bool required = true) {
        schema_["properties"][name] = schema;
        if (required) schema_["required"].push_back(name);
        return *this;
    }

    json build() const { return schema_; }

private:
    json schema_;
};

// ═══════════════════════════════════════════════════════════════════
// Resource Definition
// ═══════════════════════════════════════════════════════════════════

/// Handler: takes URI match params as a list of strings, returns JSON result.
using ResourceHandler = std::function<json(const std::vector<std::string>& params)>;

struct ResourceDef {
    std::string uri_pattern;     // e.g. "ida://idb/metadata" or "ida://functions/{pattern}"
    std::string name;
    std::string description;
    ResourceHandler handler;
    bool is_template;            // true if uri_pattern contains {param}
};

// ═══════════════════════════════════════════════════════════════════
// Output Limiting
// ═══════════════════════════════════════════════════════════════════

constexpr size_t OUTPUT_LIMIT_MAX_CHARS = 50000;
constexpr size_t OUTPUT_CACHE_MAX_SIZE = 100;
constexpr size_t OUTPUT_LIMIT_PREVIEW_ITEMS = 10;
constexpr size_t OUTPUT_LIMIT_PREVIEW_STR_LEN = 1000;

// ═══════════════════════════════════════════════════════════════════
// MCP Protocol
// ═══════════════════════════════════════════════════════════════════

/// Tool handler: takes arguments dict, returns result json.
using ToolHandler = std::function<json(const json& arguments)>;

class McpProtocol {
public:
    McpProtocol(const std::string& name, const std::string& version = "1.0.0");

    /// Register a tool.
    void register_tool(const ToolSchema& schema, ToolHandler handler);

    /// Register a resource.
    void register_resource(const ResourceDef& def);

    /// Get the JSON-RPC registry (for wiring into server).
    jsonrpc::JsonRpcRegistry& registry() { return registry_; }

    /// Set the download base URL for output limiting.
    void set_download_base_url(const std::string& url);
    const std::string& get_download_base_url() const { return download_base_url_; }

    /// Get cached output by ID.
    json get_cached_output(const std::string& output_id) const;

    /// Set enabled extensions for the current request.
    void set_enabled_extensions(const std::set<std::string>& exts);

    /// Set protocol version for the current request.
    void set_protocol_version(const std::string& version);

private:
    std::string name_;
    std::string version_;
    std::string download_base_url_ = "http://127.0.0.1:13337"; // Overridden by plugin with actual port
    std::string protocol_version_ = "2025-06-18";

    // Tool management
    struct ToolEntry {
        ToolSchema schema;
        ToolHandler handler;
        std::string extension_group; // empty = no extension required
    };
    std::vector<ToolEntry> tools_;

    // Resource management
    std::vector<ResourceDef> resources_;

    // Extension groups
    std::set<std::string> enabled_extensions_;

    // Output cache
    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, json> output_cache_;

    // Internal JSON-RPC registry
    jsonrpc::JsonRpcRegistry registry_;

    // MCP protocol methods
    json mcp_ping(const json& params);
    json mcp_initialize(const json& params);
    json mcp_tools_list(const json& params);
    json mcp_tools_call(const json& params);
    json mcp_resources_list(const json& params);
    json mcp_resource_templates_list(const json& params);
    json mcp_resources_read(const json& params);
    json mcp_notifications_cancelled(const json& params);

    // Output limiting helpers
    json truncate_value(const json& value, int depth = 0);
    json add_download_info(const json& result, const std::string& output_id,
                           size_t total_chars);
    void cache_output(const std::string& output_id, const json& data);
    std::string generate_output_id();
};

} // namespace mcp
