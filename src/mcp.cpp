#include "mcp.h"

#include <algorithm>
#include <random>
#include <regex>
#include <sstream>

namespace mcp {

// ═══════════════════════════════════════════════════════════════════
// UUID generation (simple v4)
// ═══════════════════════════════════════════════════════════════════

static std::string uuid_v4() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<int> dist(0, 15);

    const char hex[] = "0123456789abcdef";
    std::string uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    for (auto& c : uuid) {
        if (c == 'x') {
            c = hex[dist(gen)];
        } else if (c == 'y') {
            c = hex[(dist(gen) & 0x3) | 0x8];
        }
    }
    return uuid;
}

// ═══════════════════════════════════════════════════════════════════
// McpProtocol
// ═══════════════════════════════════════════════════════════════════

McpProtocol::McpProtocol(const std::string& name, const std::string& version)
    : name_(name), version_(version) {

    const char* env_url = std::getenv("IDA_MCP_URL");
    if (env_url) download_base_url_ = env_url;

    // Register MCP protocol methods
    registry_.register_method("ping",
        [this](const json& p) { return mcp_ping(p); });
    registry_.register_method("initialize",
        [this](const json& p) { return mcp_initialize(p); });
    registry_.register_method("tools/list",
        [this](const json& p) { return mcp_tools_list(p); });
    registry_.register_method("tools/call",
        [this](const json& p) { return mcp_tools_call(p); });
    registry_.register_method("resources/list",
        [this](const json& p) { return mcp_resources_list(p); });
    registry_.register_method("resources/templates/list",
        [this](const json& p) { return mcp_resource_templates_list(p); });
    registry_.register_method("resources/read",
        [this](const json& p) { return mcp_resources_read(p); });
    registry_.register_method("notifications/cancelled",
        [this](const json& p) { return mcp_notifications_cancelled(p); });
    registry_.register_method("notifications/initialized",
        [](const json&) { return json::object(); });
}

void McpProtocol::register_tool(const ToolSchema& schema, ToolHandler handler) {
    tools_.push_back({schema, std::move(handler), ""});
}

void McpProtocol::register_resource(const ResourceDef& def) {
    resources_.push_back(def);
}

void McpProtocol::set_download_base_url(const std::string& url) {
    download_base_url_ = url;
    // Remove trailing slash
    while (!download_base_url_.empty() && download_base_url_.back() == '/') {
        download_base_url_.pop_back();
    }
}

json McpProtocol::get_cached_output(const std::string& output_id) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = output_cache_.find(output_id);
    if (it != output_cache_.end()) return it->second;
    return nullptr;
}

void McpProtocol::set_enabled_extensions(const std::set<std::string>& exts) {
    enabled_extensions_ = exts;
}

void McpProtocol::set_protocol_version(const std::string& version) {
    protocol_version_ = version;
}

// ═══════════════════════════════════════════════════════════════════
// MCP Protocol Methods
// ═══════════════════════════════════════════════════════════════════

json McpProtocol::mcp_ping(const json&) {
    return json::object();
}

json McpProtocol::mcp_initialize(const json& params) {
    return {
        {"protocolVersion", protocol_version_},
        {"capabilities", {
            {"tools", json::object()},
            {"resources", {
                {"subscribe", false},
                {"listChanged", false},
            }},
            {"prompts", json::object()},
        }},
        {"serverInfo", {
            {"name", name_},
            {"version", version_},
        }},
    };
}

json McpProtocol::mcp_tools_list(const json&) {
    json tools = json::array();
    for (const auto& entry : tools_) {
        // Check extension group
        if (!entry.extension_group.empty() &&
            enabled_extensions_.count(entry.extension_group) == 0) {
            continue;
        }

        json tool = {
            {"name", entry.schema.name},
            {"description", entry.schema.description},
            {"inputSchema", entry.schema.input_schema},
        };
        if (!entry.schema.output_schema.is_null()) {
            tool["outputSchema"] = entry.schema.output_schema;
        }
        tools.push_back(tool);
    }
    return {{"tools", tools}};
}

json McpProtocol::mcp_tools_call(const json& params) {
    std::string name = params.value("name", "");
    json arguments = params.value("arguments", json::object());

    // Find the tool
    ToolEntry* found = nullptr;
    for (auto& entry : tools_) {
        if (entry.schema.name == name) {
            found = &entry;
            break;
        }
    }

    if (!found) {
        return {
            {"content", json::array({{{"type", "text"}, {"text", "Tool '" + name + "' not found"}}})},
            {"isError", true},
        };
    }

    // Check extension
    if (!found->extension_group.empty() &&
        enabled_extensions_.count(found->extension_group) == 0) {
        return {
            {"content", json::array({{{"type", "text"},
                {"text", "Tool '" + name + "' requires extension '" +
                         found->extension_group + "'. Enable with ?ext=" +
                         found->extension_group}}})},
            {"isError", true},
        };
    }

    // Register for cancellation tracking
    // (Use the outer request ID from the JSON-RPC layer)

    try {
        json result = found->handler(arguments);

        // Build MCP response
        json structured = result.is_object() ? result : json{{"result", result}};
        std::string text_content = result.dump(2);

        // Apply output limiting
        std::string serialized = structured.dump();
        if (serialized.size() > OUTPUT_LIMIT_MAX_CHARS) {
            std::string output_id = generate_output_id();
            cache_output(output_id, structured);
            json preview = truncate_value(structured);
            preview = add_download_info(preview, output_id, serialized.size());

            return {
                {"content", json::array({{{"type", "text"}, {"text", text_content}}})},
                {"structuredContent", preview},
                {"isError", false},
            };
        }

        return {
            {"content", json::array({{{"type", "text"}, {"text", text_content}}})},
            {"structuredContent", structured},
            {"isError", false},
        };

    } catch (const std::exception& e) {
        return {
            {"content", json::array({{{"type", "text"}, {"text", e.what()}}})},
            {"isError", true},
        };
    }
}

json McpProtocol::mcp_resources_list(const json&) {
    json resources = json::array();
    for (const auto& def : resources_) {
        if (def.is_template) continue; // Only static resources

        resources.push_back({
            {"uri", def.uri_pattern},
            {"name", def.name},
            {"description", def.description},
            {"mimeType", "application/json"},
        });
    }
    return {{"resources", resources}};
}

json McpProtocol::mcp_resource_templates_list(const json&) {
    json templates = json::array();
    for (const auto& def : resources_) {
        if (!def.is_template) continue;

        templates.push_back({
            {"uriTemplate", def.uri_pattern},
            {"name", def.name},
            {"description", def.description},
            {"mimeType", "application/json"},
        });
    }
    return {{"resourceTemplates", templates}};
}

json McpProtocol::mcp_resources_read(const json& params) {
    std::string uri = params.value("uri", "");

    for (const auto& def : resources_) {
        // Convert URI pattern to regex
        std::string pattern = def.uri_pattern;
        // Escape regex special chars except { }
        std::string regex_str;
        bool in_param = false;
        std::vector<std::string> param_names;
        for (size_t i = 0; i < pattern.size(); ++i) {
            char c = pattern[i];
            if (c == '{') {
                in_param = true;
                regex_str += "([^/]+)";
                std::string pname;
                ++i;
                while (i < pattern.size() && pattern[i] != '}') {
                    pname += pattern[i++];
                }
                param_names.push_back(pname);
            } else if (c == '.' || c == '+' || c == '(' || c == ')' ||
                       c == '[' || c == ']' || c == '\\' || c == '^' ||
                       c == '$' || c == '|') {
                regex_str += '\\';
                regex_str += c;
            } else {
                regex_str += c;
            }
        }
        regex_str = "^" + regex_str + "$";

        try {
            std::regex re(regex_str);
            std::smatch match;
            if (std::regex_match(uri, match, re)) {
                // Extract params
                std::vector<std::string> uri_params;
                for (size_t i = 1; i < match.size(); ++i) {
                    uri_params.push_back(match[i].str());
                }

                try {
                    json result = def.handler(uri_params);
                    return {
                        {"contents", json::array({{
                            {"uri", uri},
                            {"mimeType", "application/json"},
                            {"text", result.dump(2)},
                        }})},
                    };
                } catch (const std::exception& e) {
                    return {
                        {"contents", json::array({{
                            {"uri", uri},
                            {"mimeType", "application/json"},
                            {"text", json({{"error", e.what()}}).dump(2)},
                        }})},
                        {"isError", true},
                    };
                }
            }
        } catch (...) {}
    }

    // Not found
    json available = json::array();
    for (const auto& def : resources_) {
        available.push_back(def.uri_pattern);
    }
    return {
        {"contents", json::array({{
            {"uri", uri},
            {"mimeType", "application/json"},
            {"text", json({
                {"error", "Resource not found: " + uri},
                {"available_patterns", available},
            }).dump(2)},
        }})},
        {"isError", true},
    };
}

json McpProtocol::mcp_notifications_cancelled(const json& params) {
    json request_id = params.value("requestId", json());
    if (!request_id.is_null()) {
        jsonrpc::cancel_request(request_id);
    }
    return nullptr; // Notifications return null
}

// ═══════════════════════════════════════════════════════════════════
// Output Limiting
// ═══════════════════════════════════════════════════════════════════

json McpProtocol::truncate_value(const json& value, int depth) {
    if (depth > 5) return value;

    if (value.is_string()) {
        std::string s = value.get<std::string>();
        if (s.size() > OUTPUT_LIMIT_PREVIEW_STR_LEN) {
            return s.substr(0, OUTPUT_LIMIT_PREVIEW_STR_LEN) +
                   "... [" + std::to_string(s.size()) + " chars total]";
        }
        return value;
    }

    if (value.is_array()) {
        json result = json::array();
        size_t limit = std::min(value.size(), OUTPUT_LIMIT_PREVIEW_ITEMS);
        for (size_t i = 0; i < limit; ++i) {
            result.push_back(truncate_value(value[i], depth + 1));
        }
        if (value.size() > OUTPUT_LIMIT_PREVIEW_ITEMS) {
            result.push_back({{"_truncated",
                "... and " + std::to_string(value.size() - OUTPUT_LIMIT_PREVIEW_ITEMS) +
                " more items"}});
        }
        return result;
    }

    if (value.is_object()) {
        json result = json::object();
        for (auto& [k, v] : value.items()) {
            result[k] = truncate_value(v, depth + 1);
        }
        return result;
    }

    return value;
}

json McpProtocol::add_download_info(const json& result,
                                     const std::string& output_id,
                                     size_t total_chars) {
    std::string download_url = download_base_url_ + "/output/" + output_id + ".json";
    json info = {
        {"_output_truncated", true},
        {"_total_chars", total_chars},
        {"_output_id", output_id},
        {"_download_url", download_url},
        {"_download_hint", "Output truncated. Run: curl -o .ida-mcp/" +
                           output_id + ".json " + download_url},
    };

    if (result.is_object()) {
        json merged = result;
        merged.merge_patch(info);
        return merged;
    }
    if (result.is_array() && !result.empty()) {
        json arr = result;
        if (arr[0].is_object()) {
            arr[0].merge_patch(info);
        } else {
            arr.insert(arr.begin(), info);
        }
        return arr;
    }

    json wrapped = {{"_preview", result}};
    wrapped.merge_patch(info);
    return wrapped;
}

void McpProtocol::cache_output(const std::string& output_id, const json& data) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    if (output_cache_.size() >= OUTPUT_CACHE_MAX_SIZE) {
        // Evict oldest entry
        output_cache_.erase(output_cache_.begin());
    }
    output_cache_[output_id] = data;
}

std::string McpProtocol::generate_output_id() {
    return uuid_v4();
}

} // namespace mcp
