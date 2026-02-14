#pragma once

#include <nlohmann/json.hpp>

#include <atomic>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

using json = nlohmann::json;

// ═══════════════════════════════════════════════════════════════════
// JSON-RPC 2.0 Error Codes
// ═══════════════════════════════════════════════════════════════════

namespace jsonrpc {

constexpr int PARSE_ERROR      = -32700;
constexpr int INVALID_REQUEST  = -32600;
constexpr int METHOD_NOT_FOUND = -32601;
constexpr int INVALID_PARAMS   = -32602;
constexpr int INTERNAL_ERROR   = -32603;
constexpr int REQUEST_CANCELLED = -32800;
constexpr int MCP_TOOL_ERROR   = -32000;

// ═══════════════════════════════════════════════════════════════════
// Exceptions
// ═══════════════════════════════════════════════════════════════════

class JsonRpcException : public std::exception {
public:
    int code;
    std::string message;
    json data;

    JsonRpcException(int code, std::string message, json data = nullptr)
        : code(code), message(std::move(message)), data(std::move(data)) {}

    const char* what() const noexcept override { return message.c_str(); }
};

class RequestCancelledError : public std::exception {
public:
    std::string message;
    explicit RequestCancelledError(std::string msg = "Request cancelled")
        : message(std::move(msg)) {}
    const char* what() const noexcept override { return message.c_str(); }
};

// ═══════════════════════════════════════════════════════════════════
// Cancellation Tracking
// ═══════════════════════════════════════════════════════════════════

/// Register a pending request for cancellation tracking.
/// Returns a shared cancel flag (set to true when cancelled).
std::shared_ptr<std::atomic<bool>> register_pending_request(const json& request_id);

/// Unregister a pending request.
void unregister_pending_request(const json& request_id);

/// Signal cancellation for a pending request. Returns true if found.
bool cancel_request(const json& request_id);

// ═══════════════════════════════════════════════════════════════════
// JSON-RPC Registry
// ═══════════════════════════════════════════════════════════════════

/// Method handler: takes params (json), returns result (json).
using RpcMethod = std::function<json(const json& params)>;

class JsonRpcRegistry {
public:
    /// Register a named method.
    void register_method(const std::string& name, RpcMethod handler);

    /// Dispatch a raw JSON-RPC request (bytes or string).
    /// Returns the response JSON, or std::nullopt for notifications.
    std::optional<json> dispatch(const std::string& request_str);

    /// Dispatch a raw C-string request.
    std::optional<json> dispatch(const char* request_str) {
        return dispatch(std::string(request_str));
    }

    /// Dispatch a pre-parsed JSON-RPC request.
    std::optional<json> dispatch_parsed(const json& request);

    /// Check if a method exists.
    bool has_method(const std::string& name) const;

    /// Map an exception to a JSON-RPC error response.
    virtual json map_exception(const std::exception& e);

private:
    std::unordered_map<std::string, RpcMethod> methods_;

    json make_error(const json& id, int code, const std::string& message,
                    const json& data = nullptr);
    json make_result(const json& id, const json& result);
    json call(const std::string& method, const json& params);
};

} // namespace jsonrpc
