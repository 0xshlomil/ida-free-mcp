#ifndef IDA_MCP_TESTING
#include "ida_pre.h"
#include <kernwin.hpp>
#endif

#include "jsonrpc.h"

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <sstream>

namespace jsonrpc {

// ═══════════════════════════════════════════════════════════════════
// Cancellation Tracking
// ═══════════════════════════════════════════════════════════════════

static std::mutex g_pending_lock;
static std::unordered_map<std::string, std::shared_ptr<std::atomic<bool>>> g_pending;

static std::string id_to_key(const json& id) {
    if (id.is_string()) return id.get<std::string>();
    if (id.is_number_integer()) return std::to_string(id.get<int64_t>());
    if (id.is_number_float()) return std::to_string(id.get<double>());
    return id.dump();
}

std::shared_ptr<std::atomic<bool>> register_pending_request(const json& request_id) {
    auto flag = std::make_shared<std::atomic<bool>>(false);
    std::lock_guard<std::mutex> lock(g_pending_lock);
    g_pending[id_to_key(request_id)] = flag;
    return flag;
}

void unregister_pending_request(const json& request_id) {
    std::lock_guard<std::mutex> lock(g_pending_lock);
    g_pending.erase(id_to_key(request_id));
}

bool cancel_request(const json& request_id) {
    std::lock_guard<std::mutex> lock(g_pending_lock);
    auto it = g_pending.find(id_to_key(request_id));
    if (it != g_pending.end()) {
        it->second->store(true);
        return true;
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════
// Logging Configuration
// ═══════════════════════════════════════════════════════════════════

static bool parse_bool_env(const char* name, bool default_val) {
    const char* val = std::getenv(name);
    if (!val) return default_val;
    std::string s(val);
    if (s == "1" || s == "true" || s == "yes" || s == "on") return true;
    if (s == "0" || s == "false" || s == "no" || s == "off") return false;
    return default_val;
}

static bool g_log_requests = parse_bool_env("IDA_MCP_LOG_REQUESTS", true);

static std::set<std::string> parse_skip_methods() {
    std::set<std::string> result;
    const char* val = std::getenv("IDA_MCP_LOG_SKIP_METHODS");
    std::string s = val ? val : "tools/call";
    std::istringstream iss(s);
    std::string token;
    while (std::getline(iss, token, ',')) {
        // trim
        auto start = token.find_first_not_of(" \t");
        auto end = token.find_last_not_of(" \t");
        if (start != std::string::npos)
            result.insert(token.substr(start, end - start + 1));
    }
    return result;
}

static std::set<std::string> g_log_skip = parse_skip_methods();

static std::string truncate_str(const std::string& s, size_t max_len = 200) {
    if (s.size() <= max_len) return s;
    return s.substr(0, max_len) + "...";
}

// ═══════════════════════════════════════════════════════════════════
// Logging helper - uses msg() in IDA, printf in tests
// ═══════════════════════════════════════════════════════════════════

#ifdef IDA_MCP_TESTING
static void log_msg(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}
#else
static void log_msg(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vmsg(fmt, args);
    va_end(args);
}
#endif

// ═══════════════════════════════════════════════════════════════════
// JsonRpcRegistry
// ═══════════════════════════════════════════════════════════════════

void JsonRpcRegistry::register_method(const std::string& name, RpcMethod handler) {
    methods_[name] = std::move(handler);
}

bool JsonRpcRegistry::has_method(const std::string& name) const {
    return methods_.count(name) > 0;
}

std::optional<json> JsonRpcRegistry::dispatch(const std::string& request_str) {
    json request;
    try {
        request = json::parse(request_str);
    } catch (const json::parse_error& e) {
        return make_error(nullptr, PARSE_ERROR, "JSON parse error", e.what());
    }
    return dispatch_parsed(request);
}

std::optional<json> JsonRpcRegistry::dispatch_parsed(const json& request) {
    // Validate JSON object
    if (!request.is_object()) {
        return make_error(nullptr, INVALID_REQUEST,
                          "Invalid request: must be a JSON object");
    }

    // Validate jsonrpc version
    auto it_ver = request.find("jsonrpc");
    if (it_ver == request.end() || !it_ver->is_string() ||
        it_ver->get<std::string>() != "2.0") {
        return make_error(nullptr, INVALID_REQUEST,
                          "Invalid request: 'jsonrpc' must be '2.0'");
    }

    // Validate method
    auto it_method = request.find("method");
    if (it_method == request.end()) {
        return make_error(nullptr, INVALID_REQUEST,
                          "Invalid request: 'method' is required");
    }
    if (!it_method->is_string()) {
        return make_error(nullptr, INVALID_REQUEST,
                          "Invalid request: 'method' must be a string");
    }
    std::string method = it_method->get<std::string>();

    // Extract ID and notification flag
    json request_id = nullptr;
    bool is_notification = true;
    auto it_id = request.find("id");
    if (it_id != request.end()) {
        request_id = *it_id;
        is_notification = false;
    }

    // Extract params
    json params = nullptr;
    auto it_params = request.find("params");
    if (it_params != request.end()) {
        params = *it_params;
    }

    bool should_log = g_log_requests && g_log_skip.count(method) == 0;
    if (should_log) {
        std::string params_str = params.is_null() ? "null" : params.dump();
        log_msg("[MCP] >> %s(%s)\n", method.c_str(),
                truncate_str(params_str).c_str());
    }

    auto start = std::chrono::steady_clock::now();

    try {
        json result = call(method, params);

        if (should_log) {
            auto elapsed = std::chrono::steady_clock::now() - start;
            double ms = std::chrono::duration<double, std::milli>(elapsed).count();
            std::string result_str = result.dump();
            log_msg("[MCP] << %s (%.1fms) %s\n", method.c_str(), ms,
                    truncate_str(result_str).c_str());
        }

        if (is_notification) return std::nullopt;
        return make_result(request_id, result);

    } catch (const JsonRpcException& e) {
        if (should_log) {
            auto elapsed = std::chrono::steady_clock::now() - start;
            double ms = std::chrono::duration<double, std::milli>(elapsed).count();
            log_msg("[MCP] << %s (%.1fms) ERROR: %s\n", method.c_str(), ms,
                    e.message.c_str());
        }
        if (is_notification) return std::nullopt;
        json error_response = make_error(request_id, e.code, e.message);
        if (!e.data.is_null()) {
            error_response["error"]["data"] = e.data;
        }
        return error_response;

    } catch (const RequestCancelledError& e) {
        if (should_log) {
            auto elapsed = std::chrono::steady_clock::now() - start;
            double ms = std::chrono::duration<double, std::milli>(elapsed).count();
            log_msg("[MCP] << %s (%.1fms) CANCELLED\n", method.c_str(), ms);
        }
        if (is_notification) return std::nullopt;
        std::string cancel_msg = e.message.empty() ? "Request cancelled" : e.message;
        return make_error(request_id, REQUEST_CANCELLED, cancel_msg);

    } catch (const std::exception& e) {
        if (should_log) {
            auto elapsed = std::chrono::steady_clock::now() - start;
            double ms = std::chrono::duration<double, std::milli>(elapsed).count();
            log_msg("[MCP] << %s (%.1fms) EXCEPTION: %s\n", method.c_str(), ms,
                    e.what());
        }
        if (is_notification) return std::nullopt;
        json error = map_exception(e);
        return make_error(request_id, error["code"].get<int>(),
                          error["message"].get<std::string>(),
                          error.contains("data") ? error["data"] : nullptr);
    }
}

json JsonRpcRegistry::map_exception(const std::exception& e) {
    return {
        {"code", INTERNAL_ERROR},
        {"message", std::string("Internal Error: ") + e.what()},
    };
}

json JsonRpcRegistry::call(const std::string& method, const json& params) {
    auto it = methods_.find(method);
    if (it == methods_.end()) {
        throw JsonRpcException(METHOD_NOT_FOUND,
                               "Method '" + method + "' not found");
    }
    return it->second(params);
}

json JsonRpcRegistry::make_error(const json& id, int code,
                                  const std::string& message,
                                  const json& data) {
    json error = {{"code", code}, {"message", message}};
    if (!data.is_null()) {
        error["data"] = data;
    }
    return {{"jsonrpc", "2.0"}, {"error", error}, {"id", id}};
}

json JsonRpcRegistry::make_result(const json& id, const json& result) {
    return {{"jsonrpc", "2.0"}, {"result", result}, {"id", id}};
}

} // namespace jsonrpc
