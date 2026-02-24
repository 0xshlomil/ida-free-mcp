#pragma once

#include "mcp.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

// Forward declare httplib::Server to avoid pulling the massive header here
namespace httplib {
class Server;
}

namespace server {

// ═══════════════════════════════════════════════════════════════════
// SSE Connection
// ═══════════════════════════════════════════════════════════════════

struct SseConnection {
    std::string session_id;
    std::atomic<bool> alive{true};
    // Response is written directly by the chunked content provider
};

// ═══════════════════════════════════════════════════════════════════
// MCP HTTP Server
// ═══════════════════════════════════════════════════════════════════

class McpHttpServer {
public:
    explicit McpHttpServer(mcp::McpProtocol& protocol);
    ~McpHttpServer();

    /// Start the server on the given host:port in a background thread.
    /// If the port is in use, tries successive ports up to max_retries times.
    bool start(const std::string& host, int port, int max_retries = 10);

    /// Stop the server.
    void stop();

    /// Check if the server is running.
    bool is_running() const { return running_.load(); }

    /// Get the port (for logging).
    int port() const { return port_; }

private:
    mcp::McpProtocol& protocol_;
    std::unique_ptr<httplib::Server> server_;
    std::thread server_thread_;
    std::atomic<bool> running_{false};
    int port_ = 0;

    // SSE connections
    std::mutex sse_mutex_;
    std::unordered_map<std::string, std::shared_ptr<SseConnection>> sse_connections_;

    // CORS
    bool is_cors_allowed(const std::string& origin) const;

    // Route handlers
    void setup_routes();

    // Parse ?ext= query parameter
    std::set<std::string> parse_extensions(const std::string& query_string);
};

} // namespace server
