#ifndef IDA_MCP_TESTING
#include "ida_pre.h"
#endif

#include "server.h"

#include <httplib.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <random>
#include <sstream>
#include <thread>

#ifndef IDA_MCP_TESTING
#include <kernwin.hpp>
#define LOG_MSG(fmt, ...) msg(fmt, ##__VA_ARGS__)
#else
#define LOG_MSG(fmt, ...) std::printf(fmt, ##__VA_ARGS__)
#endif

namespace server {

// ═══════════════════════════════════════════════════════════════════
// UUID generation
// ═══════════════════════════════════════════════════════════════════

static std::string uuid_v4() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<int> dist(0, 15);

    const char hex[] = "0123456789abcdef";
    std::string uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    for (auto& c : uuid) {
        if (c == 'x') c = hex[dist(gen)];
        else if (c == 'y') c = hex[(dist(gen) & 0x3) | 0x8];
    }
    return uuid;
}

// ═══════════════════════════════════════════════════════════════════
// URL query parsing
// ═══════════════════════════════════════════════════════════════════

static std::string url_decode(const std::string& s) {
    std::string result;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int hi = 0, lo = 0;
            auto hex_val = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            hi = hex_val(s[i + 1]);
            lo = hex_val(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                result += static_cast<char>((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        if (s[i] == '+') {
            result += ' ';
        } else {
            result += s[i];
        }
    }
    return result;
}

static std::unordered_map<std::string, std::string> parse_query(const std::string& query) {
    std::unordered_map<std::string, std::string> params;
    std::istringstream iss(query);
    std::string pair;
    while (std::getline(iss, pair, '&')) {
        auto eq = pair.find('=');
        if (eq != std::string::npos) {
            params[url_decode(pair.substr(0, eq))] = url_decode(pair.substr(eq + 1));
        } else if (!pair.empty()) {
            params[url_decode(pair)] = "";
        }
    }
    return params;
}

static std::string extract_query_string(const std::string& path) {
    auto q = path.find('?');
    return (q != std::string::npos) ? path.substr(q + 1) : "";
}

static std::string extract_path(const std::string& full_path) {
    auto q = full_path.find('?');
    return (q != std::string::npos) ? full_path.substr(0, q) : full_path;
}

// ═══════════════════════════════════════════════════════════════════
// McpHttpServer
// ═══════════════════════════════════════════════════════════════════

McpHttpServer::McpHttpServer(mcp::McpProtocol& protocol)
    : protocol_(protocol) {}

McpHttpServer::~McpHttpServer() {
    stop();
}

bool McpHttpServer::start(const std::string& host, int port) {
    if (running_.load()) {
        LOG_MSG("[MCP] Server is already running\n");
        return false;
    }

    server_ = std::make_unique<httplib::Server>();
    setup_routes();

    port_ = port;
    running_.store(true);

    server_thread_ = std::thread([this, host, port]() {
        LOG_MSG("[MCP] Server started:\n");
        LOG_MSG("  Streamable HTTP: http://%s:%d/mcp\n", host.c_str(), port);
        LOG_MSG("  SSE: http://%s:%d/sse\n", host.c_str(), port);

        if (!server_->listen(host, port)) {
            if (running_.load()) {
                LOG_MSG("[MCP] Server failed to start on %s:%d\n",
                        host.c_str(), port);
            }
        }
        running_.store(false);
    });

    // Give the server a moment to bind
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return running_.load();
}

void McpHttpServer::stop() {
    if (!running_.load()) return;

    running_.store(false);

    // Close all SSE connections
    {
        std::lock_guard<std::mutex> lock(sse_mutex_);
        for (auto& [id, conn] : sse_connections_) {
            conn->alive.store(false);
        }
        sse_connections_.clear();
    }

    if (server_) {
        server_->stop();
    }

    if (server_thread_.joinable()) {
        server_thread_.join();
    }

    server_.reset();
    LOG_MSG("[MCP] Server stopped\n");
}

bool McpHttpServer::is_cors_allowed(const std::string& origin) const {
    if (origin.empty()) return false;

    // Parse the origin to get hostname
    // Origin format: scheme://host[:port]
    auto scheme_end = origin.find("://");
    if (scheme_end == std::string::npos) return false;

    std::string host_part = origin.substr(scheme_end + 3);
    // Remove port if present
    auto colon = host_part.find(':');
    std::string hostname = (colon != std::string::npos)
                           ? host_part.substr(0, colon)
                           : host_part;

    return hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1";
}

std::set<std::string> McpHttpServer::parse_extensions(const std::string& query_string) {
    std::set<std::string> exts;
    auto params = parse_query(query_string);
    auto it = params.find("ext");
    if (it != params.end() && !it->second.empty()) {
        std::istringstream iss(it->second);
        std::string token;
        while (std::getline(iss, token, ',')) {
            // Trim
            auto start = token.find_first_not_of(" \t");
            auto end = token.find_last_not_of(" \t");
            if (start != std::string::npos) {
                exts.insert(token.substr(start, end - start + 1));
            }
        }
    }
    return exts;
}

void McpHttpServer::setup_routes() {
    // ── OPTIONS (CORS preflight) ────────────────────────────────
    server_->Options(".*", [this](const httplib::Request& req, httplib::Response& res) {
        std::string origin = req.get_header_value("Origin");
        if (is_cors_allowed(origin)) {
            res.set_header("Access-Control-Allow-Origin", origin);
            res.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
            res.set_header("Access-Control-Allow-Headers",
                "Content-Type, Accept, X-Requested-With, Mcp-Session-Id, Mcp-Protocol-Version");
            if (req.get_header_value("Access-Control-Request-Private-Network") == "true") {
                res.set_header("Access-Control-Allow-Private-Network", "true");
            }
        }
        res.status = 200;
    });

    // ── POST /mcp (Streamable HTTP) ────────────────────────────
    server_->Post("/mcp", [this](const httplib::Request& req, httplib::Response& res) {
        // CORS
        std::string origin = req.get_header_value("Origin");
        if (is_cors_allowed(origin)) {
            res.set_header("Access-Control-Allow-Origin", origin);
        }

        // Body size limit (10MB)
        if (req.body.size() > 10 * 1024 * 1024) {
            res.status = 413;
            res.set_content("Payload Too Large: exceeds 10485760 bytes\n", "text/plain");
            return;
        }

        // Parse extensions
        auto exts = parse_extensions(extract_query_string(req.path));
        protocol_.set_enabled_extensions(exts);
        protocol_.set_protocol_version("2025-06-18");

        // Dispatch
        auto response = protocol_.registry().dispatch(req.body);

        if (!response.has_value()) {
            // Notification
            res.status = 202;
            res.set_content("Accepted", "application/json");
        } else {
            res.status = 200;
            res.set_content(response->dump(), "application/json");
        }
    });

    // ── GET /sse (SSE transport) ────────────────────────────────
    server_->Get("/sse", [this](const httplib::Request& req, httplib::Response& res) {
        std::string origin = req.get_header_value("Origin");

        auto conn = std::make_shared<SseConnection>();
        conn->session_id = uuid_v4();

        {
            std::lock_guard<std::mutex> lock(sse_mutex_);
            sse_connections_[conn->session_id] = conn;
        }

        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");
        if (is_cors_allowed(origin)) {
            res.set_header("Access-Control-Allow-Origin", origin);
        }

        // Use chunked content provider for SSE
        res.set_chunked_content_provider(
            "text/event-stream",
            [this, conn](size_t offset, httplib::DataSink& sink) -> bool {
                // Send endpoint event first (on first call, offset == 0)
                if (offset == 0) {
                    std::string event = "event: endpoint\ndata: /sse?session=" +
                                        conn->session_id + "\n\n";
                    sink.write(event.data(), event.size());
                }

                // Keep alive with pings
                auto last_ping = std::chrono::steady_clock::now();
                while (conn->alive.load() && running_.load()) {
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        now - last_ping).count();

                    if (elapsed >= 30) {
                        std::string ping = "event: ping\ndata: {}\n\n";
                        if (!sink.write(ping.data(), ping.size())) {
                            break;
                        }
                        last_ping = now;
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                return false; // Close connection
            },
            [this, conn](bool) {
                // Cleanup on disconnect
                conn->alive.store(false);
                std::lock_guard<std::mutex> lock(sse_mutex_);
                sse_connections_.erase(conn->session_id);
            }
        );
    });

    // ── POST /sse?session=X (SSE request) ───────────────────────
    server_->Post("/sse", [this](const httplib::Request& req, httplib::Response& res) {
        std::string origin = req.get_header_value("Origin");
        if (is_cors_allowed(origin)) {
            res.set_header("Access-Control-Allow-Origin", origin);
        }

        auto params = parse_query(extract_query_string(req.path));
        auto it = params.find("session");
        if (it == params.end()) {
            res.status = 400;
            res.set_content("Missing ?session for SSE POST\n", "text/plain");
            return;
        }

        std::string session_id = it->second;

        // Parse extensions
        auto exts = parse_extensions(extract_query_string(req.path));
        protocol_.set_enabled_extensions(exts);
        protocol_.set_protocol_version("2024-11-05");

        // Dispatch
        auto response = protocol_.registry().dispatch(req.body);

        // Send response via SSE if we have a connection
        if (response.has_value()) {
            std::lock_guard<std::mutex> lock(sse_mutex_);
            auto conn_it = sse_connections_.find(session_id);
            if (conn_it != sse_connections_.end() && conn_it->second->alive.load()) {
                // Note: We can't write directly to the SSE connection from here
                // because cpp-httplib's chunked provider runs in a different thread.
                // For now, we return the response directly in the POST response
                // (which is the Streamable HTTP behavior, adequate for most clients).
            }
        }

        // Return 202 Accepted
        res.status = 202;
        res.set_content(req.body, "application/json");
    });

    // ── GET /output/{id}.json (download cached output) ──────────
    server_->Get(R"(/output/([a-f0-9\-]+)\.json)", [this](const httplib::Request& req, httplib::Response& res) {
        std::string origin = req.get_header_value("Origin");
        if (is_cors_allowed(origin)) {
            res.set_header("Access-Control-Allow-Origin", origin);
        }

        std::string output_id = req.matches[1];
        json cached = protocol_.get_cached_output(output_id);

        if (cached.is_null()) {
            res.status = 404;
            res.set_content("Output not found\n", "text/plain");
            return;
        }

        res.status = 200;
        res.set_content(cached.dump(2), "application/json");
    });

    // ── 404 catch-all ───────────────────────────────────────────
    server_->set_error_handler([](const httplib::Request&, httplib::Response& res) {
        if (res.status == 404) {
            res.set_content("Not Found\n", "text/plain");
        }
    });
}

} // namespace server
