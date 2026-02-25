#include "ida_pre.h"

#include "plugin.h"
#include "mcp.h"
#include "server.h"
#include "dialog_suppress.h"
#include "tools/registry.h"
#include "resources/resources.h"
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <hexrays.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#else
#include <windows.h>
#include <process.h>
#endif

namespace fs = std::filesystem;

// ═══════════════════════════════════════════════════════════════════
// Instance Registry
// ═══════════════════════════════════════════════════════════════════

static fs::path get_instances_dir() {
#ifdef _WIN32
    const char* home = std::getenv("USERPROFILE");
#else
    const char* home = std::getenv("HOME");
#endif
    if (!home) return {};
    return fs::path(home) / ".ida-mcp" / "instances";
}

static int get_pid() {
#ifdef _WIN32
    return _getpid();
#else
    return getpid();
#endif
}

static bool is_pid_alive(int pid) {
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) { CloseHandle(h); return true; }
    return false;
#else
    return kill(pid, 0) == 0;
#endif
}

static void write_instance_file(int port, const std::string& idb_path) {
    auto dir = get_instances_dir();
    if (dir.empty()) return;

    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) return;

    nlohmann::json info = {
        {"port", port},
        {"pid", get_pid()},
        {"idb_path", idb_path},
    };

    auto file = dir / (std::to_string(get_pid()) + ".json");
    std::ofstream ofs(file);
    if (ofs) ofs << info.dump(2);
}

static void remove_instance_file() {
    auto dir = get_instances_dir();
    if (dir.empty()) return;

    auto file = dir / (std::to_string(get_pid()) + ".json");
    std::error_code ec;
    fs::remove(file, ec);
}

static void cleanup_stale_instances() {
    auto dir = get_instances_dir();
    if (dir.empty()) return;

    std::error_code ec;
    if (!fs::exists(dir, ec)) return;

    for (auto& entry : fs::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".json")
            continue;

        std::string stem = entry.path().stem().string();
        try {
            int pid = std::stoi(stem);
            if (!is_pid_alive(pid)) {
                fs::remove(entry.path(), ec);
            }
        } catch (...) {
            // Not a PID-named file, skip
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Plugin Module
// ═══════════════════════════════════════════════════════════════════

struct McpPlugmod : public plugmod_t {
    std::unique_ptr<mcp::McpProtocol> protocol;
    std::unique_ptr<server::McpHttpServer> http_server;

    static constexpr const char* HOST = "127.0.0.1";
    static constexpr int DEFAULT_PORT = 13337;

    McpPlugmod() = default;

    ~McpPlugmod() override {
        if (http_server) {
            http_server->stop();
        }
        remove_instance_file();
        idasync::uninstall_dialog_hook();
    }

    bool idaapi run(size_t) override {
        // Toggle: stop if already running
        if (http_server && http_server->is_running()) {
            http_server->stop();
            http_server.reset();
            protocol.reset();
            remove_instance_file();
            return true;
        }

        // Clean up stale instance files from crashed sessions
        cleanup_stale_instances();

        // Determine port (env var or default)
        int port = DEFAULT_PORT;
        const char* port_env = std::getenv("IDA_MCP_PORT");
        if (port_env) {
            int p = std::atoi(port_env);
            if (p > 0 && p <= 65535) port = p;
        }

        // Install dialog auto-dismiss hook for search tools
        idasync::install_dialog_hook();

        // Create protocol and register everything
        protocol = std::make_unique<mcp::McpProtocol>("ida-pro-mcp", IDA_MCP_VERSION);

        register_core_tools(*protocol);
        register_analysis_tools(*protocol);
        register_memory_tools(*protocol);
        register_modify_tools(*protocol);
        register_type_tools(*protocol);
        register_stack_tools(*protocol);
        register_decompiler_tools(*protocol);
        register_resources(*protocol);

        // Log decompiler availability
        bool has_hexrays = init_hexrays_plugin();
        msg("[MCP] Hex-Rays decompiler: %s\n", has_hexrays ? "available" : "not available");

        // Start HTTP server (auto-increments port if in use)
        http_server = std::make_unique<server::McpHttpServer>(*protocol);
        if (!http_server->start(HOST, port)) {
            msg("[MCP] Error: Failed to start server on port range %d-%d\n",
                port, port + 10);
            http_server.reset();
            protocol.reset();
            return false;
        }

        // Use the actual bound port for download URLs
        int actual_port = http_server->port();
        char url_buf[256];
        qsnprintf(url_buf, sizeof(url_buf), "http://%s:%d", HOST, actual_port);
        protocol->set_download_base_url(url_buf);

        // Write instance registry file
        std::string idb_path = get_path(PATH_TYPE_IDB);
        write_instance_file(actual_port, idb_path);

        return true;
    }
};

// ═══════════════════════════════════════════════════════════════════
// Plugin Descriptor
// ═══════════════════════════════════════════════════════════════════

static plugmod_t* idaapi init() {
    msg("[MCP] Native plugin loaded, use Edit -> Plugins -> MCP (Ctrl+Alt+M) to start the server\n");
    return new McpPlugmod();
}

#ifdef _WIN32
__declspec(dllexport)
#endif
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,                  // plugmod_t-based plugin (init returns plugmod_t*)
    init,                          // init
    nullptr,                       // term (handled by plugmod_t destructor)
    nullptr,                       // run (handled by plugmod_t::run)
    "IDA Pro MCP Server (Native)", // comment
    "Native MCP server for LLM-assisted reverse engineering", // help
    "MCP",                         // wanted_name
    "Ctrl-Alt-M",                  // wanted_hotkey
};
