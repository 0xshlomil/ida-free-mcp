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

#include <memory>
#include <string>

// ═══════════════════════════════════════════════════════════════════
// Plugin Module
// ═══════════════════════════════════════════════════════════════════

struct McpPlugmod : public plugmod_t {
    std::unique_ptr<mcp::McpProtocol> protocol;
    std::unique_ptr<server::McpHttpServer> http_server;

    static constexpr const char* HOST = "127.0.0.1";
    static constexpr int PORT = 13337;

    McpPlugmod() = default;

    ~McpPlugmod() override {
        if (http_server) {
            http_server->stop();
        }
        idasync::uninstall_dialog_hook();
    }

    bool idaapi run(size_t) override {
        // Toggle: stop if already running
        if (http_server && http_server->is_running()) {
            http_server->stop();
            http_server.reset();
            protocol.reset();
            return true;
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

        // Set download base URL
        char url_buf[256];
        qsnprintf(url_buf, sizeof(url_buf), "http://%s:%d", HOST, PORT);
        protocol->set_download_base_url(url_buf);

        // Start HTTP server
        http_server = std::make_unique<server::McpHttpServer>(*protocol);
        if (!http_server->start(HOST, PORT)) {
            msg("[MCP] Error: Failed to start server on %s:%d\n", HOST, PORT);
            http_server.reset();
            protocol.reset();
            return false;
        }

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
