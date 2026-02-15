#ifndef IDA_MCP_TESTING
#include "../ida_pre.h"
#endif

#include "registry.h"
#include "../utils.h"

#ifndef IDA_MCP_TESTING
#include <funcs.hpp>
#include <hexrays.hpp>
#include <lines.hpp>
#endif

#include <string>

using namespace mcp;

#ifndef IDA_MCP_TESTING

// ═══════════════════════════════════════════════════════════════════
// decompile
// ═══════════════════════════════════════════════════════════════════

static json tool_decompile(const json& params) {
    std::string addr_str = params.value("addr", "");

    try {
        if (!init_hexrays_plugin()) {
            return {
                {"addr", addr_str},
                {"pseudocode", nullptr},
                {"ok", false},
                {"error", "Decompiler not available (Hex-Rays plugin not loaded)"},
            };
        }

        ea_t ea = utils::parse_address(addr_str);
        func_t* pfn = get_func(ea);
        if (!pfn) {
            return {
                {"addr", addr_str},
                {"pseudocode", nullptr},
                {"ok", false},
                {"error", "No function at " + utils::hex_str(ea)},
            };
        }

        hexrays_failure_t hf;
        cfuncptr_t cfunc = decompile_func(pfn, &hf);
        if (!cfunc) {
            std::string err = "Decompilation failed";
            qstring desc = hf.desc();
            if (!desc.empty()) {
                err += ": ";
                err += desc.c_str();
            }
            return {
                {"addr", addr_str},
                {"pseudocode", nullptr},
                {"ok", false},
                {"error", err},
            };
        }

        // Extract pseudocode lines
        const strvec_t& sv = cfunc->get_pseudocode();
        std::string pseudocode;
        for (size_t i = 0; i < sv.size(); ++i) {
            qstring clean;
            tag_remove(&clean, sv[i].line);
            if (i > 0) pseudocode += "\n";
            pseudocode += clean.c_str();
        }

        return {
            {"addr", utils::hex_str(pfn->start_ea)},
            {"pseudocode", pseudocode},
            {"ok", true},
            {"error", nullptr},
        };
    } catch (const std::exception& e) {
        return {
            {"addr", addr_str},
            {"pseudocode", nullptr},
            {"ok", false},
            {"error", e.what()},
        };
    }
}

#endif // !IDA_MCP_TESTING

void register_decompiler_tools(McpProtocol& mcp) {
#ifndef IDA_MCP_TESTING
    mcp.register_tool(
        {"decompile",
         "Decompile a function to pseudocode",
         SchemaBuilder()
             .string_prop("addr", "Function address (hex or decimal)")
             .build()},
        ida_sync_tool(tool_decompile, 60.0)
    );
#endif
}
