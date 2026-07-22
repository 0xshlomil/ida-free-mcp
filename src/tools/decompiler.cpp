#ifndef IDA_MCP_TESTING
#include "../ida_pre.h"
#endif

#include "registry.h"
#include "../utils.h"

#ifndef IDA_MCP_TESTING
#include <funcs.hpp>
#include <hexrays.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <moves.hpp>
#include <name.hpp>
#endif

#include <string>

using namespace mcp;

#ifndef IDA_MCP_TESTING

// ═══════════════════════════════════════════════════════════════════
// Debug/verbose mode
// ═══════════════════════════════════════════════════════════════════

static bool g_debug = false;

static void dbg(const char* fmt, ...) {
    if (!g_debug) return;
    va_list va;
    va_start(va, fmt);
    vmsg(fmt, va);
    va_end(va);
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

static std::string ptr_hex(uintptr_t p) {
    char buf[32];
    qsnprintf(buf, sizeof(buf), "0x%lx", p);
    return buf;
}

// ═══════════════════════════════════════════════════════════════════
// Tool: debug_mode - toggle verbose logging to IDA console
// ═══════════════════════════════════════════════════════════════════

static json tool_debug_mode(const json& params) {
    bool enable = params.value("enable", !g_debug);  // toggle if not specified
    g_debug = enable;
    msg("[MCP] Debug mode: %s\n", g_debug ? "ON" : "OFF");
    return {{"debug", g_debug}};
}

// ═══════════════════════════════════════════════════════════════════
// Tool: hexrays_diag - SDK status check
// ═══════════════════════════════════════════════════════════════════

static json tool_hexrays_diag(const json&) {
    json result;

    dbg("[MCP] hexrays_diag: checking SDK status\n");

    result["init_hexrays_plugin"] = (bool)init_hexrays_plugin();

    hexdsp_t* dsp = get_hexdsp();
    if (dsp)
        result["hexdsp"] = ptr_hex((uintptr_t)dsp);
    else
        result["hexdsp"] = nullptr;

    // Plugin list - find hexcx
    result["hexcx_loaded"] = false;
    json all_plugins = json::array();
    for (const plugin_info_t* pi = get_plugins(); pi != nullptr; pi = pi->next) {
        const char* pi_path = pi->path;
        if (pi_path == nullptr) continue;
        json pj = {
            {"path", std::string(pi_path)},
        };
        if (pi->entry)
            pj["entry_addr"] = ptr_hex((uintptr_t)pi->entry);
        // Check for hexcx/hexx
        if (strstr(pi_path, "hexcx") || strstr(pi_path, "hexx")) {
            result["hexcx_loaded"] = true;
            result["hexcx_path"] = std::string(pi_path);
            if (pi->entry)
                result["hexcx_entry"] = ptr_hex((uintptr_t)pi->entry);
            pj["is_hexrays"] = true;
        }
        all_plugins.push_back(pj);
    }
    result["plugins"] = all_plugins;

    // Add guidance for LLMs interpreting this output
    if (!result.value("init_hexrays_plugin", false)) {
        result["note"] = "Hex-Rays SDK is not initialized. This is normal for IDA Free. "
                         "The 'decompile' tool uses GUI-based decompilation and works without the SDK.";
    }

    dbg("[MCP] hexrays_diag: done\n");
    return result;
}

// ═══════════════════════════════════════════════════════════════════
// Tool: decompile - GUI-based decompilation
// ═══════════════════════════════════════════════════════════════════

// Try to read pseudocode via vdui_t probing (Method A).
// get_viewer_user_data() may return the vdui_t* directly.
// We validate by checking that vdui_t::ct matches the widget pointer.
// If valid, we read cfunc_t::sv (strvec_t) which contains the pseudocode
// lines. These are core SDK types - no hexdsp calls needed for reading.
static bool read_pseudocode_via_vdui(TWidget *w, ea_t func_ea,
                                     std::string& out_text, int& out_lines) {
    void *ud = get_viewer_user_data(w);
    if (!ud) return false;

    vdui_t *vu = (vdui_t*)ud;

    // Validate: ct must match widget, flags must be sane
    if (vu->ct != w) return false;
    if ((vu->flags & ~(VDUI_VISIBLE | VDUI_VALID)) != 0) return false;
    if (vu->view_idx < 0 || vu->view_idx >= 26) return false;
    if (!vu->visible() || !vu->valid()) return false;

    // Get cfunc_t* via qrefcnt_t<cfunc_t>::operator T*()
    cfunc_t *cf = vu->cfunc;
    if (!cf) return false;

    // Verify this is the right function and text is ready
    if (cf->entry_ea != func_ea) return false;
    if (!(cf->statebits & CFS_TEXT)) return false;

    // Read strvec_t (qvector<simpleline_t>) - all core SDK types
    const strvec_t &sv = cf->sv;
    std::string text;
    for (size_t i = 0; i < sv.size(); i++) {
        qstring clean;
        tag_remove(&clean, sv[i].line);
        if (i > 0) text += "\n";
        text += clean.c_str();
    }

    out_text = std::move(text);
    out_lines = (int)sv.size();
    dbg("[MCP] decompile: read %d lines via vdui_t probe\n", out_lines);
    return true;
}

// Try to read pseudocode via place_t iteration (Method B).
// Uses the custom viewer's place_t virtual methods (generate/next)
// which are implemented by hexcx64.so internally and don't need hexdsp.
static bool read_pseudocode_via_places(TWidget *w,
                                       std::string& out_text, int& out_lines) {
    lochist_entry_t loc;
    if (!get_custom_viewer_location(&loc, w, false)) return false;
    if (!loc.place()) return false;

    void *viewer_ud = get_viewer_user_data(w);
    place_t *cur = loc.place()->clone();
    if (!cur) return false;

    // Go to the very beginning by calling prev() repeatedly
    int rewind_count = 0;
    while (cur->prev(viewer_ud) && rewind_count < 100000)
        rewind_count++;

    std::string text;
    int line_count = 0;
    const int MAX_LINES = 50000;

    while (line_count < MAX_LINES) {
        qstrvec_t lines;
        int deflnnum;
        color_t pfx_color;
        bgcolor_t bgcolor;
        int n = cur->generate(&lines, &deflnnum, &pfx_color, &bgcolor,
                              viewer_ud, 5000);

        if (n <= 0) break;

        for (size_t i = 0; i < (size_t)n && i < lines.size(); i++) {
            qstring clean;
            tag_remove(&clean, lines[i]);
            if (line_count > 0) text += "\n";
            text += clean.c_str();
            line_count++;
        }

        if (!cur->next(viewer_ud)) break;
    }

    delete cur;

    if (line_count == 0) return false;

    out_text = std::move(text);
    out_lines = line_count;
    dbg("[MCP] decompile: read %d lines via place iteration (rewound %d)\n",
        out_lines, rewind_count);
    return true;
}

static json tool_decompile(const json& params) {
    std::string addr_str = params.value("addr", "");

    try {
        ea_t ea = utils::parse_address(addr_str);
        func_t* pfn = get_func(ea);
        if (!pfn) {
            return {
                {"addr", addr_str}, {"ok", false},
                {"error", "No function at " + utils::hex_str(ea)},
            };
        }

        dbg("[MCP] decompile: function %s-%s\n",
            utils::hex_str(pfn->start_ea).c_str(),
            utils::hex_str(pfn->end_ea).c_str());

        // Step 1: Navigate to the function
        jumpto(pfn->start_ea);

        // Activate the disassembly view BEFORE F5. hx:GenPseudo decompiles the
        // current address of the *focused* widget — if a Pseudocode widget is the
        // active one (e.g. left over from a previous call), F5 just re-runs on ITS
        // function and never refreshes to ours, which is the stale-output bug.
        if (TWidget *dv = find_widget("IDA View-A"))
            activate_widget(dv, true);

        // Step 2: Trigger F5 decompilation via GUI action
        bool acted = process_ui_action("hx:GenPseudo");
        dbg("[MCP] decompile: hx:GenPseudo = %d\n", acted);

        if (!acted) {
            return {
                {"addr", utils::hex_str(pfn->start_ea)}, {"ok", false},
                {"error", "Decompiler action failed (hx:GenPseudo)"},
            };
        }

        // Steps 3+4: Find the pseudocode widget showing THIS function and read it.
        //
        // On IDA Pro, Method A (vdui_t/cfunc probe) validates by cfunc_t::entry_ea.
        // But IDA Free's cloud decompiler (hexcx) does NOT populate cfunc_t/vdui_t, so
        // there we must read the widget text (Method B) and validate it belongs to our
        // function by checking the decompiled text contains the function's name — this
        // is what stops a stale widget (on another function) from being returned, which
        // was the original bug. The cloud decompile is also asynchronous, so we retry
        // briefly to let the freshly-generated pseudocode land in the widget.
        qstring fname;
        get_func_name(&fname, pfn->start_ea);

        for (int attempt = 0; attempt < 40; attempt++) {
            for (char c = 'A'; c <= 'Z'; c++) {
                char buf[32];
                qsnprintf(buf, sizeof(buf), "Pseudocode-%c", c);
                TWidget *w = find_widget(buf);
                if (!w) continue;

                // Method A: cfunc probe (IDA Pro — self-validates entry_ea).
                std::string pseudocode;
                int line_count = 0;
                if (read_pseudocode_via_vdui(w, pfn->start_ea, pseudocode, line_count)) {
                    return {
                        {"addr", utils::hex_str(pfn->start_ea)},
                        {"pseudocode", pseudocode}, {"lines", line_count}, {"ok", true},
                    };
                }

                // Method B: text iteration (IDA Free). Accept only if the text names
                // this function, so a stale widget on a different function is skipped.
                std::string t;
                int tl = 0;
                if (read_pseudocode_via_places(w, t, tl)) {
                    if (fname.empty() || t.find(fname.c_str()) != std::string::npos) {
                        return {
                            {"addr", utils::hex_str(pfn->start_ea)},
                            {"pseudocode", t}, {"lines", tl}, {"ok", true},
                        };
                    }
                }
            }
            qsleep(50); // let the async cloud decompile populate the widget, then retry
        }

        return {
            {"addr", utils::hex_str(pfn->start_ea)}, {"ok", false},
            {"error", "No pseudocode widget for this function after decompilation"},
        };

    } catch (const std::exception& e) {
        return {
            {"addr", addr_str}, {"ok", false},
            {"error", std::string("Exception: ") + e.what()},
        };
    }
}

#endif // !IDA_MCP_TESTING

void register_decompiler_tools(McpProtocol& mcp) {
#ifndef IDA_MCP_TESTING
    mcp.register_tool(
        {"debug_mode",
         "Toggle debug/verbose logging to IDA console",
         SchemaBuilder()
             .bool_prop("enable", "Enable (true) or disable (false) debug logging")
             .build()},
        ida_sync_tool(tool_debug_mode)
    );

    mcp.register_tool(
        {"hexrays_diag",
         "Check Hex-Rays decompiler SDK status (init_hexrays_plugin, hexdsp, loaded plugins). "
         "NOTE: On IDA Free these will report 'not initialized' — this is expected and does NOT "
         "affect the 'decompile' tool, which uses GUI-based decompilation instead of the SDK API.",
         SchemaBuilder().build()},
        ida_sync_tool(tool_hexrays_diag)
    );

    mcp.register_tool(
        {"decompile",
         "Decompile a function to pseudocode. Works on both IDA Pro and IDA Free — uses GUI-based "
         "decompilation (F5) and reads output from the pseudocode widget, no Hex-Rays SDK required.",
         SchemaBuilder()
             .string_prop("addr", "Function address (hex or decimal)")
             .build()},
        ida_sync_tool(tool_decompile, 60.0)
    );
#endif
}
