#ifndef IDA_MCP_TESTING
#include "../ida_pre.h"
#endif

#include "registry.h"
#include "../utils.h"

#ifndef IDA_MCP_TESTING
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <ua.hpp>
#endif

#include <string>
#include <vector>

using namespace mcp;

#ifndef IDA_MCP_TESTING

// ═══════════════════════════════════════════════════════════════════
// set_comments (disassembly comments only; decompiler deferred)
// ═══════════════════════════════════════════════════════════════════

static json tool_set_comments(const json& params) {
    json items = params.value("items", json());
    if (items.is_object()) {
        items = json::array({items});
    }
    if (!items.is_array()) {
        items = json::array();
    }

    json results = json::array();
    for (const auto& item : items) {
        std::string addr_str = item.value("addr", "");
        std::string comment = item.value("comment", "");

        try {
            ea_t ea = utils::parse_address(addr_str);

            if (!set_cmt(ea, comment.c_str(), false)) {
                results.push_back({
                    {"addr", addr_str},
                    {"error", "Failed to set disassembly comment at " + utils::hex_str(ea)},
                });
                continue;
            }

            results.push_back({
                {"addr", addr_str},
                {"ok", true},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// rename (functions and globals only; locals/stack deferred)
// ═══════════════════════════════════════════════════════════════════

static json tool_rename(const json& params) {
    json batch = params.value("batch", json::object());
    json result = json::object();

    // Rename functions
    if (batch.contains("func")) {
        json func_items = batch["func"];
        if (func_items.is_object()) func_items = json::array({func_items});
        if (func_items.is_null()) func_items = json::array();

        json func_results = json::array();
        for (const auto& item : func_items) {
            try {
                std::string addr_str = item.value("addr", "");
                std::string new_name = item.value("name", "");
                ea_t ea = utils::parse_address(addr_str);

                bool success = set_name(ea, new_name.c_str(), SN_CHECK);
                func_results.push_back({
                    {"addr", addr_str},
                    {"name", new_name},
                    {"ok", success},
                    {"error", success ? json(nullptr) : json("Rename failed")},
                    {"dir", nullptr},
                    {"dir_error", nullptr},
                });
            } catch (const std::exception& e) {
                func_results.push_back({
                    {"addr", item.value("addr", "")},
                    {"error", e.what()},
                });
            }
        }
        result["func"] = func_results;
    }

    // Rename globals
    if (batch.contains("data")) {
        json data_items = batch["data"];
        if (data_items.is_object()) data_items = json::array({data_items});
        if (data_items.is_null()) data_items = json::array();

        json data_results = json::array();
        for (const auto& item : data_items) {
            try {
                std::string old_name = item.value("old", "");
                std::string new_name = item.value("new", "");

                ea_t ea = get_name_ea(BADADDR, old_name.c_str());
                if (ea == BADADDR) {
                    data_results.push_back({
                        {"old", old_name},
                        {"new", new_name},
                        {"ok", false},
                        {"error", "Global '" + old_name + "' not found"},
                    });
                    continue;
                }

                bool success = set_name(ea, new_name.c_str(), SN_CHECK);
                data_results.push_back({
                    {"old", old_name},
                    {"new", new_name},
                    {"ok", success},
                    {"error", success ? json(nullptr) : json("Rename failed")},
                });
            } catch (const std::exception& e) {
                data_results.push_back({
                    {"old", item.value("old", "")},
                    {"error", e.what()},
                });
            }
        }
        result["data"] = data_results;
    }

    return result;
}

// ═══════════════════════════════════════════════════════════════════
// patch_asm
// ═══════════════════════════════════════════════════════════════════

static json tool_patch_asm(const json& params) {
    auto items = utils::normalize_dict_list(
        params.value("items", json()),
        nullptr);

    json results = json::array();
    for (const auto& item : items) {
        std::string addr_str = item.value("addr", "");
        std::string asm_text = item.value("asm", "");

        try {
            ea_t ea = utils::parse_address(addr_str);

            // Split by semicolons
            auto instructions = utils::split(asm_text, ';');
            ea_t cur_ea = ea;

            for (const auto& raw_insn : instructions) {
                std::string insn_text = utils::trim(raw_insn);
                if (insn_text.empty()) continue;

                // PH.assemble() returns the number of bytes assembled
                uchar buf[32];
                ssize_t size = PH.assemble(buf, cur_ea, 0, cur_ea, true, insn_text.c_str());
                if (size <= 0) {
                    throw std::runtime_error("Assembly failed for: " + insn_text);
                }

                patch_bytes(cur_ea, buf, static_cast<size_t>(size));
                cur_ea += static_cast<ea_t>(size);
            }

            results.push_back({
                {"addr", addr_str},
                {"ok", true},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str},
                {"ok", false},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// define_func
// ═══════════════════════════════════════════════════════════════════

static json tool_define_func(const json& params) {
    auto items = utils::normalize_dict_list(
        params.value("items", json()),
        [](const std::string& s) -> json {
            return {{"addr", s}};
        });

    json results = json::array();
    for (const auto& item : items) {
        std::string addr_str = item.value("addr", "");
        std::string end_str = item.value("end", "");

        try {
            ea_t start_ea = utils::parse_address(addr_str);
            ea_t end_ea = BADADDR;
            if (!end_str.empty()) {
                end_ea = utils::parse_address(end_str);
            }

            // Check if function already exists
            func_t* existing = get_func(start_ea);
            if (existing && existing->start_ea == start_ea) {
                results.push_back({
                    {"addr", addr_str},
                    {"start", utils::hex_str(existing->start_ea)},
                    {"end", utils::hex_str(existing->end_ea)},
                    {"ok", true},
                    {"error", nullptr},
                });
                continue;
            }

            bool ok = add_func(start_ea, end_ea);
            if (!ok) {
                results.push_back({
                    {"addr", addr_str},
                    {"start", utils::hex_str(start_ea)},
                    {"end", nullptr},
                    {"ok", false},
                    {"error", "Failed to define function"},
                });
                continue;
            }

            func_t* fn = get_func(start_ea);
            results.push_back({
                {"addr", addr_str},
                {"start", utils::hex_str(fn ? fn->start_ea : start_ea)},
                {"end", fn ? json(utils::hex_str(fn->end_ea)) : json(nullptr)},
                {"ok", true},
                {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str},
                {"ok", false},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// define_code
// ═══════════════════════════════════════════════════════════════════

static json tool_define_code(const json& params) {
    auto items = utils::normalize_dict_list(
        params.value("items", json()),
        [](const std::string& s) -> json {
            return {{"addr", s}};
        });

    json results = json::array();
    for (const auto& item : items) {
        std::string addr_str = item.value("addr", "");

        try {
            ea_t ea = utils::parse_address(addr_str);
            int length = create_insn(ea);

            if (length <= 0) {
                results.push_back({
                    {"addr", addr_str},
                    {"length", 0},
                    {"ok", false},
                    {"error", "Failed to create instruction at " + utils::hex_str(ea)},
                });
                continue;
            }

            results.push_back({
                {"addr", addr_str},
                {"length", length},
                {"ok", true},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str},
                {"length", 0},
                {"ok", false},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// undefine
// ═══════════════════════════════════════════════════════════════════

static json tool_undefine(const json& params) {
    auto items = utils::normalize_dict_list(
        params.value("items", json()),
        [](const std::string& s) -> json {
            return {{"addr", s}};
        });

    json results = json::array();
    for (const auto& item : items) {
        std::string addr_str = item.value("addr", "");
        std::string end_str = item.value("end", "");
        int size = item.value("size", 0);

        try {
            ea_t start_ea = utils::parse_address(addr_str);
            asize_t nbytes = 1;

            if (!end_str.empty()) {
                ea_t end_ea = utils::parse_address(end_str);
                nbytes = static_cast<asize_t>(end_ea - start_ea);
            } else if (size > 0) {
                nbytes = static_cast<asize_t>(size);
            }

            del_items(start_ea, DELIT_EXPAND, nbytes);

            results.push_back({
                {"addr", addr_str},
                {"size", static_cast<int>(nbytes)},
                {"ok", true},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str},
                {"size", 0},
                {"ok", false},
                {"error", e.what()},
            });
        }
    }
    return results;
}

#endif // !IDA_MCP_TESTING

void register_modify_tools(McpProtocol& mcp) {
#ifndef IDA_MCP_TESTING
    mcp.register_tool(
        {"set_comments",
         "Set comments at addresses (both disassembly and decompiler views)",
         SchemaBuilder()
             .prop("items", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address (hex or decimal)"}}},
                         {"comment", {{"type", "string"}, {"description", "Comment text"}}},
                     }}, {"required", json::array({"addr", "comment"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address (hex or decimal)"}}},
                         {"comment", {{"type", "string"}, {"description", "Comment text"}}},
                     }}, {"required", json::array({"addr", "comment"})}},
                 })},
                 {"description", "Comment operation(s)"},
             })
             .build()},
        ida_sync_tool(tool_set_comments)
    );

    mcp.register_tool(
        {"rename",
         "Unified rename operation for functions, globals, locals, and stack variables",
         SchemaBuilder()
             .prop("batch", {
                 {"type", "object"},
                 {"description", "Batch rename operations across all entity types"},
                 {"properties", {
                     {"func", {{"anyOf", json::array({
                         {{"type", "array"}, {"items", {{"type", "object"}}}},
                         {{"type", "object"}},
                         {{"type", "null"}},
                     })}, {"description", "Function rename operations"}}},
                     {"data", {{"anyOf", json::array({
                         {{"type", "array"}, {"items", {{"type", "object"}}}},
                         {{"type", "object"}},
                         {{"type", "null"}},
                     })}, {"description", "Global/data variable rename operations"}}},
                 }},
             })
             .build()},
        ida_sync_tool(tool_rename)
    );

    mcp.register_tool(
        {"patch_asm",
         "Assemble and patch instructions at addresses",
         SchemaBuilder()
             .prop("items", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to patch"}}},
                         {"asm", {{"type", "string"}, {"description", "Assembly instructions (semicolon-separated)"}}},
                     }}, {"required", json::array({"addr", "asm"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to patch"}}},
                         {"asm", {{"type", "string"}, {"description", "Assembly instructions (semicolon-separated)"}}},
                     }}, {"required", json::array({"addr", "asm"})}},
                 })},
                 {"description", "Assembly patch operation(s)"},
             })
             .build()},
        ida_sync_tool(tool_patch_asm)
    );

    mcp.register_tool(
        {"define_func",
         "Define a function at address",
         SchemaBuilder()
             .prop("items", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Start address"}}},
                         {"end", {{"type", "string"}, {"description", "End address (optional, IDA auto-detects)"}}},
                     }}, {"required", json::array({"addr"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Start address"}}},
                         {"end", {{"type", "string"}, {"description", "End address (optional, IDA auto-detects)"}}},
                     }}, {"required", json::array({"addr"})}},
                 })},
                 {"description", "Function definition operation(s)"},
             })
             .build()},
        ida_sync_tool(tool_define_func)
    );

    mcp.register_tool(
        {"define_code",
         "Convert bytes to code (create instruction)",
         SchemaBuilder()
             .prop("items", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to define as code"}}},
                     }}, {"required", json::array({"addr"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to define as code"}}},
                     }}, {"required", json::array({"addr"})}},
                 })},
                 {"description", "Code definition operation(s)"},
             })
             .build()},
        ida_sync_tool(tool_define_code)
    );

    mcp.register_tool(
        {"undefine",
         "Undefine items back to raw bytes",
         SchemaBuilder()
             .prop("items", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Start address"}}},
                         {"end", {{"type", "string"}, {"description", "End address (optional)"}}},
                         {"size", {{"type", "integer"}, {"description", "Size in bytes (optional, default 1)"}}},
                     }}, {"required", json::array({"addr"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Start address"}}},
                         {"end", {{"type", "string"}, {"description", "End address (optional)"}}},
                         {"size", {{"type", "integer"}, {"description", "Size in bytes (optional, default 1)"}}},
                     }}, {"required", json::array({"addr"})}},
                 })},
                 {"description", "Undefine operation(s)"},
             })
             .build()},
        ida_sync_tool(tool_undefine)
    );
#endif
}
