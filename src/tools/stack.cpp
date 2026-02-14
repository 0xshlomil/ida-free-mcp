#ifndef IDA_MCP_TESTING
#include "../ida_pre.h"
#endif

#include "registry.h"
#include "../utils.h"

#ifndef IDA_MCP_TESTING
#include <idp.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#include <typeinf.hpp>
#include <name.hpp>
// PH macro needs idp.hpp (already included)
#endif

#include <string>
#include <vector>

using namespace mcp;

#ifndef IDA_MCP_TESTING

// ═══════════════════════════════════════════════════════════════════
// stack_frame
// ═══════════════════════════════════════════════════════════════════

static json tool_stack_frame(const json& params) {
    auto addrs = utils::normalize_list_input(params.value("addrs", json()));

    json results = json::array();
    for (const auto& addr_str : addrs) {
        try {
            ea_t ea = utils::parse_address(addr_str);
            func_t* fn = get_func(ea);
            if (!fn) {
                results.push_back({
                    {"addr", addr_str}, {"vars", nullptr},
                    {"error", "Not a function"},
                });
                continue;
            }

            tinfo_t frame_tif;
            if (!get_func_frame(&frame_tif, fn)) {
                results.push_back({
                    {"addr", addr_str}, {"vars", json::array()},
                    {"error", nullptr},
                });
                continue;
            }

            udt_type_data_t udt;
            if (!frame_tif.get_udt_details(&udt)) {
                results.push_back({
                    {"addr", addr_str}, {"vars", json::array()},
                    {"error", nullptr},
                });
                continue;
            }

            json vars = json::array();
            for (size_t i = 0; i < udt.size(); ++i) {
                const udm_t& udm = udt[i];
                uint64_t offset_bytes = udm.offset / 8;
                uint64_t size_bytes = udm.size / 8;

                // Skip special frame members (return address, saved regs)
                tid_t member_tid = frame_tif.get_udm_tid(static_cast<int>(i));
                if (member_tid != BADADDR && is_special_frame_member(member_tid)) {
                    continue;
                }

                qstring type_str;
                udm.type.print(&type_str);

                vars.push_back({
                    {"name", udm.name.c_str()},
                    {"offset", utils::hex_str(static_cast<ea_t>(offset_bytes))},
                    {"type", type_str.c_str()},
                    {"size", static_cast<int>(size_bytes)},
                });
            }

            results.push_back({
                {"addr", addr_str},
                {"vars", vars},
                {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str}, {"vars", nullptr}, {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// declare_stack
// ═══════════════════════════════════════════════════════════════════

static json tool_declare_stack(const json& params) {
    auto items = utils::normalize_dict_list(
        params.value("items", json()),
        nullptr);

    json results = json::array();
    for (const auto& item : items) {
        std::string addr_str = item.value("addr", "");
        std::string var_name = item.value("name", "");
        int offset = item.value("offset", 0);
        std::string type_str = item.value("type", "");

        try {
            ea_t ea = utils::parse_address(addr_str);
            func_t* fn = get_func(ea);
            if (!fn) {
                results.push_back({
                    {"addr", addr_str}, {"name", var_name},
                    {"ok", false}, {"error", "Not a function"},
                });
                continue;
            }

            // Parse type
            tinfo_t tif;
            if (!type_str.empty()) {
                if (!tif.get_named_type(nullptr, type_str.c_str())) {
                    qstring parsed_name;
                    if (!parse_decl(&tif, &parsed_name, nullptr, type_str.c_str(), PT_SIL)) {
                        results.push_back({
                            {"addr", addr_str}, {"name", var_name},
                            {"ok", false}, {"error", "Failed to parse type: " + type_str},
                        });
                        continue;
                    }
                }
            }

            bool ok = define_stkvar(fn, var_name.c_str(), offset, tif);
            results.push_back({
                {"addr", addr_str}, {"name", var_name},
                {"ok", ok},
                {"error", ok ? json(nullptr) : json("define_stkvar failed")},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str}, {"name", var_name},
                {"ok", false}, {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// delete_stack
// ═══════════════════════════════════════════════════════════════════

static json tool_delete_stack(const json& params) {
    auto items = utils::normalize_dict_list(
        params.value("items", json()),
        nullptr);

    json results = json::array();
    for (const auto& item : items) {
        std::string addr_str = item.value("addr", "");
        std::string var_name = item.value("name", "");

        try {
            ea_t ea = utils::parse_address(addr_str);
            func_t* fn = get_func(ea);
            if (!fn) {
                results.push_back({
                    {"addr", addr_str}, {"name", var_name},
                    {"ok", false}, {"error", "Not a function"},
                });
                continue;
            }

            tinfo_t frame_tif;
            if (!get_func_frame(&frame_tif, fn)) {
                results.push_back({
                    {"addr", addr_str}, {"name", var_name},
                    {"ok", false}, {"error", "No stack frame found"},
                });
                continue;
            }

            // Find member by name
            udm_t udm;
            udm.name = var_name.c_str();
            int idx = frame_tif.find_udm(&udm, STRMEM_NAME);
            if (idx < 0) {
                results.push_back({
                    {"addr", addr_str}, {"name", var_name},
                    {"ok", false}, {"error", "Stack variable not found: " + var_name},
                });
                continue;
            }

            // Check if special
            tid_t member_tid = frame_tif.get_udm_tid(idx);
            if (member_tid != BADADDR && is_special_frame_member(member_tid)) {
                results.push_back({
                    {"addr", addr_str}, {"name", var_name},
                    {"ok", false}, {"error", "Cannot delete special frame member"},
                });
                continue;
            }

            // Check if function argument
            uint64_t offset_bytes = udm.offset / 8;
            if (PH.is_funcarg_off(fn, static_cast<uval_t>(offset_bytes))) {
                results.push_back({
                    {"addr", addr_str}, {"name", var_name},
                    {"ok", false}, {"error", "Cannot delete function argument"},
                });
                continue;
            }

            uint64_t size_bytes = udm.size / 8;
            bool ok = delete_frame_members(fn, static_cast<uval_t>(offset_bytes),
                                           static_cast<uval_t>(offset_bytes + size_bytes));
            results.push_back({
                {"addr", addr_str}, {"name", var_name},
                {"ok", ok},
                {"error", ok ? json(nullptr) : json("delete_frame_members failed")},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str}, {"name", var_name},
                {"ok", false}, {"error", e.what()},
            });
        }
    }
    return results;
}

#endif // !IDA_MCP_TESTING

void register_stack_tools(McpProtocol& mcp) {
#ifndef IDA_MCP_TESTING
    mcp.register_tool(
        {"stack_frame",
         "Get stack frame variables for a function",
         SchemaBuilder()
             .prop("addrs", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Function addresses"},
             })
             .build()},
        ida_sync_tool(tool_stack_frame)
    );

    mcp.register_tool(
        {"declare_stack",
         "Create stack variable in function frame",
         SchemaBuilder()
             .prop("items", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Function address"}}},
                         {"name", {{"type", "string"}, {"description", "Variable name"}}},
                         {"offset", {{"type", "integer"}, {"description", "Stack offset"}}},
                         {"type", {{"type", "string"}, {"description", "Variable type"}}},
                     }}, {"required", json::array({"addr", "name", "offset"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Function address"}}},
                         {"name", {{"type", "string"}, {"description", "Variable name"}}},
                         {"offset", {{"type", "integer"}, {"description", "Stack offset"}}},
                         {"type", {{"type", "string"}, {"description", "Variable type"}}},
                     }}, {"required", json::array({"addr", "name", "offset"})}},
                 })},
                 {"description", "Stack variable declaration(s)"},
             })
             .build()},
        ida_sync_tool(tool_declare_stack)
    );

    mcp.register_tool(
        {"delete_stack",
         "Delete stack variable from function frame",
         SchemaBuilder()
             .prop("items", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Function address"}}},
                         {"name", {{"type", "string"}, {"description", "Variable name to delete"}}},
                     }}, {"required", json::array({"addr", "name"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Function address"}}},
                         {"name", {{"type", "string"}, {"description", "Variable name to delete"}}},
                     }}, {"required", json::array({"addr", "name"})}},
                 })},
                 {"description", "Stack variable deletion(s)"},
             })
             .build()},
        ida_sync_tool(tool_delete_stack)
    );
#endif
}
