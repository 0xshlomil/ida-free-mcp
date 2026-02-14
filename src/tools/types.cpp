#ifndef IDA_MCP_TESTING
#include "../ida_pre.h"
#endif

#include "registry.h"
#include "../utils.h"

#ifndef IDA_MCP_TESTING
#include <idp.hpp>
#include <bytes.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <typeinf.hpp>
#include <funcs.hpp>
#include <frame.hpp>
#endif

#include <string>
#include <vector>

using namespace mcp;

#ifndef IDA_MCP_TESTING

// ═══════════════════════════════════════════════════════════════════
// declare_type
// ═══════════════════════════════════════════════════════════════════

static json tool_declare_type(const json& params) {
    auto decls = utils::normalize_list_input(params.value("decls", json()));

    json results = json::array();
    for (const auto& decl : decls) {
        try {
            // parse_decls returns 0 on success, or number of errors
            int nerrors = parse_decls(nullptr, decl.c_str(), nullptr, HTI_DCL);

            if (nerrors == 0) {
                results.push_back({
                    {"decl", decl},
                    {"ok", true},
                    {"error", nullptr},
                });
            } else {
                results.push_back({
                    {"decl", decl},
                    {"ok", false},
                    {"error", "Parse failed with " + std::to_string(nerrors) + " error(s)"},
                });
            }
        } catch (const std::exception& e) {
            results.push_back({
                {"decl", decl},
                {"ok", false},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// read_struct
// ═══════════════════════════════════════════════════════════════════

static json tool_read_struct(const json& params) {
    auto queries = utils::normalize_dict_list(
        params.value("queries", json()),
        nullptr);

    json results = json::array();
    for (const auto& query : queries) {
        std::string addr_str = query.value("addr", "");
        std::string struct_name = query.value("struct", "");

        try {
            ea_t ea = BADADDR;
            if (!addr_str.empty()) {
                ea = utils::parse_address(addr_str);
            }

            // Auto-detect struct from type info if not specified
            if (struct_name.empty() && ea != BADADDR) {
                tinfo_t addr_tif;
                if (get_tinfo(&addr_tif, ea)) {
                    // If it's a pointer, dereference
                    if (addr_tif.is_ptr()) {
                        addr_tif = addr_tif.get_pointed_object();
                    }
                    if (addr_tif.is_udt()) {
                        qstring tname;
                        addr_tif.get_type_name(&tname);
                        struct_name = tname.c_str();
                    }
                }
            }

            if (struct_name.empty()) {
                results.push_back({
                    {"addr", addr_str}, {"struct", nullptr},
                    {"members", nullptr},
                    {"error", "No struct name provided and could not auto-detect"},
                });
                continue;
            }

            tinfo_t tif;
            if (!tif.get_named_type(nullptr, struct_name.c_str())) {
                results.push_back({
                    {"addr", addr_str}, {"struct", struct_name},
                    {"members", nullptr},
                    {"error", "Struct not found: " + struct_name},
                });
                continue;
            }

            if (!tif.is_udt()) {
                results.push_back({
                    {"addr", addr_str}, {"struct", struct_name},
                    {"members", nullptr},
                    {"error", "Not a struct/union: " + struct_name},
                });
                continue;
            }

            udt_type_data_t udt;
            if (!tif.get_udt_details(&udt)) {
                results.push_back({
                    {"addr", addr_str}, {"struct", struct_name},
                    {"members", nullptr},
                    {"error", "Failed to get struct details"},
                });
                continue;
            }

            json members = json::array();
            for (size_t i = 0; i < udt.size(); ++i) {
                const udm_t& udm = udt[i];
                uint64_t offset_bytes = udm.offset / 8;
                uint64_t size_bytes = udm.size / 8;

                qstring type_str;
                udm.type.print(&type_str);

                json member = {
                    {"offset", utils::hex_str(static_cast<ea_t>(offset_bytes))},
                    {"type", type_str.c_str()},
                    {"name", udm.name.c_str()},
                    {"size", static_cast<int>(size_bytes)},
                };

                // Read actual value if address provided
                if (ea != BADADDR) {
                    ea_t member_ea = ea + offset_bytes;
                    if (size_bytes == 0) {
                        member["value"] = "0x0";
                    } else if (udm.type.is_ptr()) {
                        bool is_64 = inf_is_64bit();
                        if (is_64) {
                            char buf[32];
                            qsnprintf(buf, sizeof(buf), "0x%016llx",
                                      static_cast<unsigned long long>(get_qword(member_ea)));
                            member["value"] = buf;
                        } else {
                            char buf[16];
                            qsnprintf(buf, sizeof(buf), "0x%08x",
                                      static_cast<uint32_t>(get_dword(member_ea)));
                            member["value"] = buf;
                        }
                    } else if (size_bytes <= 8) {
                        uint64_t val = 0;
                        switch (size_bytes) {
                            case 1: val = get_byte(member_ea); break;
                            case 2: val = get_word(member_ea); break;
                            case 4: val = get_dword(member_ea); break;
                            case 8: val = get_qword(member_ea); break;
                            default: {
                                std::vector<uint8_t> buf(size_bytes);
                                get_bytes(buf.data(), size_bytes, member_ea);
                                for (int b = static_cast<int>(size_bytes) - 1; b >= 0; --b)
                                    val = (val << 8) | buf[b];
                                break;
                            }
                        }
                        char buf[64];
                        switch (size_bytes) {
                            case 1: qsnprintf(buf, sizeof(buf), "0x%02x (%llu)", static_cast<uint8_t>(val), static_cast<unsigned long long>(val)); break;
                            case 2: qsnprintf(buf, sizeof(buf), "0x%04x (%llu)", static_cast<uint16_t>(val), static_cast<unsigned long long>(val)); break;
                            case 4: qsnprintf(buf, sizeof(buf), "0x%08x (%llu)", static_cast<uint32_t>(val), static_cast<unsigned long long>(val)); break;
                            case 8: qsnprintf(buf, sizeof(buf), "0x%016llx (%llu)", static_cast<unsigned long long>(val), static_cast<unsigned long long>(val)); break;
                            default: qsnprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(val)); break;
                        }
                        member["value"] = buf;
                    } else {
                        // Large field: hex dump
                        size_t show = std::min(size_bytes, static_cast<uint64_t>(16));
                        std::vector<uint8_t> buf(show);
                        get_bytes(buf.data(), show, member_ea);
                        std::string hex;
                        for (size_t b = 0; b < show; ++b) {
                            if (b > 0) hex += " ";
                            char hb[4];
                            qsnprintf(hb, sizeof(hb), "%02X", buf[b]);
                            hex += hb;
                        }
                        if (size_bytes > 16) hex += "...";
                        member["value"] = "[" + hex + "]";
                    }
                }

                members.push_back(member);
            }

            results.push_back({
                {"addr", addr_str.empty() ? json(nullptr) : json(addr_str)},
                {"struct", struct_name},
                {"members", members},
                {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str}, {"struct", struct_name},
                {"members", nullptr}, {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// search_structs
// ═══════════════════════════════════════════════════════════════════

static json tool_search_structs(const json& params) {
    std::string filter = params.value("filter", "");
    std::string filter_lower = utils::to_lower(filter);

    json results = json::array();
    uint32_t ordinal_limit = get_ordinal_limit(nullptr);

    for (uint32_t ord = 1; ord < ordinal_limit; ++ord) {
        tinfo_t tif;
        if (!tif.get_numbered_type(nullptr, ord)) continue;
        if (!tif.is_udt()) continue;

        qstring tname;
        tif.get_type_name(&tname);
        std::string name = tname.c_str();

        // Apply filter
        if (!filter.empty()) {
            std::string name_lower = utils::to_lower(name);
            if (name_lower.find(filter_lower) == std::string::npos) continue;
        }

        udt_type_data_t udt;
        bool is_union = false;
        int cardinality = 0;
        if (tif.get_udt_details(&udt)) {
            is_union = udt.is_union;
            cardinality = static_cast<int>(udt.size());
        }

        results.push_back({
            {"name", name},
            {"size", static_cast<int>(tif.get_size())},
            {"cardinality", cardinality},
            {"is_union", is_union},
            {"ordinal", static_cast<int>(ord)},
        });
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// set_type
// ═══════════════════════════════════════════════════════════════════

static json tool_set_type(const json& params) {
    auto edits = utils::normalize_dict_list(
        params.value("edits", json()),
        nullptr);

    json results = json::array();
    for (const auto& edit : edits) {
        try {
            std::string addr_str = edit.value("addr", "");
            std::string type_str = edit.value("type", "");
            // Also accept "signature" for function types
            if (type_str.empty()) {
                type_str = edit.value("signature", "");
            }
            std::string kind = edit.value("kind", "");
            std::string var_name = edit.value("name", "");

            if (type_str.empty()) {
                results.push_back({
                    {"edit", edit}, {"ok", false},
                    {"error", "No type/signature provided"},
                });
                continue;
            }

            ea_t ea = utils::parse_address(addr_str);

            // Parse type string
            tinfo_t tif;
            if (!tif.get_named_type(nullptr, type_str.c_str())) {
                // Try parsing as C declaration
                qstring parsed_name;
                if (!parse_decl(&tif, &parsed_name, nullptr, type_str.c_str(), PT_SIL)) {
                    results.push_back({
                        {"edit", edit}, {"ok", false},
                        {"error", "Failed to parse type: " + type_str},
                    });
                    continue;
                }
            }

            // Auto-detect kind
            if (kind.empty()) {
                if (tif.is_func()) {
                    kind = "function";
                } else if (!var_name.empty()) {
                    kind = "stack"; // If name given, assume stack var
                } else {
                    kind = "global";
                }
            }

            if (kind == "function" || kind == "global") {
                bool ok = apply_tinfo(ea, tif, TINFO_DEFINITE);
                results.push_back({
                    {"edit", edit},
                    {"ok", ok},
                    {"error", ok ? json(nullptr) : json("apply_tinfo failed")},
                });
            } else if (kind == "stack") {
                // Set stack variable type
                func_t* fn = get_func(ea);
                if (!fn) {
                    results.push_back({
                        {"edit", edit}, {"ok", false},
                        {"error", "Not a function at " + addr_str},
                    });
                    continue;
                }

                tinfo_t frame_tif;
                if (!get_func_frame(&frame_tif, fn)) {
                    results.push_back({
                        {"edit", edit}, {"ok", false},
                        {"error", "No stack frame found"},
                    });
                    continue;
                }

                udm_t udm;
                udm.name = var_name.c_str();
                int idx = frame_tif.find_udm(&udm, STRMEM_NAME);
                if (idx < 0) {
                    results.push_back({
                        {"edit", edit}, {"ok", false},
                        {"error", "Stack variable not found: " + var_name},
                    });
                    continue;
                }

                tid_t member_tid = frame_tif.get_udm_tid(idx);
                if (member_tid == BADADDR) {
                    results.push_back({
                        {"edit", edit}, {"ok", false},
                        {"error", "Could not get TID for stack variable"},
                    });
                    continue;
                }

                bool ok = set_frame_member_type(fn, udm.offset / 8, tif);
                results.push_back({
                    {"edit", edit},
                    {"ok", ok},
                    {"error", ok ? json(nullptr) : json("set_frame_member_type failed")},
                });
            } else {
                results.push_back({
                    {"edit", edit}, {"ok", false},
                    {"error", "Unsupported kind: " + kind},
                });
            }
        } catch (const std::exception& e) {
            results.push_back({
                {"edit", edit}, {"ok", false}, {"error", e.what()},
            });
        }
    }
    return results;
}

#endif // !IDA_MCP_TESTING

void register_type_tools(McpProtocol& mcp) {
#ifndef IDA_MCP_TESTING
    mcp.register_tool(
        {"declare_type",
         "Parse C type declarations and add them to the type library",
         SchemaBuilder()
             .prop("decls", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "C type declaration(s) to parse"},
             })
             .build()},
        ida_sync_tool(tool_declare_type)
    );

    mcp.register_tool(
        {"read_struct",
         "Read structure definition with optional memory values",
         SchemaBuilder()
             .prop("queries", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Memory address to read values from (optional)"}}},
                         {"struct", {{"type", "string"}, {"description", "Structure name (auto-detected if omitted)"}}},
                     }}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Memory address to read values from (optional)"}}},
                         {"struct", {{"type", "string"}, {"description", "Structure name (auto-detected if omitted)"}}},
                     }}},
                 })},
                 {"description", "Structure read request(s)"},
             })
             .build()},
        ida_sync_tool(tool_read_struct)
    );

    mcp.register_tool(
        {"search_structs",
         "Search structures by name (case-insensitive substring match)",
         SchemaBuilder()
             .string_prop("filter", "Filter string for struct names")
             .build()},
        ida_sync_tool(tool_search_structs)
    );

    mcp.register_tool(
        {"set_type",
         "Apply type to function, global, or stack variable",
         SchemaBuilder()
             .prop("edits", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address of function/global"}}},
                         {"type", {{"type", "string"}, {"description", "Type string or C declaration"}}},
                         {"signature", {{"type", "string"}, {"description", "Function signature (alternative to type)"}}},
                         {"kind", {{"type", "string"}, {"description", "Kind: function, global, or stack (auto-detected)"}}},
                         {"name", {{"type", "string"}, {"description", "Variable name (for stack vars)"}}},
                     }}, {"required", json::array({"addr"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address of function/global"}}},
                         {"type", {{"type", "string"}, {"description", "Type string or C declaration"}}},
                         {"signature", {{"type", "string"}, {"description", "Function signature (alternative to type)"}}},
                         {"kind", {{"type", "string"}, {"description", "Kind: function, global, or stack (auto-detected)"}}},
                         {"name", {{"type", "string"}, {"description", "Variable name (for stack vars)"}}},
                     }}, {"required", json::array({"addr"})}},
                 })},
                 {"description", "Type application operation(s)"},
             })
             .build()},
        ida_sync_tool(tool_set_type)
    );
#endif
}
