#ifndef IDA_MCP_TESTING
#include "../ida_pre.h"
#endif

#include "registry.h"
#include "../utils.h"
#include "../dialog_suppress.h"

#ifndef IDA_MCP_TESTING
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#endif

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <regex>
#include <sstream>
#include <vector>

using namespace mcp;

// ═══════════════════════════════════════════════════════════════════
// int_convert (pure math, no IDA needed)
// ═══════════════════════════════════════════════════════════════════

static json tool_int_convert(const json& params) {
    auto inputs = utils::normalize_dict_list(
        params.value("inputs", json()),
        [](const std::string& s) -> json {
            return {{"text", s}, {"size", 64}};
        });

    json results = json::array();

    for (const auto& item : inputs) {
        std::string text = item.value("text", "");
        int size = item.value("size", 0);

        // Parse the number
        int64_t value = 0;
        try {
            // Handle hex (0x), binary (0b), octal (0o), and decimal
            if (text.size() >= 2 && text[0] == '0') {
                if (text[1] == 'x' || text[1] == 'X') {
                    value = static_cast<int64_t>(std::stoull(text, nullptr, 16));
                } else if (text[1] == 'b' || text[1] == 'B') {
                    value = static_cast<int64_t>(std::stoull(text.substr(2), nullptr, 2));
                } else if (text[1] == 'o' || text[1] == 'O') {
                    value = static_cast<int64_t>(std::stoull(text.substr(2), nullptr, 8));
                } else {
                    value = static_cast<int64_t>(std::stoull(text, nullptr, 0));
                }
            } else {
                // Try decimal (may be negative)
                value = std::stoll(text, nullptr, 0);
            }
        } catch (...) {
            results.push_back({
                {"input", text},
                {"result", nullptr},
                {"error", "Invalid number: " + text},
            });
            continue;
        }

        // Determine byte size if not specified
        if (size == 0) {
            uint64_t abs_val = static_cast<uint64_t>(std::abs(value));
            int bits = 0;
            uint64_t n = abs_val;
            while (n) {
                bits++;
                n >>= 1;
            }
            size = (bits + 7) / 8;
            if (size == 0) size = 1;
        }

        // Convert to bytes (little-endian, signed)
        std::vector<uint8_t> bytes_data(size, 0);
        uint64_t uval = static_cast<uint64_t>(value);
        for (int i = 0; i < size && i < 8; ++i) {
            bytes_data[i] = static_cast<uint8_t>((uval >> (i * 8)) & 0xFF);
        }
        // Sign-extend for negative values
        if (value < 0) {
            for (int i = 8; i < size; ++i) {
                bytes_data[i] = 0xFF;
            }
        }

        // Format bytes as space-separated hex
        std::string bytes_str;
        for (size_t i = 0; i < bytes_data.size(); ++i) {
            if (i > 0) bytes_str += " ";
            char buf[4];
            qsnprintf(buf, sizeof(buf), "%02x", bytes_data[i]);
            bytes_str += buf;
        }

        // ASCII representation
        json ascii_val = nullptr;
        std::string ascii_str;
        bool valid_ascii = true;
        // Strip trailing zeros for ASCII check
        size_t end = bytes_data.size();
        while (end > 0 && bytes_data[end - 1] == 0) --end;
        for (size_t i = 0; i < end; ++i) {
            uint8_t b = bytes_data[i];
            if (b >= 32 && b <= 126) {
                ascii_str += static_cast<char>(b);
            } else {
                valid_ascii = false;
                break;
            }
        }
        if (valid_ascii && !ascii_str.empty()) {
            ascii_val = ascii_str;
        }

        // Binary representation
        std::string bin_str = "0b";
        bool started = false;
        for (int bit = 63; bit >= 0; --bit) {
            bool b = (static_cast<uint64_t>(value) >> bit) & 1;
            if (b) started = true;
            if (started) bin_str += (b ? '1' : '0');
        }
        if (!started) bin_str += '0';

        // Hex representation
        char hex_buf[32];
        if (value >= 0) {
            qsnprintf(hex_buf, sizeof(hex_buf), "0x%llx",
                      static_cast<unsigned long long>(value));
        } else {
            qsnprintf(hex_buf, sizeof(hex_buf), "-0x%llx",
                      static_cast<unsigned long long>(-value));
        }

        results.push_back({
            {"input", text},
            {"result", {
                {"decimal", std::to_string(value)},
                {"hexadecimal", std::string(hex_buf)},
                {"bytes", bytes_str},
                {"ascii", ascii_val},
                {"binary", bin_str},
            }},
            {"error", nullptr},
        });
    }

    return results;
}

#ifndef IDA_MCP_TESTING

// ═══════════════════════════════════════════════════════════════════
// IDA-dependent tools
// ═══════════════════════════════════════════════════════════════════

static json get_function_info(ea_t addr) {
    func_t* fn = get_func(addr);
    if (!fn) return nullptr;

    qstring name;
    get_func_name(&name, fn->start_ea);

    return {
        {"addr", utils::hex_str(addr)},
        {"name", name.c_str()},
        {"size", utils::hex_str(fn->end_ea - fn->start_ea)},
    };
}

static json get_function_info_optional(ea_t addr) {
    func_t* fn = get_func(addr);
    if (!fn) return nullptr;

    qstring name;
    get_func_name(&name, fn->start_ea);

    return {
        {"addr", utils::hex_str(fn->start_ea)},
        {"name", name.c_str()},
        {"size", utils::hex_str(fn->end_ea - fn->start_ea)},
    };
}

static json tool_lookup_funcs(const json& params) {
    auto queries = utils::normalize_list_input(params.value("queries", json()));

    // Handle empty/"*" as "all functions"
    if (queries.empty() || (queries.size() == 1 && (queries[0] == "*" || queries[0].empty()))) {
        json all_funcs = json::array();
        size_t count = get_func_qty();
        for (size_t i = 0; i < count && all_funcs.size() < 1000; ++i) {
            func_t* fn = getn_func(i);
            if (fn) {
                json fi = get_function_info(fn->start_ea);
                if (!fi.is_null()) {
                    all_funcs.push_back({{"query", "*"}, {"fn", fi}, {"error", nullptr}});
                }
            }
        }
        return all_funcs;
    }

    json results = json::array();
    for (const auto& query : queries) {
        try {
            ea_t ea = BADADDR;

            // Try parsing as address
            std::string q = utils::trim(query);
            if (q.size() >= 2 && (q[0] == '0' && (q[1] == 'x' || q[1] == 'X'))) {
                try { ea = utils::parse_address(q); } catch (...) {}
            }
            // Try sub_ prefix
            if (ea == BADADDR && q.size() > 4 && q.substr(0, 4) == "sub_") {
                try { ea = std::stoull(q.substr(4), nullptr, 16); } catch (...) {}
            }
            // Try name lookup
            if (ea == BADADDR) {
                ea = get_name_ea(BADADDR, q.c_str());
            }

            if (ea != BADADDR) {
                json fi = get_function_info_optional(ea);
                if (!fi.is_null()) {
                    results.push_back({{"query", query}, {"fn", fi}, {"error", nullptr}});
                } else {
                    results.push_back({{"query", query}, {"fn", nullptr}, {"error", "Not a function"}});
                }
            } else {
                results.push_back({{"query", query}, {"fn", nullptr}, {"error", "Not found"}});
            }
        } catch (const std::exception& e) {
            results.push_back({{"query", query}, {"fn", nullptr}, {"error", e.what()}});
        }
    }
    return results;
}

static json tool_list_funcs(const json& params) {
    auto queries = utils::normalize_dict_list(
        params.value("queries", json()),
        [](const std::string& s) -> json {
            return {{"offset", 0}, {"count", 50}, {"filter", s}};
        });

    // Build list of all functions
    json all_functions = json::array();
    size_t count = get_func_qty();
    for (size_t i = 0; i < count; ++i) {
        func_t* fn = getn_func(i);
        if (fn) {
            qstring name;
            get_func_name(&name, fn->start_ea);
            all_functions.push_back({
                {"addr", utils::hex_str(fn->start_ea)},
                {"name", name.c_str()},
                {"size", utils::hex_str(fn->end_ea - fn->start_ea)},
            });
        }
    }

    json results = json::array();
    for (const auto& query : queries) {
        int offset = query.value("offset", 0);
        int cnt = query.value("count", 100);
        std::string filter = query.value("filter", "");

        if (filter == "*") filter = "";

        json filtered = utils::pattern_filter(all_functions, filter, "name");
        results.push_back(utils::paginate(filtered, offset, cnt));
    }
    return results;
}

static json tool_list_globals(const json& params) {
    auto queries = utils::normalize_dict_list(
        params.value("queries", json()),
        [](const std::string& s) -> json {
            return {{"offset", 0}, {"count", 50}, {"filter", s}};
        });

    // Build list of all globals (names that are not functions)
    json all_globals = json::array();
    size_t nlist_size = get_nlist_size();
    for (size_t i = 0; i < nlist_size; ++i) {
        ea_t ea = get_nlist_ea(i);
        if (get_func(ea)) continue; // Skip function names

        const char* name = get_nlist_name(i);
        if (name) {
            all_globals.push_back({
                {"addr", utils::hex_str(ea)},
                {"name", name},
            });
        }
    }

    json results = json::array();
    for (const auto& query : queries) {
        int offset = query.value("offset", 0);
        int cnt = query.value("count", 100);
        std::string filter = query.value("filter", "");

        if (filter == "*") filter = "";

        json filtered = utils::pattern_filter(all_globals, filter, "name");
        results.push_back(utils::paginate(filtered, offset, cnt));
    }
    return results;
}

static json tool_imports(const json& params) {
    int offset = params.value("offset", 0);
    int count = params.value("count", 0);

    json all_imports = json::array();
    int nimps = get_import_module_qty();

    for (int i = 0; i < nimps; ++i) {
        qstring module_name;
        if (!get_import_module_name(&module_name, i)) {
            module_name = "<unnamed>";
        }

        struct ImportCtx {
            json* imports;
            const char* module;
        };
        ImportCtx ctx{&all_imports, module_name.c_str()};

        enum_import_names(i, [](ea_t ea, const char* name, uval_t ordinal, void* ud) -> int {
            auto* c = static_cast<ImportCtx*>(ud);
            std::string import_name;
            if (name && name[0]) {
                import_name = name;
            } else {
                import_name = "#" + std::to_string(ordinal);
            }
            c->imports->push_back({
                {"addr", utils::hex_str(ea)},
                {"imported_name", import_name},
                {"module", c->module},
            });
            return 1; // Continue enumeration
        }, &ctx);
    }

    return utils::paginate(all_imports, offset, count);
}

// ═══════════════════════════════════════════════════════════════════
// find_regex — Search strings by regex pattern
// ═══════════════════════════════════════════════════════════════════

static json tool_find_regex(const json& params) {
    idasync::SuppressDialogs suppress_guard;

    std::string pattern_str = params.value("pattern", "");
    int limit = params.value("limit", 30);
    int offset_skip = params.value("offset", 0);
    if (limit <= 0 || limit > 500) limit = 500;

    try {
        std::regex re(pattern_str, std::regex::icase | std::regex::ECMAScript);

        // Iterate all named items looking for string literals
        json matches = json::array();
        int skipped = 0;
        int total_matched = 0;
        bool more = false;

        // Iterate all segments looking for string items
        int nseg = get_segm_qty();
        for (int s = 0; s < nseg && !more; ++s) {
            segment_t* seg = getnseg(s);
            if (!seg) continue;

            ea_t ea = seg->start_ea;
            while (ea < seg->end_ea && ea != BADADDR) {
                flags64_t fl = get_flags(ea);
                if (is_strlit(fl)) {
                    qstring str_buf;
                    size_t len = get_strlit_contents(&str_buf, ea, -1, STRTYPE_C);
                    if (len > 0 && len != static_cast<size_t>(-1)) {
                        std::string str_val = str_buf.c_str();
                        if (std::regex_search(str_val, re)) {
                            total_matched++;
                            if (skipped < offset_skip) {
                                skipped++;
                            } else if (static_cast<int>(matches.size()) < limit) {
                                matches.push_back({
                                    {"addr", utils::hex_str(ea)},
                                    {"string", str_val},
                                });
                            } else {
                                more = true;
                                break;
                            }
                        }
                    }
                }
                ea = next_head(ea, seg->end_ea);
            }
        }

        json cursor = more ? json({{"next", offset_skip + limit}}) : json({{"done", true}});
        return {
            {"n", static_cast<int>(matches.size())},
            {"matches", matches},
            {"cursor", cursor},
        };
    } catch (const std::regex_error& e) {
        return {
            {"n", 0},
            {"matches", json::array()},
            {"cursor", {{"done", true}}},
            {"error", std::string("Invalid regex: ") + e.what()},
        };
    }
}

#endif // !IDA_MCP_TESTING

// ═══════════════════════════════════════════════════════════════════
// Registration
// ═══════════════════════════════════════════════════════════════════

void register_core_tools(McpProtocol& mcp) {
    // int_convert - no IDA sync needed (pure math)
    mcp.register_tool(
        {"int_convert",
         "Convert numbers to different formats",
         SchemaBuilder()
             .prop("inputs", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"text", {{"type", "string"}, {"description", "Number string to convert"}}},
                         {"size", {{"type", "integer"}, {"description", "Byte size for conversion (omit for auto)"}}},
                     }}}}},
                     {{"type", "object"}, {"properties", {
                         {"text", {{"type", "string"}, {"description", "Number string to convert"}}},
                         {"size", {{"type", "integer"}, {"description", "Byte size for conversion (omit for auto)"}}},
                     }}},
                 })},
                 {"description", "Convert numbers to various formats (hex, decimal, binary, ascii)"},
             })
             .build()},
        tool_int_convert
    );

#ifndef IDA_MCP_TESTING
    // lookup_funcs
    mcp.register_tool(
        {"lookup_funcs",
         "Get functions by address or name (auto-detects)",
         SchemaBuilder()
             .prop("queries", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Address(es) or name(s)"},
             })
             .build()},
        ida_sync_tool(tool_lookup_funcs)
    );

    // list_funcs
    mcp.register_tool(
        {"list_funcs",
         "List functions",
         SchemaBuilder()
             .prop("queries", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}}}},
                     {{"type", "object"}},
                     {{"type", "string"}},
                 })},
                 {"description", "List functions with optional filtering and pagination"},
             })
             .build()},
        ida_sync_tool(tool_list_funcs)
    );

    // list_globals
    mcp.register_tool(
        {"list_globals",
         "List globals",
         SchemaBuilder()
             .prop("queries", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}}}},
                     {{"type", "object"}},
                     {{"type", "string"}},
                 })},
                 {"description", "List global variables with optional filtering and pagination"},
             })
             .build()},
        ida_sync_tool(tool_list_globals)
    );

    // imports
    mcp.register_tool(
        {"imports",
         "List imports",
         SchemaBuilder()
             .int_prop("offset", "Offset")
             .int_prop("count", "Count (0=all)")
             .build()},
        ida_sync_tool(tool_imports)
    );

    // find_regex
    mcp.register_tool(
        {"find_regex",
         "Search strings in the database by regex pattern (case-insensitive)",
         SchemaBuilder()
             .string_prop("pattern", "Regex pattern to search for")
             .int_prop("limit", "Max matches (default: 30, max: 500)", false)
             .int_prop("offset", "Skip first N matches (default: 0)", false)
             .build()},
        ida_sync_tool(tool_find_regex, 90.0)
    );
#endif
}
