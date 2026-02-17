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
#endif

#include <cstdint>
#include <cstdio>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

using namespace mcp;

#ifndef IDA_MCP_TESTING

// ═══════════════════════════════════════════════════════════════════
// get_bytes
// ═══════════════════════════════════════════════════════════════════

static json tool_get_bytes(const json& params) {
    json regions = params.value("regions", json());
    if (regions.is_object()) {
        regions = json::array({regions});
    }
    if (!regions.is_array()) {
        regions = json::array();
    }

    json results = json::array();
    for (const auto& item : regions) {
        std::string addr_str = item.value("addr", "");
        int size = item.value("size", 0);

        try {
            ea_t ea = utils::parse_address(addr_str);
            std::vector<uint8_t> buf(size);
            if (get_bytes(buf.data(), size, ea) != size) {
                results.push_back({
                    {"addr", addr_str},
                    {"data", nullptr},
                    {"error", "Failed to read bytes"},
                });
                continue;
            }

            // Format as space-separated 0xNN hex bytes
            std::string data;
            for (int i = 0; i < size; ++i) {
                if (i > 0) data += " ";
                char hex_buf[8];
                qsnprintf(hex_buf, sizeof(hex_buf), "0x%02x", buf[i]);
                data += hex_buf;
            }
            results.push_back({
                {"addr", addr_str},
                {"data", data},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str},
                {"data", nullptr},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// get_string
// ═══════════════════════════════════════════════════════════════════

static json tool_get_string(const json& params) {
    auto addrs = utils::normalize_list_input(params.value("addrs", json()));

    json results = json::array();
    for (const auto& addr_str : addrs) {
        try {
            ea_t ea = utils::parse_address(addr_str);

            qstring buf;
            size_t len = get_strlit_contents(&buf, ea, -1, STRTYPE_C);
            if (len == 0 || len == static_cast<size_t>(-1)) {
                results.push_back({
                    {"addr", addr_str},
                    {"value", nullptr},
                    {"error", "No string at address"},
                });
                continue;
            }

            results.push_back({
                {"addr", addr_str},
                {"value", buf.c_str()},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str},
                {"value", nullptr},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// Helper: parse integer type spec like "u32le", "i16be"
// ═══════════════════════════════════════════════════════════════════

struct IntTypeSpec {
    bool is_signed;
    int bits;
    bool big_endian;
};

static bool parse_int_type(const std::string& ty, IntTypeSpec& spec) {
    static const std::regex re(R"(^([iu])(8|16|32|64)(le|be)?$)", std::regex::icase);
    std::smatch m;
    if (!std::regex_match(ty, m, re)) return false;
    spec.is_signed = (m[1].str() == "i" || m[1].str() == "I");
    spec.bits = std::stoi(m[2].str());
    std::string endian = m[3].str();
    spec.big_endian = (endian == "be" || endian == "BE");
    return true;
}

static uint64_t bytes_to_uint(const uint8_t* data, int nbytes, bool big_endian) {
    uint64_t val = 0;
    if (big_endian) {
        for (int i = 0; i < nbytes; ++i)
            val = (val << 8) | data[i];
    } else {
        for (int i = nbytes - 1; i >= 0; --i)
            val = (val << 8) | data[i];
    }
    return val;
}

static void uint_to_bytes(uint64_t val, uint8_t* data, int nbytes, bool big_endian) {
    if (big_endian) {
        for (int i = nbytes - 1; i >= 0; --i) {
            data[i] = static_cast<uint8_t>(val & 0xFF);
            val >>= 8;
        }
    } else {
        for (int i = 0; i < nbytes; ++i) {
            data[i] = static_cast<uint8_t>(val & 0xFF);
            val >>= 8;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// get_int
// ═══════════════════════════════════════════════════════════════════

static json tool_get_int(const json& params) {
    auto queries = utils::normalize_dict_list(
        params.value("queries", json()),
        [](const std::string& s) -> json {
            return {{"addr", s}, {"ty", "u64le"}};
        });

    json results = json::array();
    for (const auto& item : queries) {
        std::string addr_str = item.value("addr", "");
        std::string ty = item.value("ty", "u64le");

        try {
            IntTypeSpec spec;
            if (!parse_int_type(ty, spec)) {
                results.push_back({
                    {"addr", addr_str}, {"ty", ty},
                    {"value", nullptr}, {"error", "Invalid type: " + ty},
                });
                continue;
            }

            ea_t ea = utils::parse_address(addr_str);
            int nbytes = spec.bits / 8;
            std::vector<uint8_t> buf(nbytes);
            if (get_bytes(buf.data(), nbytes, ea) != nbytes) {
                results.push_back({
                    {"addr", addr_str}, {"ty", ty},
                    {"value", nullptr}, {"error", "Failed to read bytes"},
                });
                continue;
            }

            uint64_t uval = bytes_to_uint(buf.data(), nbytes, spec.big_endian);
            int64_t sval = static_cast<int64_t>(uval);
            // Sign-extend if needed
            if (spec.is_signed && spec.bits < 64) {
                uint64_t sign_bit = 1ULL << (spec.bits - 1);
                if (uval & sign_bit) {
                    sval = static_cast<int64_t>(uval | (~0ULL << spec.bits));
                }
            }

            json value;
            if (spec.is_signed) {
                value = sval;
            } else {
                // JSON doesn't support unsigned 64-bit natively; use int64 if it fits
                if (uval <= static_cast<uint64_t>(INT64_MAX)) {
                    value = static_cast<int64_t>(uval);
                } else {
                    // Return as string for values > INT64_MAX
                    char buf[32];
                    qsnprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(uval));
                    value = std::string(buf);
                }
            }

            results.push_back({
                {"addr", addr_str}, {"ty", ty},
                {"value", value}, {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str}, {"ty", ty},
                {"value", nullptr}, {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// get_global_value
// ═══════════════════════════════════════════════════════════════════

static json get_global_variable_value(ea_t ea) {
    // Try to get type info
    tinfo_t tif;
    bool has_type = get_tinfo(&tif, ea);

    // Check for string first
    qstring str_buf;
    size_t str_len = get_strlit_contents(&str_buf, ea, -1, STRTYPE_C);
    if (str_len > 0 && str_len != static_cast<size_t>(-1)) {
        return json(str_buf.c_str());
    }

    // Determine size
    asize_t item_size = 0;
    if (has_type) {
        item_size = static_cast<asize_t>(tif.get_size());
    }
    if (item_size == 0) {
        item_size = get_item_size(ea);
    }
    if (item_size == 0) item_size = 1;

    // Read and format based on size
    char hex_buf[32];
    switch (item_size) {
        case 1: qsnprintf(hex_buf, sizeof(hex_buf), "0x%02x", get_byte(ea)); break;
        case 2: qsnprintf(hex_buf, sizeof(hex_buf), "0x%04x", get_word(ea)); break;
        case 4: qsnprintf(hex_buf, sizeof(hex_buf), "0x%08x", static_cast<uint32_t>(get_dword(ea))); break;
        case 8: qsnprintf(hex_buf, sizeof(hex_buf), "0x%016llx",
                          static_cast<unsigned long long>(get_qword(ea))); break;
        default: {
            // Read raw bytes
            std::vector<uint8_t> buf(item_size);
            if (get_bytes(buf.data(), item_size, ea) == item_size) {
                std::string data;
                for (asize_t i = 0; i < item_size; ++i) {
                    if (i > 0) data += " ";
                    char b[8];
                    qsnprintf(b, sizeof(b), "0x%02x", buf[i]);
                    data += b;
                }
                return json(data);
            }
            return json("0x??");
        }
    }
    return json(std::string(hex_buf));
}

static json tool_get_global_value(const json& params) {
    auto queries = utils::normalize_list_input(params.value("queries", json()));

    json results = json::array();
    for (const auto& query : queries) {
        try {
            ea_t ea = BADADDR;

            // Try as address first
            std::string q = utils::trim(query);
            if (q.size() >= 2 && q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) {
                try { ea = utils::parse_address(q); } catch (...) {}
            }
            // Try as name
            if (ea == BADADDR) {
                ea = get_name_ea(BADADDR, q.c_str());
            }
            // Try as decimal
            if (ea == BADADDR) {
                try { ea = utils::parse_address(q); } catch (...) {}
            }

            if (ea == BADADDR) {
                results.push_back({
                    {"query", query}, {"value", nullptr},
                    {"error", "Not found: " + query},
                });
                continue;
            }

            json value = get_global_variable_value(ea);
            results.push_back({
                {"query", query}, {"value", value}, {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"query", query}, {"value", nullptr}, {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// patch
// ═══════════════════════════════════════════════════════════════════

static json tool_patch(const json& params) {
    auto patches = utils::normalize_dict_list(
        params.value("patches", json()),
        nullptr);

    json results = json::array();
    for (const auto& item : patches) {
        std::string addr_str = item.value("addr", "");
        std::string data_hex = item.value("data", "");

        try {
            ea_t ea = utils::parse_address(addr_str);

            // Parse hex string (space-separated or continuous)
            std::string clean;
            for (char c : data_hex) {
                if (c != ' ' && c != '\t') clean += c;
            }
            if (clean.size() % 2 != 0) {
                results.push_back({
                    {"addr", addr_str}, {"size", 0},
                    {"ok", false}, {"error", "Odd number of hex digits"},
                });
                continue;
            }

            std::vector<uint8_t> bytes;
            for (size_t i = 0; i < clean.size(); i += 2) {
                unsigned int byte_val;
                if (sscanf(clean.c_str() + i, "%02x", &byte_val) != 1) {
                    throw std::runtime_error("Invalid hex data at position " + std::to_string(i));
                }
                bytes.push_back(static_cast<uint8_t>(byte_val));
            }

            patch_bytes(ea, bytes.data(), bytes.size());

            results.push_back({
                {"addr", addr_str},
                {"size", static_cast<int>(bytes.size())},
                {"ok", true},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str}, {"size", 0},
                {"ok", false}, {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// put_int
// ═══════════════════════════════════════════════════════════════════

static json tool_put_int(const json& params) {
    auto items = utils::normalize_dict_list(
        params.value("items", json()),
        nullptr);

    json results = json::array();
    for (const auto& item : items) {
        std::string addr_str = item.value("addr", "");
        std::string ty = item.value("ty", "u32le");
        std::string value_str;
        if (item.contains("value")) {
            if (item["value"].is_string()) {
                value_str = item["value"].get<std::string>();
            } else {
                value_str = item["value"].dump();
            }
        }

        try {
            IntTypeSpec spec;
            if (!parse_int_type(ty, spec)) {
                results.push_back({
                    {"addr", addr_str}, {"ty", ty}, {"value", value_str},
                    {"ok", false}, {"error", "Invalid type: " + ty},
                });
                continue;
            }

            ea_t ea = utils::parse_address(addr_str);
            int nbytes = spec.bits / 8;

            // Parse value
            int64_t sval = std::stoll(value_str, nullptr, 0);
            uint64_t uval = static_cast<uint64_t>(sval);

            // Convert to bytes
            std::vector<uint8_t> buf(nbytes);
            uint_to_bytes(uval, buf.data(), nbytes, spec.big_endian);

            patch_bytes(ea, buf.data(), buf.size());

            results.push_back({
                {"addr", addr_str}, {"ty", ty}, {"value", value_str},
                {"ok", true}, {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str}, {"ty", ty}, {"value", value_str},
                {"ok", false}, {"error", e.what()},
            });
        }
    }
    return results;
}

#endif // !IDA_MCP_TESTING

void register_memory_tools(McpProtocol& mcp) {
#ifndef IDA_MCP_TESTING
    mcp.register_tool(
        {"get_bytes",
         "Read bytes from memory addresses",
         SchemaBuilder()
             .prop("regions", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to read from (hex or decimal)"}}},
                         {"size", {{"type", "integer"}, {"description", "Number of bytes to read"}}},
                     }}, {"required", json::array({"addr", "size"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to read from (hex or decimal)"}}},
                         {"size", {{"type", "integer"}, {"description", "Number of bytes to read"}}},
                     }}, {"required", json::array({"addr", "size"})}},
                 })},
                 {"description", "Memory read request(s)"},
             })
             .build()},
        ida_sync_tool(tool_get_bytes)
    );

    mcp.register_tool(
        {"get_string",
         "Read strings from memory addresses",
         SchemaBuilder()
             .prop("addrs", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Addresses to read strings from"},
             })
             .build()},
        ida_sync_tool(tool_get_string)
    );

    mcp.register_tool(
        {"get_int",
         "Read integer values from memory with type specification",
         SchemaBuilder()
             .prop("queries", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to read from"}}},
                         {"ty", {{"type", "string"}, {"description", "Type: [u|i][8|16|32|64][le|be] e.g. u32le, i16be"}}},
                     }}, {"required", json::array({"addr", "ty"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to read from"}}},
                         {"ty", {{"type", "string"}, {"description", "Type: [u|i][8|16|32|64][le|be] e.g. u32le, i16be"}}},
                     }}, {"required", json::array({"addr", "ty"})}},
                 })},
                 {"description", "Integer read request(s)"},
             })
             .build()},
        ida_sync_tool(tool_get_int)
    );

    mcp.register_tool(
        {"get_global_value",
         "Read global variable values by name or address",
         SchemaBuilder()
             .prop("queries", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Global variable names or addresses"},
             })
             .build()},
        ida_sync_tool(tool_get_global_value)
    );

    mcp.register_tool(
        {"patch",
         "Patch bytes in memory",
         SchemaBuilder()
             .prop("patches", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to patch"}}},
                         {"data", {{"type", "string"}, {"description", "Hex bytes to write (e.g. '90 90 90')"}}},
                     }}, {"required", json::array({"addr", "data"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to patch"}}},
                         {"data", {{"type", "string"}, {"description", "Hex bytes to write (e.g. '90 90 90')"}}},
                     }}, {"required", json::array({"addr", "data"})}},
                 })},
                 {"description", "Patch operation(s)"},
             })
             .build()},
        ida_sync_tool(tool_patch)
    );

    mcp.register_tool(
        {"put_int",
         "Write integer values to memory",
         SchemaBuilder()
             .prop("items", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to write to"}}},
                         {"ty", {{"type", "string"}, {"description", "Type: [u|i][8|16|32|64][le|be]"}}},
                         {"value", {{"type", {"string", "integer"}}, {"description", "Integer value to write (string or number)"}}},
                     }}, {"required", json::array({"addr", "ty", "value"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"addr", {{"type", "string"}, {"description", "Address to write to"}}},
                         {"ty", {{"type", "string"}, {"description", "Type: [u|i][8|16|32|64][le|be]"}}},
                         {"value", {{"type", {"string", "integer"}}, {"description", "Integer value to write (string or number)"}}},
                     }}, {"required", json::array({"addr", "ty", "value"})}},
                 })},
                 {"description", "Integer write operation(s)"},
             })
             .build()},
        ida_sync_tool(tool_put_int)
    );
#endif
}
