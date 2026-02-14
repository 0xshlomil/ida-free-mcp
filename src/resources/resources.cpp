#ifndef IDA_MCP_TESTING
#include "../ida_pre.h"
#endif

#include "resources.h"
#include "../sync.h"
#include "../utils.h"

#ifndef IDA_MCP_TESTING
#include <idp.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <xref.hpp>
#include <entry.hpp>
#include <name.hpp>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#endif

using namespace mcp;

#ifndef IDA_MCP_TESTING

// ═══════════════════════════════════════════════════════════════════
// ida://idb/metadata
// ═══════════════════════════════════════════════════════════════════

static json resource_idb_metadata(const std::vector<std::string>&) {
    return idasync::execute_on_main_thread([]() -> json {
        const char* idb_path = get_path(PATH_TYPE_IDB);

        char root_buf[QMAXPATH];
        get_root_filename(root_buf, sizeof(root_buf));

        ea_t base = get_imagebase();

        // Get image size
        segment_t* first_seg = nullptr;
        segment_t* last_seg = nullptr;
        int nseg = get_segm_qty();
        if (nseg > 0) {
            first_seg = getnseg(0);
            last_seg = getnseg(nseg - 1);
        }
        ea_t image_size = 0;
        if (first_seg && last_seg) {
            image_size = last_seg->end_ea - first_seg->start_ea;
        }

        // File hashes
        std::string md5 = "unavailable";
        std::string sha256 = "unavailable";
        std::string crc32_str = "unavailable";
        std::string filesize = "unavailable";

        char input_path[QMAXPATH];
        get_input_file_path(input_path, sizeof(input_path));
        (void)input_path;

        // Retrieve MD5 from IDA's metadata
        uint8_t md5_hash[16];
        if (retrieve_input_file_md5(md5_hash)) {
            char md5_str[33];
            for (int i = 0; i < 16; ++i) {
                qsnprintf(md5_str + i * 2, 3, "%02x", md5_hash[i]);
            }
            md5 = md5_str;
        }

        // Retrieve SHA256 from IDA's metadata
        uint8_t sha256_hash[32];
        if (retrieve_input_file_sha256(sha256_hash)) {
            char sha256_str[65];
            for (int i = 0; i < 32; ++i) {
                qsnprintf(sha256_str + i * 2, 3, "%02x", sha256_hash[i]);
            }
            sha256 = sha256_str;
        }

        // Retrieve CRC32 from IDA's metadata
        uint32_t crc = retrieve_input_file_crc32();
        if (crc != 0) {
            char crc_buf[16];
            qsnprintf(crc_buf, sizeof(crc_buf), "0x%08x", crc);
            crc32_str = crc_buf;
        }

        // Retrieve file size from IDA's metadata
        uint64_t fsize = retrieve_input_file_size();
        if (fsize != 0) {
            filesize = utils::hex_str(static_cast<ea_t>(fsize));
        }

        return {
            {"path", idb_path ? idb_path : ""},
            {"module", root_buf},
            {"base", utils::hex_str(base)},
            {"size", utils::hex_str(image_size)},
            {"md5", md5},
            {"sha256", sha256},
            {"crc32", crc32_str},
            {"filesize", filesize},
        };
    });
}

// ═══════════════════════════════════════════════════════════════════
// ida://idb/segments
// ═══════════════════════════════════════════════════════════════════

static json resource_idb_segments(const std::vector<std::string>&) {
    return idasync::execute_on_main_thread([]() -> json {
        json segments = json::array();
        int nseg = get_segm_qty();
        for (int i = 0; i < nseg; ++i) {
            segment_t* seg = getnseg(i);
            if (!seg) continue;

            qstring name;
            get_segm_name(&name, seg);

            std::string perms;
            if (seg->perm & SEGPERM_READ) perms += "r";
            if (seg->perm & SEGPERM_WRITE) perms += "w";
            if (seg->perm & SEGPERM_EXEC) perms += "x";
            if (perms.empty()) perms = "---";

            segments.push_back({
                {"name", name.c_str()},
                {"start", utils::hex_str(seg->start_ea)},
                {"end", utils::hex_str(seg->end_ea)},
                {"size", utils::hex_str(seg->size())},
                {"permissions", perms},
            });
        }
        return segments;
    });
}

// ═══════════════════════════════════════════════════════════════════
// ida://cursor
// ═══════════════════════════════════════════════════════════════════

static json resource_cursor(const std::vector<std::string>&) {
    return idasync::execute_on_main_thread([]() -> json {
        ea_t ea = get_screen_ea();
        json result = {{"addr", utils::hex_str(ea)}};

        func_t* func = get_func(ea);
        if (func) {
            qstring fn_name;
            get_func_name(&fn_name, func->start_ea);
            result["function"] = {
                {"addr", utils::hex_str(func->start_ea)},
                {"name", fn_name.c_str()},
            };
        }
        return result;
    });
}

// ═══════════════════════════════════════════════════════════════════
// ida://idb/entrypoints
// ═══════════════════════════════════════════════════════════════════

static json resource_entrypoints(const std::vector<std::string>&) {
    return idasync::execute_on_main_thread([]() -> json {
        json entries = json::array();
        size_t qty = get_entry_qty();
        for (size_t i = 0; i < qty; ++i) {
            uval_t ordinal = get_entry_ordinal(static_cast<int>(i));
            ea_t ea = get_entry(ordinal);
            qstring name;
            get_entry_name(&name, ordinal);
            entries.push_back({
                {"addr", utils::hex_str(ea)},
                {"name", name.c_str()},
                {"ordinal", static_cast<int>(ordinal)},
            });
        }
        return entries;
    });
}

// ═══════════════════════════════════════════════════════════════════
// ida://selection
// ═══════════════════════════════════════════════════════════════════

static json resource_selection(const std::vector<std::string>&) {
    return idasync::execute_on_main_thread([]() -> json {
        ea_t start = BADADDR, end = BADADDR;
        bool has_sel = read_range_selection(nullptr, &start, &end);
        if (has_sel && start != BADADDR) {
            return {
                {"start", utils::hex_str(start)},
                {"end", utils::hex_str(end)},
            };
        }
        return {{"selection", nullptr}};
    });
}

// ═══════════════════════════════════════════════════════════════════
// ida://types
// ═══════════════════════════════════════════════════════════════════

static json resource_types(const std::vector<std::string>&) {
    return idasync::execute_on_main_thread([]() -> json {
        json types = json::array();
        uint32_t ordinal_limit = get_ordinal_limit(nullptr);
        for (uint32_t ord = 1; ord < ordinal_limit; ++ord) {
            tinfo_t tif;
            if (!tif.get_numbered_type(nullptr, ord)) continue;

            qstring tname;
            tif.get_type_name(&tname);

            qstring type_str;
            tif.print(&type_str);

            types.push_back({
                {"ordinal", static_cast<int>(ord)},
                {"name", tname.c_str()},
                {"type", type_str.c_str()},
            });
        }
        return types;
    });
}

// ═══════════════════════════════════════════════════════════════════
// ida://structs
// ═══════════════════════════════════════════════════════════════════

static json resource_structs(const std::vector<std::string>&) {
    return idasync::execute_on_main_thread([]() -> json {
        json structs = json::array();
        uint32_t ordinal_limit = get_ordinal_limit(nullptr);
        for (uint32_t ord = 1; ord < ordinal_limit; ++ord) {
            tinfo_t tif;
            if (!tif.get_numbered_type(nullptr, ord)) continue;
            if (!tif.is_udt()) continue;

            qstring tname;
            tif.get_type_name(&tname);

            udt_type_data_t udt;
            bool is_union = false;
            if (tif.get_udt_details(&udt)) {
                is_union = udt.is_union;
            }

            structs.push_back({
                {"name", tname.c_str()},
                {"size", utils::hex_str(static_cast<ea_t>(tif.get_size()))},
                {"is_union", is_union},
            });
        }
        return structs;
    });
}

// ═══════════════════════════════════════════════════════════════════
// ida://struct/{name}
// ═══════════════════════════════════════════════════════════════════

static json resource_struct_by_name(const std::vector<std::string>& params) {
    if (params.empty()) return {{"error", "Missing struct name"}};
    std::string name = params[0];

    return idasync::execute_on_main_thread([name]() -> json {
        tinfo_t tif;
        if (!tif.get_named_type(nullptr, name.c_str())) {
            return {{"error", "Struct not found: " + name}};
        }
        if (!tif.is_udt()) {
            return {{"error", "Not a struct/union: " + name}};
        }

        udt_type_data_t udt;
        if (!tif.get_udt_details(&udt)) {
            return {{"error", "Failed to get struct details"}};
        }

        json members = json::array();
        for (size_t i = 0; i < udt.size(); ++i) {
            const udm_t& udm = udt[i];
            uint64_t offset_bytes = udm.offset / 8;
            uint64_t size_bytes = udm.size / 8;

            qstring type_str;
            udm.type.print(&type_str);

            members.push_back({
                {"name", udm.name.c_str()},
                {"offset", utils::hex_str(static_cast<ea_t>(offset_bytes))},
                {"size", utils::hex_str(static_cast<ea_t>(size_bytes))},
                {"type", type_str.c_str()},
            });
        }

        return {
            {"name", name},
            {"size", utils::hex_str(static_cast<ea_t>(tif.get_size()))},
            {"members", members},
        };
    });
}

// ═══════════════════════════════════════════════════════════════════
// ida://import/{name}
// ═══════════════════════════════════════════════════════════════════

static json resource_import_by_name(const std::vector<std::string>& params) {
    if (params.empty()) return {{"error", "Missing import name"}};
    std::string target_name = params[0];

    return idasync::execute_on_main_thread([target_name]() -> json {
        int nimps = get_import_module_qty();
        for (int i = 0; i < nimps; ++i) {
            qstring module_name;
            if (!get_import_module_name(&module_name, i)) {
                module_name = "<unnamed>";
            }

            struct ImportCtx {
                const std::string* target;
                const char* module;
                json result;
                bool found;
            };
            ImportCtx ctx{&target_name, module_name.c_str(), json(), false};

            enum_import_names(i, [](ea_t ea, const char* name, uval_t ordinal, void* ud) -> int {
                auto* c = static_cast<ImportCtx*>(ud);
                std::string import_name;
                if (name && name[0]) {
                    import_name = name;
                } else {
                    import_name = "#" + std::to_string(ordinal);
                }

                if (import_name == *c->target) {
                    c->result = {
                        {"addr", utils::hex_str(ea)},
                        {"name", import_name},
                        {"module", c->module},
                        {"ordinal", static_cast<int>(ordinal)},
                    };
                    c->found = true;
                    return 0; // Stop enumeration
                }
                return 1; // Continue
            }, &ctx);

            if (ctx.found) return ctx.result;
        }
        return {{"error", "Import not found: " + target_name}};
    });
}

// ═══════════════════════════════════════════════════════════════════
// ida://export/{name}
// ═══════════════════════════════════════════════════════════════════

static json resource_export_by_name(const std::vector<std::string>& params) {
    if (params.empty()) return {{"error", "Missing export name"}};
    std::string target_name = params[0];

    return idasync::execute_on_main_thread([target_name]() -> json {
        size_t qty = get_entry_qty();
        for (size_t i = 0; i < qty; ++i) {
            uval_t ordinal = get_entry_ordinal(static_cast<int>(i));
            ea_t ea = get_entry(ordinal);
            qstring name;
            get_entry_name(&name, ordinal);

            if (std::string(name.c_str()) == target_name) {
                return {
                    {"addr", utils::hex_str(ea)},
                    {"name", name.c_str()},
                    {"ordinal", static_cast<int>(ordinal)},
                };
            }
        }
        return {{"error", "Export not found: " + target_name}};
    });
}

// ═══════════════════════════════════════════════════════════════════
// ida://xrefs/from/{addr}
// ═══════════════════════════════════════════════════════════════════

static json resource_xrefs_from(const std::vector<std::string>& params) {
    if (params.empty()) return {{"error", "Missing address"}};
    std::string addr_str = params[0];

    return idasync::execute_on_main_thread([addr_str]() -> json {
        ea_t ea;
        try {
            ea = utils::parse_address(addr_str);
        } catch (const std::exception& e) {
            return json({{"error", e.what()}});
        }

        json xrefs = json::array();
        xrefblk_t xb;
        for (bool ok = xb.first_from(ea, XREF_ALL); ok; ok = xb.next_from()) {
            xrefs.push_back({
                {"addr", utils::hex_str(xb.to)},
                {"type", xb.iscode ? "code" : "data"},
            });
        }
        return xrefs;
    });
}

#endif // !IDA_MCP_TESTING

void register_resources(McpProtocol& mcp) {
#ifndef IDA_MCP_TESTING
    mcp.register_resource({
        "ida://idb/metadata",
        "idb_metadata_resource",
        "Get IDB file metadata (path, arch, base address, size, hashes)",
        resource_idb_metadata,
        false, // not a template
    });

    mcp.register_resource({
        "ida://idb/segments",
        "idb_segments_resource",
        "Get all memory segments with permissions",
        resource_idb_segments,
        false,
    });

    mcp.register_resource({
        "ida://cursor",
        "cursor_resource",
        "Get current cursor position and function",
        resource_cursor,
        false,
    });

    mcp.register_resource({
        "ida://idb/entrypoints",
        "entrypoints_resource",
        "Get all entry points (exports) of the binary",
        resource_entrypoints,
        false,
    });

    mcp.register_resource({
        "ida://selection",
        "selection_resource",
        "Get current selection range",
        resource_selection,
        false,
    });

    mcp.register_resource({
        "ida://types",
        "types_resource",
        "Get all types in the type library",
        resource_types,
        false,
    });

    mcp.register_resource({
        "ida://structs",
        "structs_resource",
        "Get all structures/unions in the type library",
        resource_structs,
        false,
    });

    mcp.register_resource({
        "ida://struct/{name}",
        "struct_by_name_resource",
        "Get structure definition by name",
        resource_struct_by_name,
        true, // template
    });

    mcp.register_resource({
        "ida://import/{name}",
        "import_by_name_resource",
        "Find import by name",
        resource_import_by_name,
        true,
    });

    mcp.register_resource({
        "ida://export/{name}",
        "export_by_name_resource",
        "Find export by name",
        resource_export_by_name,
        true,
    });

    mcp.register_resource({
        "ida://xrefs/from/{addr}",
        "xrefs_from_resource",
        "Get cross-references from an address",
        resource_xrefs_from,
        true,
    });
#endif
}
