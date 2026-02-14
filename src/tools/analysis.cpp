#ifndef IDA_MCP_TESTING
#include "../ida_pre.h"
#endif

#include "registry.h"
#include "../utils.h"

#ifndef IDA_MCP_TESTING
#include <idp.hpp>
#include <funcs.hpp>
#include <name.hpp>
#include <nalt.hpp>
#include <bytes.hpp>
#include <lines.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include <gdl.hpp>
#include <search.hpp>
#endif

#include <algorithm>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace mcp;

#ifndef IDA_MCP_TESTING

// ═══════════════════════════════════════════════════════════════════
// Helper: get function info as JSON
// ═══════════════════════════════════════════════════════════════════

static json get_func_info_optional(ea_t addr) {
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

// ═══════════════════════════════════════════════════════════════════
// disasm
// ═══════════════════════════════════════════════════════════════════

static json tool_disasm(const json& params) {
    std::string addr_str = params.value("addr", "");
    int max_instructions = params.value("max_instructions", 5000);
    int offset = params.value("offset", 0);
    bool include_total = params.value("include_total", false);

    // Enforce limits
    if (max_instructions <= 0 || max_instructions > 50000)
        max_instructions = 50000;
    if (offset < 0) offset = 0;

    try {
        ea_t start = utils::parse_address(addr_str);
        func_t* func = get_func(start);

        // Get segment info
        segment_t* seg = getseg(start);
        if (!seg) {
            return {
                {"addr", addr_str},
                {"asm", nullptr},
                {"error", "No segment found"},
                {"cursor", {{"done", true}}},
            };
        }

        qstring seg_name;
        get_segm_name(&seg_name, seg);
        std::string segment_name = seg_name.c_str();

        std::string func_name;
        ea_t header_addr = start;

        if (func) {
            qstring fn_name;
            get_func_name(&fn_name, func->start_ea);
            func_name = fn_name.c_str();
            if (func_name.empty()) func_name = "<unnamed>";
        } else {
            func_name = "<no function>";
        }

        // Collect disassembly lines
        std::vector<std::string> lines;
        int seen = 0;
        int total_count = 0;
        bool more = false;

        auto maybe_add = [&](ea_t ea) -> bool {
            if (include_total) total_count++;
            if (seen < offset) {
                seen++;
                return true;
            }
            if (static_cast<int>(lines.size()) < max_instructions) {
                qstring disasm_line;
                generate_disasm_line(&disasm_line, ea, 0);
                qstring clean;
                tag_remove(&clean, disasm_line);

                char addr_buf[32];
                qsnprintf(addr_buf, sizeof(addr_buf), "%llx",
                          static_cast<unsigned long long>(ea));
                lines.push_back(std::string(addr_buf) + "  " + clean.c_str());
                seen++;
                return true;
            }
            more = true;
            seen++;
            return include_total;
        };

        if (func) {
            // Iterate function items
            ea_t ea = func->start_ea;
            ea_t end_ea = func->end_ea;
            while (ea < end_ea && ea != BADADDR) {
                if (ea >= start) {
                    if (!maybe_add(ea)) break;
                }
                ea = next_head(ea, end_ea);
            }
        } else {
            // Sequential disassembly
            ea_t ea = start;
            while (ea < seg->end_ea && ea != BADADDR) {
                insn_t insn;
                if (decode_insn(&insn, ea) == 0) break;
                if (!maybe_add(ea)) break;
                ea = next_head(ea, seg->end_ea);
                if (ea == BADADDR) break;
            }
        }

        if (include_total && !more) {
            more = total_count > offset + max_instructions;
        }

        // Build lines string
        std::string lines_str = func_name + " (" + segment_name + " @ " +
                                utils::hex_str(header_addr) + "):";
        for (const auto& line : lines) {
            lines_str += "\n" + line;
        }

        // Build result
        json asm_obj = {
            {"name", func_name},
            {"start_ea", utils::hex_str(header_addr)},
            {"lines", lines_str},
        };

        // Function type info
        if (func) {
            tinfo_t tif;
            if (get_tinfo(&tif, func->start_ea) && tif.is_func()) {
                func_type_data_t ftd;
                if (tif.get_func_details(&ftd)) {
                    qstring rettype_str;
                    ftd.rettype.print(&rettype_str);
                    asm_obj["return_type"] = rettype_str.c_str();

                    json args = json::array();
                    for (size_t i = 0; i < ftd.size(); ++i) {
                        qstring type_str;
                        ftd[i].type.print(&type_str);
                        std::string arg_name = ftd[i].name.c_str();
                        if (arg_name.empty()) {
                            arg_name = "arg" + std::to_string(i);
                        }
                        args.push_back({
                            {"name", arg_name},
                            {"type", type_str.c_str()},
                        });
                    }
                    asm_obj["arguments"] = args;
                }
            }
        }

        return {
            {"addr", addr_str},
            {"asm", asm_obj},
            {"instruction_count", static_cast<int>(lines.size())},
            {"total_instructions", include_total ? json(total_count) : json(nullptr)},
            {"cursor", more ? json({{"next", offset + max_instructions}})
                            : json({{"done", true}})},
        };
    } catch (const std::exception& e) {
        return {
            {"addr", addr_str},
            {"asm", nullptr},
            {"error", e.what()},
            {"cursor", {{"done", true}}},
        };
    }
}

// ═══════════════════════════════════════════════════════════════════
// xrefs_to
// ═══════════════════════════════════════════════════════════════════

static json tool_xrefs_to(const json& params) {
    auto addrs = utils::normalize_list_input(params.value("addrs", json()));
    int limit = params.value("limit", 100);

    if (limit <= 0 || limit > 1000) limit = 1000;

    json results = json::array();
    for (const auto& addr_str : addrs) {
        try {
            ea_t ea = utils::parse_address(addr_str);
            json xrefs = json::array();
            bool more_flag = false;

            xrefblk_t xb;
            for (bool ok = xb.first_to(ea, XREF_ALL); ok; ok = xb.next_to()) {
                if (static_cast<int>(xrefs.size()) >= limit) {
                    more_flag = true;
                    break;
                }
                xrefs.push_back({
                    {"addr", utils::hex_str(xb.from)},
                    {"type", xb.iscode ? "code" : "data"},
                    {"fn", get_func_info_optional(xb.from)},
                });
            }

            results.push_back({
                {"addr", addr_str},
                {"xrefs", xrefs},
                {"more", more_flag},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str},
                {"xrefs", nullptr},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// callees
// ═══════════════════════════════════════════════════════════════════

static json tool_callees(const json& params) {
    auto addrs = utils::normalize_list_input(params.value("addrs", json()));
    int limit = params.value("limit", 200);
    if (limit <= 0 || limit > 500) limit = 500;

    json results = json::array();
    for (const auto& addr_str : addrs) {
        try {
            ea_t ea = utils::parse_address(addr_str);
            func_t* fn = get_func(ea);
            if (!fn) {
                results.push_back({
                    {"addr", addr_str}, {"callees", nullptr},
                    {"more", false}, {"error", "Not a function"},
                });
                continue;
            }

            json callees_arr = json::array();
            std::set<ea_t> seen;
            bool more_flag = false;

            ea_t cur = fn->start_ea;
            while (cur < fn->end_ea && cur != BADADDR) {
                insn_t insn;
                if (decode_insn(&insn, cur) > 0) {
                    if (is_call_insn(insn)) {
                        ea_t target = BADADDR;
                        // Extract call target from first operand
                        const op_t& op = insn.ops[0];
                        if (op.type == o_near || op.type == o_far) {
                            target = op.addr;
                        } else if (op.type == o_mem) {
                            target = op.addr;
                        }

                        if (target != BADADDR && seen.find(target) == seen.end()) {
                            seen.insert(target);
                            if (static_cast<int>(callees_arr.size()) >= limit) {
                                more_flag = true;
                            } else {
                                qstring callee_name;
                                get_name(&callee_name, target);
                                func_t* callee_fn = get_func(target);
                                std::string type_str = callee_fn ? "internal" : "external";

                                callees_arr.push_back({
                                    {"addr", utils::hex_str(target)},
                                    {"name", callee_name.c_str()},
                                    {"type", type_str},
                                });
                            }
                        }
                    }
                }
                cur = next_head(cur, fn->end_ea);
            }

            results.push_back({
                {"addr", addr_str},
                {"callees", callees_arr},
                {"more", more_flag},
                {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str}, {"callees", nullptr},
                {"more", false}, {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// find_bytes
// ═══════════════════════════════════════════════════════════════════

static json tool_find_bytes(const json& params) {
    auto patterns = utils::normalize_list_input(params.value("patterns", json()));
    int limit = params.value("limit", 1000);
    int offset_skip = params.value("offset", 0);
    if (limit <= 0 || limit > 10000) limit = 10000;

    ea_t min_ea = inf_get_min_ea();
    ea_t max_ea = inf_get_max_ea();

    json results = json::array();
    for (const auto& pattern : patterns) {
        try {
            // Normalize pattern: replace ?? with ? for IDA's find_bytes
            std::string normalized;
            auto tokens = utils::split(pattern, ' ');
            for (size_t i = 0; i < tokens.size(); ++i) {
                std::string tok = utils::trim(tokens[i]);
                if (tok.empty()) continue;
                if (!normalized.empty()) normalized += " ";
                if (tok == "??" || tok == "?") {
                    normalized += "?";
                } else {
                    normalized += tok;
                }
            }

            json matches = json::array();
            int skipped = 0;
            bool more = false;

            compiled_binpat_vec_t bv;
            if (!parse_binpat_str(&bv, min_ea, normalized.c_str(), 16)) {
                results.push_back({
                    {"pattern", pattern},
                    {"matches", json::array()},
                    {"n", 0},
                    {"cursor", {{"done", true}}},
                    {"error", "Invalid byte pattern"},
                });
                continue;
            }

            ea_t ea = min_ea;
            while (ea < max_ea && ea != BADADDR) {
                ea = bin_search(ea, max_ea, bv, BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW);
                if (ea == BADADDR) break;

                if (skipped < offset_skip) {
                    skipped++;
                } else if (static_cast<int>(matches.size()) < limit) {
                    matches.push_back(utils::hex_str(ea));
                } else {
                    more = true;
                    break;
                }
                ea += 1; // advance past match
            }

            json cursor;
            if (more) {
                cursor = {{"next", offset_skip + limit}};
            } else {
                cursor = {{"done", true}};
            }

            results.push_back({
                {"pattern", pattern},
                {"matches", matches},
                {"n", static_cast<int>(matches.size())},
                {"cursor", cursor},
                {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"pattern", pattern},
                {"matches", json::array()},
                {"n", 0},
                {"cursor", {{"done", true}}},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// basic_blocks
// ═══════════════════════════════════════════════════════════════════

static json tool_basic_blocks(const json& params) {
    auto addrs = utils::normalize_list_input(params.value("addrs", json()));
    int max_blocks = params.value("max_blocks", 1000);
    int offset_skip = params.value("offset", 0);
    if (max_blocks <= 0 || max_blocks > 10000) max_blocks = 10000;

    json results = json::array();
    for (const auto& addr_str : addrs) {
        try {
            ea_t ea = utils::parse_address(addr_str);
            func_t* fn = get_func(ea);
            if (!fn) {
                results.push_back({
                    {"addr", addr_str}, {"blocks", nullptr},
                    {"count", 0}, {"total_blocks", 0},
                    {"cursor", {{"done", true}}}, {"error", "Not a function"},
                });
                continue;
            }

            qflow_chart_t fc;
            fc.create("", fn, fn->start_ea, fn->end_ea, 0);

            int total = fc.size();
            json blocks = json::array();

            int start_idx = offset_skip;
            int end_idx = std::min(total, offset_skip + max_blocks);

            for (int i = start_idx; i < end_idx; ++i) {
                const qbasic_block_t& bb = fc.blocks[i];

                json succs = json::array();
                for (int s = 0; s < fc.nsucc(i); ++s) {
                    int succ_idx = fc.succ(i, s);
                    if (succ_idx >= 0 && succ_idx < total) {
                        succs.push_back(utils::hex_str(fc.blocks[succ_idx].start_ea));
                    }
                }

                json preds = json::array();
                for (int p = 0; p < fc.npred(i); ++p) {
                    int pred_idx = fc.pred(i, p);
                    if (pred_idx >= 0 && pred_idx < total) {
                        preds.push_back(utils::hex_str(fc.blocks[pred_idx].start_ea));
                    }
                }

                json block_obj = {
                    {"start", utils::hex_str(bb.start_ea)},
                    {"end", utils::hex_str(bb.end_ea)},
                    {"size", static_cast<int>(bb.end_ea - bb.start_ea)},
                    {"successors", succs},
                    {"predecessors", preds},
                };
                blocks.push_back(block_obj);
            }

            bool more = end_idx < total;
            json cursor = more ? json({{"next", end_idx}}) : json({{"done", true}});

            results.push_back({
                {"addr", addr_str},
                {"blocks", blocks},
                {"count", static_cast<int>(blocks.size())},
                {"total_blocks", total},
                {"cursor", cursor},
                {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"addr", addr_str}, {"blocks", nullptr},
                {"count", 0}, {"total_blocks", 0},
                {"cursor", {{"done", true}}}, {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// find
// ═══════════════════════════════════════════════════════════════════

static json tool_find(const json& params) {
    std::string type = params.value("type", "");
    auto targets = utils::normalize_list_input(params.value("targets", json()));
    int limit = params.value("limit", 1000);
    int offset_skip = params.value("offset", 0);
    if (limit <= 0 || limit > 10000) limit = 10000;

    ea_t min_ea = inf_get_min_ea();
    ea_t max_ea = inf_get_max_ea();

    json results = json::array();
    for (const auto& target_str : targets) {
        try {
            json matches = json::array();
            int skipped = 0;
            bool more = false;

            if (type == "string") {
                // Search for UTF-8 string bytes
                std::string hex_pattern;
                for (unsigned char c : target_str) {
                    if (!hex_pattern.empty()) hex_pattern += " ";
                    char buf[4];
                    qsnprintf(buf, sizeof(buf), "%02X", c);
                    hex_pattern += buf;
                }

                compiled_binpat_vec_t bv;
                if (parse_binpat_str(&bv, min_ea, hex_pattern.c_str(), 16)) {
                    ea_t ea = min_ea;
                    while (ea < max_ea && ea != BADADDR) {
                        ea = bin_search(ea, max_ea, bv, BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW);
                        if (ea == BADADDR) break;

                        if (skipped < offset_skip) {
                            skipped++;
                        } else if (static_cast<int>(matches.size()) < limit) {
                            matches.push_back(utils::hex_str(ea));
                        } else {
                            more = true;
                            break;
                        }
                        ea += 1;
                    }
                }
            } else if (type == "immediate") {
                // Search for immediate value in instructions
                ea_t target_val = utils::parse_address(target_str);

                // Convert to LE bytes for 4-byte and 8-byte searches
                auto search_le = [&](uint64_t val, int nbytes) {
                    std::string pattern;
                    for (int i = 0; i < nbytes; ++i) {
                        if (!pattern.empty()) pattern += " ";
                        char buf[4];
                        qsnprintf(buf, sizeof(buf), "%02X", static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
                        pattern += buf;
                    }
                    return pattern;
                };

                // Search with 4-byte LE pattern first, then 8-byte
                std::vector<std::string> search_patterns;
                if (target_val <= 0xFFFFFFFF) {
                    search_patterns.push_back(search_le(target_val, 4));
                }
                search_patterns.push_back(search_le(target_val, 8));

                std::set<ea_t> found_eas;
                for (const auto& pat : search_patterns) {
                    compiled_binpat_vec_t bv;
                    if (!parse_binpat_str(&bv, min_ea, pat.c_str(), 16)) continue;

                    ea_t ea = min_ea;
                    while (ea < max_ea && ea != BADADDR) {
                        ea = bin_search(ea, max_ea, bv, BIN_SEARCH_FORWARD | BIN_SEARCH_NOSHOW);
                        if (ea == BADADDR) break;

                        // Validate: find instruction that contains this address
                        ea_t insn_ea = BADADDR;
                        for (int back = 0; back <= 15; ++back) {
                            ea_t try_ea = ea - back;
                            if (try_ea < min_ea) break;
                            insn_t insn;
                            int sz = decode_insn(&insn, try_ea);
                            if (sz > 0 && try_ea + sz > ea) {
                                insn_ea = try_ea;
                                break;
                            }
                        }

                        if (insn_ea != BADADDR && found_eas.find(insn_ea) == found_eas.end()) {
                            found_eas.insert(insn_ea);
                            if (skipped < offset_skip) {
                                skipped++;
                            } else if (static_cast<int>(matches.size()) < limit) {
                                matches.push_back(utils::hex_str(insn_ea));
                            } else {
                                more = true;
                                break;
                            }
                        }
                        ea += 1;
                    }
                    if (more) break;
                }
            } else if (type == "data_ref") {
                ea_t target_ea = utils::parse_address(target_str);
                xrefblk_t xb;
                for (bool ok = xb.first_to(target_ea, XREF_DATA); ok; ok = xb.next_to()) {
                    if (skipped < offset_skip) {
                        skipped++;
                    } else if (static_cast<int>(matches.size()) < limit) {
                        matches.push_back(utils::hex_str(xb.from));
                    } else {
                        more = true;
                        break;
                    }
                }
            } else if (type == "code_ref") {
                ea_t target_ea = utils::parse_address(target_str);
                xrefblk_t xb;
                for (bool ok = xb.first_to(target_ea, XREF_ALL); ok; ok = xb.next_to()) {
                    if (!xb.iscode) continue;
                    if (skipped < offset_skip) {
                        skipped++;
                    } else if (static_cast<int>(matches.size()) < limit) {
                        matches.push_back(utils::hex_str(xb.from));
                    } else {
                        more = true;
                        break;
                    }
                }
            } else {
                results.push_back({
                    {"query", target_str},
                    {"matches", json::array()},
                    {"count", 0},
                    {"cursor", {{"done", true}}},
                    {"error", "Unknown search type: " + type},
                });
                continue;
            }

            json cursor = more ? json({{"next", offset_skip + limit}}) : json({{"done", true}});
            results.push_back({
                {"query", target_str},
                {"matches", matches},
                {"count", static_cast<int>(matches.size())},
                {"cursor", cursor},
                {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"query", target_str},
                {"matches", json::array()},
                {"count", 0},
                {"cursor", {{"done", true}}},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// export_funcs
// ═══════════════════════════════════════════════════════════════════

static json tool_export_funcs(const json& params) {
    auto addrs = utils::normalize_list_input(params.value("addrs", json()));
    std::string format = params.value("format", "json");

    if (format == "c_header") {
        std::string content = "// Auto-generated by IDA Pro MCP\n\n";
        for (const auto& addr_str : addrs) {
            try {
                ea_t ea = utils::parse_address(addr_str);
                func_t* fn = get_func(ea);
                if (!fn) continue;

                qstring name;
                get_func_name(&name, fn->start_ea);

                // Get prototype
                tinfo_t tif;
                if (get_tinfo(&tif, fn->start_ea) && tif.is_func()) {
                    qstring proto;
                    tif.print(&proto);
                    content += std::string(proto.c_str()) + ";\n";
                } else {
                    content += "// " + std::string(name.c_str()) + " at " +
                               utils::hex_str(fn->start_ea) + " (no prototype)\n";
                }
            } catch (...) {}
        }
        return {{"format", format}, {"content", content}};
    }

    if (format == "prototypes") {
        json functions = json::array();
        for (const auto& addr_str : addrs) {
            try {
                ea_t ea = utils::parse_address(addr_str);
                func_t* fn = get_func(ea);
                if (!fn) continue;

                qstring name;
                get_func_name(&name, fn->start_ea);

                std::string proto = "";
                tinfo_t tif;
                if (get_tinfo(&tif, fn->start_ea) && tif.is_func()) {
                    qstring proto_str;
                    tif.print(&proto_str);
                    proto = proto_str.c_str();
                }

                functions.push_back({
                    {"name", name.c_str()},
                    {"prototype", proto},
                });
            } catch (...) {}
        }
        return {{"format", format}, {"functions", functions}};
    }

    // Default: json format
    json functions = json::array();
    for (const auto& addr_str : addrs) {
        try {
            ea_t ea = utils::parse_address(addr_str);
            func_t* fn = get_func(ea);
            if (!fn) {
                functions.push_back({
                    {"addr", addr_str}, {"error", "Not a function"},
                });
                continue;
            }

            qstring name;
            get_func_name(&name, fn->start_ea);

            // Prototype
            std::string proto = "";
            tinfo_t tif;
            if (get_tinfo(&tif, fn->start_ea) && tif.is_func()) {
                qstring proto_str;
                tif.print(&proto_str);
                proto = proto_str.c_str();
            }

            // Assembly lines
            std::string asm_lines;
            ea_t cur = fn->start_ea;
            int line_count = 0;
            while (cur < fn->end_ea && cur != BADADDR && line_count < 5000) {
                qstring disasm_line;
                generate_disasm_line(&disasm_line, cur, 0);
                qstring clean;
                tag_remove(&clean, disasm_line);
                if (!asm_lines.empty()) asm_lines += "\n";
                char addr_buf[32];
                qsnprintf(addr_buf, sizeof(addr_buf), "%llx", static_cast<unsigned long long>(cur));
                asm_lines += std::string(addr_buf) + "  " + clean.c_str();
                cur = next_head(cur, fn->end_ea);
                line_count++;
            }

            // Comments
            qstring cmt;
            get_cmt(&cmt, fn->start_ea, false);
            qstring rcmt;
            get_cmt(&rcmt, fn->start_ea, true);

            json func_obj = {
                {"addr", utils::hex_str(fn->start_ea)},
                {"name", name.c_str()},
                {"prototype", proto},
                {"size", utils::hex_str(fn->end_ea - fn->start_ea)},
                {"asm", asm_lines},
                {"comment", cmt.length() > 0 ? json(cmt.c_str()) : json(nullptr)},
                {"repeatable_comment", rcmt.length() > 0 ? json(rcmt.c_str()) : json(nullptr)},
            };

            functions.push_back(func_obj);
        } catch (const std::exception& e) {
            functions.push_back({
                {"addr", addr_str}, {"error", e.what()},
            });
        }
    }
    return {{"format", format}, {"functions", functions}};
}

// ═══════════════════════════════════════════════════════════════════
// callgraph
// ═══════════════════════════════════════════════════════════════════

static json tool_callgraph(const json& params) {
    auto roots = utils::normalize_list_input(params.value("roots", json()));
    int max_depth = params.value("max_depth", 5);
    int max_nodes = params.value("max_nodes", 1000);
    int max_edges = params.value("max_edges", 5000);
    int max_edges_per_func = params.value("max_edges_per_func", 200);

    if (max_depth <= 0) max_depth = 1;
    if (max_nodes <= 0 || max_nodes > 100000) max_nodes = 100000;
    if (max_edges <= 0 || max_edges > 200000) max_edges = 200000;
    if (max_edges_per_func <= 0 || max_edges_per_func > 5000) max_edges_per_func = 5000;

    json results = json::array();
    for (const auto& root_str : roots) {
        try {
            ea_t root_ea = utils::parse_address(root_str);
            func_t* root_fn = get_func(root_ea);
            if (!root_fn) {
                results.push_back({
                    {"root", root_str}, {"nodes", json::array()},
                    {"edges", json::array()}, {"truncated", false},
                    {"limit_reason", "Not a function"}, {"error", "Not a function"},
                });
                continue;
            }
            root_ea = root_fn->start_ea;

            // BFS traversal
            struct NodeInfo {
                ea_t addr;
                std::string name;
                int depth;
            };

            std::unordered_map<ea_t, NodeInfo> nodes;
            json edges_arr = json::array();
            std::queue<std::pair<ea_t, int>> bfs_queue;
            bool truncated = false;
            std::string limit_reason;
            bool per_func_capped = false;

            // Add root
            qstring root_name;
            get_func_name(&root_name, root_ea);
            nodes[root_ea] = {root_ea, root_name.c_str(), 0};
            bfs_queue.push({root_ea, 0});

            while (!bfs_queue.empty()) {
                auto [cur_ea, depth] = bfs_queue.front();
                bfs_queue.pop();

                if (depth >= max_depth) continue;

                func_t* fn = get_func(cur_ea);
                if (!fn) continue;

                // Find callees
                int edge_count_this_func = 0;
                ea_t ea = fn->start_ea;
                std::set<ea_t> seen_targets;

                while (ea < fn->end_ea && ea != BADADDR) {
                    insn_t insn;
                    if (decode_insn(&insn, ea) > 0 && is_call_insn(insn)) {
                        ea_t target = BADADDR;
                        const op_t& op = insn.ops[0];
                        if (op.type == o_near || op.type == o_far) {
                            target = op.addr;
                        } else if (op.type == o_mem) {
                            target = op.addr;
                        }

                        func_t* target_fn = (target != BADADDR) ? get_func(target) : nullptr;
                        if (target_fn) {
                            target = target_fn->start_ea;
                        }

                        if (target != BADADDR && seen_targets.find(target) == seen_targets.end()) {
                            seen_targets.insert(target);

                            if (edge_count_this_func >= max_edges_per_func) {
                                per_func_capped = true;
                                continue;
                            }

                            if (static_cast<int>(edges_arr.size()) >= max_edges) {
                                truncated = true;
                                limit_reason = "max_edges";
                                goto done;
                            }

                            edges_arr.push_back({
                                {"from", utils::hex_str(cur_ea)},
                                {"to", utils::hex_str(target)},
                                {"type", "call"},
                            });
                            edge_count_this_func++;

                            // Add target node if new
                            if (nodes.find(target) == nodes.end()) {
                                if (static_cast<int>(nodes.size()) >= max_nodes) {
                                    truncated = true;
                                    limit_reason = "max_nodes";
                                    goto done;
                                }
                                qstring target_name;
                                get_name(&target_name, target);
                                nodes[target] = {target, target_name.c_str(), depth + 1};
                                bfs_queue.push({target, depth + 1});
                            }
                        }
                    }
                    ea = next_head(ea, fn->end_ea);
                }
            }
            done:

            // Build nodes array
            json nodes_arr = json::array();
            for (const auto& [addr, info] : nodes) {
                nodes_arr.push_back({
                    {"addr", utils::hex_str(addr)},
                    {"name", info.name},
                    {"depth", info.depth},
                });
            }

            results.push_back({
                {"root", root_str},
                {"nodes", nodes_arr},
                {"edges", edges_arr},
                {"max_depth", max_depth},
                {"truncated", truncated},
                {"limit_reason", truncated ? json(limit_reason) : json(nullptr)},
                {"max_nodes", max_nodes},
                {"max_edges", max_edges},
                {"max_edges_per_func", max_edges_per_func},
                {"per_func_capped", per_func_capped},
                {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"root", root_str},
                {"nodes", json::array()},
                {"edges", json::array()},
                {"truncated", false},
                {"limit_reason", nullptr},
                {"error", e.what()},
            });
        }
    }
    return results;
}

// ═══════════════════════════════════════════════════════════════════
// xrefs_to_field
// ═══════════════════════════════════════════════════════════════════

static json tool_xrefs_to_field(const json& params) {
    auto queries = utils::normalize_dict_list(
        params.value("queries", json()),
        nullptr);

    json results = json::array();
    for (const auto& query : queries) {
        std::string struct_name = query.value("struct", "");
        std::string field_name = query.value("field", "");

        try {
            tinfo_t tif;
            if (!tif.get_named_type(nullptr, struct_name.c_str())) {
                results.push_back({
                    {"struct", struct_name}, {"field", field_name},
                    {"xrefs", json::array()},
                    {"error", "Struct not found: " + struct_name},
                });
                continue;
            }

            // Find field by name
            std::string fullname = struct_name + "." + field_name;
            udm_t udm;
            int idx = get_udm_by_fullname(&udm, fullname.c_str());
            if (idx < 0) {
                results.push_back({
                    {"struct", struct_name}, {"field", field_name},
                    {"xrefs", json::array()},
                    {"error", "Field not found: " + field_name},
                });
                continue;
            }

            // Get field TID for xref enumeration
            tid_t field_tid = tif.get_udm_tid(idx);
            if (field_tid == BADADDR) {
                results.push_back({
                    {"struct", struct_name}, {"field", field_name},
                    {"xrefs", json::array()},
                    {"error", "Could not get TID for field"},
                });
                continue;
            }

            // Enumerate xrefs to field TID
            json xrefs = json::array();
            xrefblk_t xb;
            for (bool ok = xb.first_to(field_tid, XREF_ALL); ok; ok = xb.next_to()) {
                json xref_obj = {
                    {"addr", utils::hex_str(xb.from)},
                    {"type", xb.iscode ? "code" : "data"},
                };
                func_t* fn = get_func(xb.from);
                if (fn) {
                    qstring fn_name;
                    get_func_name(&fn_name, fn->start_ea);
                    xref_obj["fn"] = fn_name.c_str();
                } else {
                    xref_obj["fn"] = nullptr;
                }
                xrefs.push_back(xref_obj);
            }

            results.push_back({
                {"struct", struct_name},
                {"field", field_name},
                {"xrefs", xrefs},
                {"error", nullptr},
            });
        } catch (const std::exception& e) {
            results.push_back({
                {"struct", struct_name}, {"field", field_name},
                {"xrefs", json::array()}, {"error", e.what()},
            });
        }
    }
    return results;
}

#endif // !IDA_MCP_TESTING

void register_analysis_tools(McpProtocol& mcp) {
#ifndef IDA_MCP_TESTING
    mcp.register_tool(
        {"disasm",
         "Disassemble function to assembly instructions",
         SchemaBuilder()
             .string_prop("addr", "Function address to disassemble")
             .int_prop("max_instructions", "Max instructions per function (default: 5000, max: 50000)", false)
             .int_prop("offset", "Skip first N instructions (default: 0)", false)
             .bool_prop("include_total", "Compute total instruction count (default: false)")
             .build()},
        ida_sync_tool(tool_disasm, 90.0)
    );

    mcp.register_tool(
        {"xrefs_to",
         "Get cross-references to specified addresses",
         SchemaBuilder()
             .prop("addrs", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Addresses to find cross-references to"},
             })
             .int_prop("limit", "Max xrefs per address (default: 100, max: 1000)", false)
             .build()},
        ida_sync_tool(tool_xrefs_to)
    );

    mcp.register_tool(
        {"callees",
         "Get functions called by a function",
         SchemaBuilder()
             .prop("addrs", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Function addresses to get callees for"},
             })
             .int_prop("limit", "Max callees per function (default: 200, max: 500)", false)
             .build()},
        ida_sync_tool(tool_callees)
    );

    mcp.register_tool(
        {"find_bytes",
         "Search for byte patterns with wildcards (e.g. '48 8B ? ?')",
         SchemaBuilder()
             .prop("patterns", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Byte pattern(s) to search for"},
             })
             .int_prop("limit", "Max matches per pattern (default: 1000)", false)
             .int_prop("offset", "Skip first N matches (default: 0)", false)
             .build()},
        ida_sync_tool(tool_find_bytes, 90.0)
    );

    mcp.register_tool(
        {"basic_blocks",
         "Get control flow graph basic blocks for a function",
         SchemaBuilder()
             .prop("addrs", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Function addresses"},
             })
             .int_prop("max_blocks", "Max basic blocks per function (default: 1000)", false)
             .int_prop("offset", "Skip first N blocks (default: 0)", false)
             .build()},
        ida_sync_tool(tool_basic_blocks)
    );

    mcp.register_tool(
        {"find",
         "Unified search (string, immediate, data_ref, code_ref)",
         SchemaBuilder()
             .string_prop("type", "Search type: 'string', 'immediate', 'data_ref', or 'code_ref'")
             .prop("targets", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Search targets"},
             })
             .int_prop("limit", "Max matches per target (default: 1000)", false)
             .int_prop("offset", "Skip first N matches (default: 0)", false)
             .build()},
        ida_sync_tool(tool_find, 90.0)
    );

    mcp.register_tool(
        {"export_funcs",
         "Export function data in various formats",
         SchemaBuilder()
             .prop("addrs", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Function addresses to export"},
             })
             .string_prop("format", "Output format: 'json', 'c_header', or 'prototypes' (default: json)", false)
             .build()},
        ida_sync_tool(tool_export_funcs, 90.0)
    );

    mcp.register_tool(
        {"callgraph",
         "Build call graph from root functions",
         SchemaBuilder()
             .prop("roots", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "string"}}}},
                     {{"type", "string"}},
                 })},
                 {"description", "Root function addresses"},
             })
             .int_prop("max_depth", "Max call depth (default: 5)", false)
             .int_prop("max_nodes", "Max graph nodes (default: 1000)", false)
             .int_prop("max_edges", "Max graph edges (default: 5000)", false)
             .int_prop("max_edges_per_func", "Max edges per function (default: 200)", false)
             .build()},
        ida_sync_tool(tool_callgraph, 90.0)
    );

    mcp.register_tool(
        {"xrefs_to_field",
         "Get cross-references to structure field",
         SchemaBuilder()
             .prop("queries", {
                 {"anyOf", json::array({
                     {{"type", "array"}, {"items", {{"type", "object"}, {"properties", {
                         {"struct", {{"type", "string"}, {"description", "Structure name"}}},
                         {"field", {{"type", "string"}, {"description", "Field name"}}},
                     }}, {"required", json::array({"struct", "field"})}}}},
                     {{"type", "object"}, {"properties", {
                         {"struct", {{"type", "string"}, {"description", "Structure name"}}},
                         {"field", {{"type", "string"}, {"description", "Field name"}}},
                     }}, {"required", json::array({"struct", "field"})}},
                 })},
                 {"description", "Struct field xref queries"},
             })
             .build()},
        ida_sync_tool(tool_xrefs_to_field)
    );
#endif
}
