#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using json = nlohmann::json;

// When testing without IDA SDK, define ea_t
#ifdef IDA_MCP_TESTING
using ea_t = uint64_t;
constexpr ea_t BADADDR = static_cast<ea_t>(-1);
#else
#include <pro.h>
#endif

namespace utils {

// ═══════════════════════════════════════════════════════════════════
// Address Parsing
// ═══════════════════════════════════════════════════════════════════

/// Parse an address string (hex with 0x prefix, or decimal).
/// Throws std::runtime_error on parse failure.
ea_t parse_address(const std::string& addr);

/// Format address as hex string with 0x prefix.
std::string hex_str(ea_t addr);

// ═══════════════════════════════════════════════════════════════════
// Input Normalization
// ═══════════════════════════════════════════════════════════════════

/// Normalize input to a list of strings.
/// Accepts JSON array of strings or comma-separated string.
std::vector<std::string> normalize_list_input(const json& value);

/// Normalize input to a list of JSON objects.
/// Accepts JSON object (→ [obj]), JSON array, or comma-separated string.
std::vector<json> normalize_dict_list(
    const json& value,
    std::function<json(const std::string&)> string_parser = nullptr);

// ═══════════════════════════════════════════════════════════════════
// Pagination
// ═══════════════════════════════════════════════════════════════════

/// Paginate a JSON array. count=0 means all.
/// Returns {"data": [...], "next_offset": int|null}
json paginate(const json& data, int offset, int count);

// ═══════════════════════════════════════════════════════════════════
// Pattern Filtering
// ═══════════════════════════════════════════════════════════════════

/// Filter a JSON array of objects by pattern matching on a key.
/// Supports: regex (/pattern/flags), glob (* ?), substring (case-insensitive).
json pattern_filter(const json& data, const std::string& pattern,
                    const std::string& key);

// ═══════════════════════════════════════════════════════════════════
// String Utilities
// ═══════════════════════════════════════════════════════════════════

/// Convert string to lowercase.
std::string to_lower(const std::string& s);

/// Trim whitespace from both ends.
std::string trim(const std::string& s);

/// Split string by delimiter.
std::vector<std::string> split(const std::string& s, char delim);

/// Simple glob matching (case-insensitive).
bool glob_match(const std::string& pattern, const std::string& text);

} // namespace utils
