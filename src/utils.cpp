#ifndef IDA_MCP_TESTING
#include "ida_pre.h"
#endif

#include "utils.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <regex>
#include <sstream>
#include <stdexcept>

namespace utils {

// ═══════════════════════════════════════════════════════════════════
// Address Parsing
// ═══════════════════════════════════════════════════════════════════

ea_t parse_address(const std::string& addr) {
    std::string s = trim(addr);
    if (s.empty()) {
        throw std::runtime_error("Failed to parse address: empty string");
    }

    // Try parsing as number (0x prefix for hex, plain decimal)
    try {
        size_t pos = 0;
        unsigned long long val = std::stoull(s, &pos, 0);
        if (pos == s.size()) {
            return static_cast<ea_t>(val);
        }
    } catch (...) {}

    // Check if it looks like a hex string without 0x prefix
    bool all_hex = true;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            all_hex = false;
            break;
        }
    }
    if (all_hex) {
        throw std::runtime_error("Failed to parse address (missing 0x prefix): " + addr);
    }

    throw std::runtime_error("Failed to parse address: " + addr);
}

std::string hex_str(ea_t addr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << addr;
    return oss.str();
}

// ═══════════════════════════════════════════════════════════════════
// Input Normalization
// ═══════════════════════════════════════════════════════════════════

std::vector<std::string> normalize_list_input(const json& value) {
    if (value.is_array()) {
        std::vector<std::string> result;
        for (const auto& item : value) {
            if (item.is_string()) {
                result.push_back(item.get<std::string>());
            } else {
                result.push_back(item.dump());
            }
        }
        return result;
    }
    if (value.is_string()) {
        return split(value.get<std::string>(), ',');
    }
    if (value.is_null()) {
        return {};
    }
    return {value.dump()};
}

std::vector<json> normalize_dict_list(
    const json& value,
    std::function<json(const std::string&)> string_parser) {

    if (value.is_object()) {
        return {value};
    }
    if (value.is_array()) {
        if (value.empty()) return {json::object()};

        // Check if all elements are objects
        bool all_objects = true;
        bool all_strings = true;
        for (const auto& item : value) {
            if (!item.is_object()) all_objects = false;
            if (!item.is_string()) all_strings = false;
        }

        if (all_objects) {
            return value.get<std::vector<json>>();
        }
        if (all_strings && string_parser) {
            std::vector<json> result;
            for (const auto& item : value) {
                std::string s = trim(item.get<std::string>());
                if (!s.empty()) {
                    result.push_back(string_parser(s));
                }
            }
            return result.empty() ? std::vector<json>{json::object()} : result;
        }
        // Mixed types - filter objects
        std::vector<json> result;
        for (const auto& item : value) {
            if (item.is_object()) result.push_back(item);
        }
        return result.empty() ? std::vector<json>{json::object()} : result;
    }
    if (value.is_string()) {
        std::string s = value.get<std::string>();
        // Try JSON parse first
        try {
            json parsed = json::parse(s);
            if (parsed.is_object()) return {parsed};
            if (parsed.is_array()) return parsed.get<std::vector<json>>();
        } catch (...) {}

        // Split by comma
        auto parts = split(s, ',');
        if (parts.empty()) return {json::object()};

        if (string_parser) {
            std::vector<json> result;
            for (const auto& part : parts) {
                result.push_back(string_parser(part));
            }
            return result;
        }
        return {json::object()};
    }
    return {json::object()};
}

// ═══════════════════════════════════════════════════════════════════
// Pagination
// ═══════════════════════════════════════════════════════════════════

json paginate(const json& data, int offset, int count) {
    if (!data.is_array()) {
        return {{"data", json::array()}, {"next_offset", nullptr}};
    }

    int total = static_cast<int>(data.size());
    if (count == 0) count = total;

    int end = std::min(offset + count, total);
    json page = json::array();
    for (int i = offset; i < end; ++i) {
        page.push_back(data[i]);
    }

    json next_offset = nullptr;
    if (offset + count < total) {
        next_offset = offset + count;
    }

    return {{"data", page}, {"next_offset", next_offset}};
}

// ═══════════════════════════════════════════════════════════════════
// Pattern Filtering
// ═══════════════════════════════════════════════════════════════════

json pattern_filter(const json& data, const std::string& pattern,
                    const std::string& key) {
    if (pattern.empty() || !data.is_array()) return data;

    // Determine pattern type
    std::regex regex;
    bool use_regex = false;
    bool use_glob = false;

    // Regex: /pattern/flags
    if (pattern.front() == '/' && pattern.size() >= 2) {
        auto last_slash = pattern.rfind('/');
        if (last_slash > 0) {
            std::string body = pattern.substr(1, last_slash - 1);
            std::string flag_str = pattern.substr(last_slash + 1);

            auto flags = std::regex_constants::ECMAScript;
            for (char ch : flag_str) {
                if (ch == 'i') flags |= std::regex_constants::icase;
#ifdef __cpp_lib_regex_multiline
                if (ch == 'm') flags |= std::regex_constants::multiline;
#endif
            }
            // Default to case-insensitive if no flags
            if (flag_str.empty()) flags |= std::regex_constants::icase;

            try {
                regex = std::regex(body, flags);
                use_regex = true;
            } catch (...) {}
        }
    }

    // Glob: contains * or ?
    if (!use_regex && (pattern.find('*') != std::string::npos ||
                       pattern.find('?') != std::string::npos)) {
        use_glob = true;
    }

    std::string pattern_lower = to_lower(pattern);

    json result = json::array();
    for (const auto& item : data) {
        std::string text;
        if (item.is_object() && item.contains(key)) {
            const auto& v = item[key];
            text = v.is_string() ? v.get<std::string>() : v.dump();
        }

        bool match = false;
        if (use_regex) {
            match = std::regex_search(text, regex);
        } else if (use_glob) {
            match = glob_match(pattern_lower, to_lower(text));
        } else {
            match = to_lower(text).find(pattern_lower) != std::string::npos;
        }

        if (match) result.push_back(item);
    }
    return result;
}

// ═══════════════════════════════════════════════════════════════════
// String Utilities
// ═══════════════════════════════════════════════════════════════════

std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::istringstream iss(s);
    std::string token;
    while (std::getline(iss, token, delim)) {
        std::string trimmed = trim(token);
        if (!trimmed.empty()) {
            result.push_back(trimmed);
        }
    }
    return result;
}

bool glob_match(const std::string& pattern, const std::string& text) {
    size_t pi = 0, ti = 0;
    size_t star_pi = std::string::npos, star_ti = 0;

    while (ti < text.size()) {
        if (pi < pattern.size() &&
            (pattern[pi] == '?' || pattern[pi] == text[ti])) {
            ++pi;
            ++ti;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            star_pi = pi++;
            star_ti = ti;
        } else if (star_pi != std::string::npos) {
            pi = star_pi + 1;
            ti = ++star_ti;
        } else {
            return false;
        }
    }
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
}

} // namespace utils
