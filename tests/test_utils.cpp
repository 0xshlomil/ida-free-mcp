#include <doctest.h>
#include "utils.h"

using json = nlohmann::json;

TEST_SUITE("parse_address") {

TEST_CASE("hex with 0x prefix") {
    CHECK(utils::parse_address("0x401000") == 0x401000);
    CHECK(utils::parse_address("0X401000") == 0x401000);
    CHECK(utils::parse_address("0xDEADBEEF") == 0xDEADBEEF);
}

TEST_CASE("decimal") {
    CHECK(utils::parse_address("12345") == 12345);
    CHECK(utils::parse_address("0") == 0);
}

TEST_CASE("all hex digits without prefix throws") {
    // "abcdef" is all hex chars but not a valid decimal number
    CHECK_THROWS_WITH_AS(
        utils::parse_address("abcdef"),
        "Failed to parse address (missing 0x prefix): abcdef",
        std::runtime_error);
}

TEST_CASE("numeric string without 0x parses as decimal") {
    // "401000" is all digits, so stoull parses as decimal (matching Python int("401000", 0))
    CHECK(utils::parse_address("401000") == 401000);
}

TEST_CASE("invalid string throws") {
    CHECK_THROWS_AS(utils::parse_address("not_an_addr"), std::runtime_error);
}

TEST_CASE("empty string throws") {
    CHECK_THROWS_AS(utils::parse_address(""), std::runtime_error);
}

TEST_CASE("whitespace is trimmed") {
    CHECK(utils::parse_address("  0x100  ") == 0x100);
}

} // TEST_SUITE

TEST_SUITE("hex_str") {

TEST_CASE("basic formatting") {
    CHECK(utils::hex_str(0x401000) == "0x401000");
    CHECK(utils::hex_str(0) == "0x0");
    CHECK(utils::hex_str(255) == "0xff");
}

} // TEST_SUITE

TEST_SUITE("normalize_list_input") {

TEST_CASE("json array of strings") {
    json input = json::array({"a", "b", "c"});
    auto result = utils::normalize_list_input(input);
    CHECK(result.size() == 3);
    CHECK(result[0] == "a");
    CHECK(result[1] == "b");
    CHECK(result[2] == "c");
}

TEST_CASE("comma-separated string") {
    json input = "a, b, c";
    auto result = utils::normalize_list_input(input);
    CHECK(result.size() == 3);
    CHECK(result[0] == "a");
    CHECK(result[1] == "b");
    CHECK(result[2] == "c");
}

TEST_CASE("single string") {
    json input = "hello";
    auto result = utils::normalize_list_input(input);
    CHECK(result.size() == 1);
    CHECK(result[0] == "hello");
}

TEST_CASE("null input") {
    json input = nullptr;
    auto result = utils::normalize_list_input(input);
    CHECK(result.empty());
}

TEST_CASE("array of non-strings") {
    json input = json::array({1, 2, 3});
    auto result = utils::normalize_list_input(input);
    CHECK(result.size() == 3);
    CHECK(result[0] == "1");
    CHECK(result[1] == "2");
}

} // TEST_SUITE

TEST_SUITE("paginate") {

TEST_CASE("basic pagination") {
    json data = json::array({1, 2, 3, 4, 5});
    auto result = utils::paginate(data, 0, 3);

    CHECK(result["data"].size() == 3);
    CHECK(result["data"][0] == 1);
    CHECK(result["data"][2] == 3);
    CHECK(result["next_offset"] == 3);
}

TEST_CASE("last page") {
    json data = json::array({1, 2, 3, 4, 5});
    auto result = utils::paginate(data, 3, 3);

    CHECK(result["data"].size() == 2);
    CHECK(result["data"][0] == 4);
    CHECK(result["data"][1] == 5);
    CHECK(result["next_offset"].is_null());
}

TEST_CASE("count=0 means all") {
    json data = json::array({1, 2, 3});
    auto result = utils::paginate(data, 0, 0);

    CHECK(result["data"].size() == 3);
    CHECK(result["next_offset"].is_null());
}

TEST_CASE("offset beyond data") {
    json data = json::array({1, 2, 3});
    auto result = utils::paginate(data, 10, 5);

    CHECK(result["data"].empty());
    CHECK(result["next_offset"].is_null());
}

TEST_CASE("empty data") {
    json data = json::array();
    auto result = utils::paginate(data, 0, 10);

    CHECK(result["data"].empty());
    CHECK(result["next_offset"].is_null());
}

TEST_CASE("exact boundary") {
    json data = json::array({1, 2, 3});
    auto result = utils::paginate(data, 0, 3);

    CHECK(result["data"].size() == 3);
    CHECK(result["next_offset"].is_null());
}

} // TEST_SUITE

TEST_SUITE("pattern_filter") {

TEST_CASE("substring match (case-insensitive)") {
    json data = json::array({
        {{"name", "main"}},
        {{"name", "printf"}},
        {{"name", "MainLoop"}},
    });
    auto result = utils::pattern_filter(data, "main", "name");
    CHECK(result.size() == 2);
}

TEST_CASE("glob match") {
    json data = json::array({
        {{"name", "sub_401000"}},
        {{"name", "sub_402000"}},
        {{"name", "main"}},
    });
    auto result = utils::pattern_filter(data, "sub_*", "name");
    CHECK(result.size() == 2);
}

TEST_CASE("regex match") {
    json data = json::array({
        {{"name", "func_a"}},
        {{"name", "func_b"}},
        {{"name", "main"}},
    });
    auto result = utils::pattern_filter(data, "/^func_/", "name");
    CHECK(result.size() == 2);
}

TEST_CASE("regex with flags") {
    json data = json::array({
        {{"name", "Main"}},
        {{"name", "MAIN"}},
        {{"name", "other"}},
    });
    auto result = utils::pattern_filter(data, "/main/i", "name");
    CHECK(result.size() == 2);
}

TEST_CASE("empty pattern returns all") {
    json data = json::array({{{"name", "a"}}, {{"name", "b"}}});
    auto result = utils::pattern_filter(data, "", "name");
    CHECK(result.size() == 2);
}

} // TEST_SUITE

TEST_SUITE("string utilities") {

TEST_CASE("to_lower") {
    CHECK(utils::to_lower("Hello World") == "hello world");
    CHECK(utils::to_lower("") == "");
    CHECK(utils::to_lower("already lower") == "already lower");
}

TEST_CASE("trim") {
    CHECK(utils::trim("  hello  ") == "hello");
    CHECK(utils::trim("\t\nhello\r\n") == "hello");
    CHECK(utils::trim("") == "");
    CHECK(utils::trim("   ") == "");
    CHECK(utils::trim("no_trim") == "no_trim");
}

TEST_CASE("split") {
    auto result = utils::split("a, b, c", ',');
    CHECK(result.size() == 3);
    CHECK(result[0] == "a");
    CHECK(result[1] == "b");
    CHECK(result[2] == "c");

    auto empty = utils::split("", ',');
    CHECK(empty.empty());
}

TEST_CASE("glob_match") {
    CHECK(utils::glob_match("*.txt", "hello.txt"));
    CHECK_FALSE(utils::glob_match("*.txt", "hello.cpp"));
    CHECK(utils::glob_match("sub_*", "sub_401000"));
    CHECK(utils::glob_match("?ello", "hello"));
    CHECK(utils::glob_match("*", "anything"));
    CHECK(utils::glob_match("", ""));
    CHECK_FALSE(utils::glob_match("abc", "abcd"));
}

} // TEST_SUITE

TEST_SUITE("normalize_dict_list") {

TEST_CASE("single object") {
    json input = {{"key", "value"}};
    auto result = utils::normalize_dict_list(input);
    CHECK(result.size() == 1);
    CHECK(result[0]["key"] == "value");
}

TEST_CASE("array of objects") {
    json input = json::array({{{"a", 1}}, {{"b", 2}}});
    auto result = utils::normalize_dict_list(input);
    CHECK(result.size() == 2);
}

TEST_CASE("string with parser") {
    auto result = utils::normalize_dict_list(
        json("foo, bar"),
        [](const std::string& s) -> json {
            return {{"name", s}};
        });
    CHECK(result.size() == 2);
    CHECK(result[0]["name"] == "foo");
    CHECK(result[1]["name"] == "bar");
}

TEST_CASE("json string parsed") {
    auto result = utils::normalize_dict_list(json(R"({"x": 1})"));
    CHECK(result.size() == 1);
    CHECK(result[0]["x"] == 1);
}

TEST_CASE("null returns empty object") {
    auto result = utils::normalize_dict_list(json());
    CHECK(result.size() == 1);
    CHECK(result[0].empty());
}

} // TEST_SUITE
