#include <doctest.h>
#include "jsonrpc.h"

using namespace jsonrpc;
using json = nlohmann::json;

TEST_SUITE("JsonRpcRegistry") {

TEST_CASE("dispatch valid request") {
    JsonRpcRegistry reg;
    reg.register_method("add", [](const json& params) -> json {
        // Simple method that expects no params validation
        return 42;
    });

    auto result = reg.dispatch(R"({"jsonrpc":"2.0","method":"add","params":{},"id":1})");
    REQUIRE(result.has_value());
    CHECK((*result)["jsonrpc"] == "2.0");
    CHECK((*result)["result"] == 42);
    CHECK((*result)["id"] == 1);
}

TEST_CASE("dispatch with string id") {
    JsonRpcRegistry reg;
    reg.register_method("echo", [](const json& params) -> json {
        return params;
    });

    auto result = reg.dispatch(R"({"jsonrpc":"2.0","method":"echo","params":{"msg":"hello"},"id":"abc"})");
    REQUIRE(result.has_value());
    CHECK((*result)["id"] == "abc");
    CHECK((*result)["result"]["msg"] == "hello");
}

TEST_CASE("dispatch notification (no id) returns nullopt") {
    JsonRpcRegistry reg;
    bool called = false;
    reg.register_method("notify_me", [&](const json&) -> json {
        called = true;
        return nullptr;
    });

    auto result = reg.dispatch(R"({"jsonrpc":"2.0","method":"notify_me","params":{}})");
    CHECK_FALSE(result.has_value());
    CHECK(called);
}

TEST_CASE("dispatch with null id returns response") {
    JsonRpcRegistry reg;
    reg.register_method("test", [](const json&) -> json { return "ok"; });

    auto result = reg.dispatch(R"({"jsonrpc":"2.0","method":"test","params":{},"id":null})");
    REQUIRE(result.has_value());
    CHECK((*result)["id"].is_null());
    CHECK((*result)["result"] == "ok");
}

TEST_CASE("JSON parse error") {
    JsonRpcRegistry reg;
    auto result = reg.dispatch("not valid json{{{");
    REQUIRE(result.has_value());
    CHECK((*result)["error"]["code"] == PARSE_ERROR);
}

TEST_CASE("invalid request - missing jsonrpc") {
    JsonRpcRegistry reg;
    auto result = reg.dispatch(R"({"method":"test","id":1})");
    REQUIRE(result.has_value());
    CHECK((*result)["error"]["code"] == INVALID_REQUEST);
}

TEST_CASE("invalid request - wrong jsonrpc version") {
    JsonRpcRegistry reg;
    auto result = reg.dispatch(R"({"jsonrpc":"1.0","method":"test","id":1})");
    REQUIRE(result.has_value());
    CHECK((*result)["error"]["code"] == INVALID_REQUEST);
}

TEST_CASE("invalid request - missing method") {
    JsonRpcRegistry reg;
    auto result = reg.dispatch(R"({"jsonrpc":"2.0","id":1})");
    REQUIRE(result.has_value());
    CHECK((*result)["error"]["code"] == INVALID_REQUEST);
}

TEST_CASE("invalid request - method not string") {
    JsonRpcRegistry reg;
    auto result = reg.dispatch(R"({"jsonrpc":"2.0","method":123,"id":1})");
    REQUIRE(result.has_value());
    CHECK((*result)["error"]["code"] == INVALID_REQUEST);
}

TEST_CASE("method not found") {
    JsonRpcRegistry reg;
    auto result = reg.dispatch(R"({"jsonrpc":"2.0","method":"nonexistent","params":{},"id":1})");
    REQUIRE(result.has_value());
    CHECK((*result)["error"]["code"] == METHOD_NOT_FOUND);
    CHECK(std::string((*result)["error"]["message"]).find("nonexistent") != std::string::npos);
}

TEST_CASE("method throws JsonRpcException") {
    JsonRpcRegistry reg;
    reg.register_method("fail", [](const json&) -> json {
        throw JsonRpcException(-32602, "Bad params", "details");
    });

    auto result = reg.dispatch(R"({"jsonrpc":"2.0","method":"fail","params":{},"id":1})");
    REQUIRE(result.has_value());
    CHECK((*result)["error"]["code"] == -32602);
    CHECK((*result)["error"]["message"] == "Bad params");
}

TEST_CASE("method throws std::exception") {
    JsonRpcRegistry reg;
    reg.register_method("crash", [](const json&) -> json {
        throw std::runtime_error("something broke");
    });

    auto result = reg.dispatch(R"({"jsonrpc":"2.0","method":"crash","params":{},"id":1})");
    REQUIRE(result.has_value());
    CHECK((*result)["error"]["code"] == INTERNAL_ERROR);
}

TEST_CASE("method throws RequestCancelledError") {
    JsonRpcRegistry reg;
    reg.register_method("slow", [](const json&) -> json {
        throw RequestCancelledError("cancelled by user");
    });

    auto result = reg.dispatch(R"({"jsonrpc":"2.0","method":"slow","params":{},"id":1})");
    REQUIRE(result.has_value());
    CHECK((*result)["error"]["code"] == REQUEST_CANCELLED);
    CHECK((*result)["error"]["message"] == "cancelled by user");
}

TEST_CASE("dispatch pre-parsed json") {
    JsonRpcRegistry reg;
    reg.register_method("sum", [](const json& params) -> json {
        return params.value("a", 0) + params.value("b", 0);
    });

    json req = {
        {"jsonrpc", "2.0"},
        {"method", "sum"},
        {"params", {{"a", 3}, {"b", 4}}},
        {"id", 99},
    };

    auto result = reg.dispatch_parsed(req);
    REQUIRE(result.has_value());
    CHECK((*result)["result"] == 7);
    CHECK((*result)["id"] == 99);
}

TEST_CASE("not a JSON object") {
    JsonRpcRegistry reg;
    auto result = reg.dispatch("[1,2,3]");
    REQUIRE(result.has_value());
    CHECK((*result)["error"]["code"] == INVALID_REQUEST);
}

TEST_CASE("has_method works") {
    JsonRpcRegistry reg;
    reg.register_method("exists", [](const json&) -> json { return true; });

    CHECK(reg.has_method("exists"));
    CHECK_FALSE(reg.has_method("missing"));
}

} // TEST_SUITE

TEST_SUITE("Cancellation") {

TEST_CASE("register and cancel request") {
    json id = 42;
    auto flag = register_pending_request(id);
    CHECK_FALSE(flag->load());

    CHECK(cancel_request(id));
    CHECK(flag->load());

    unregister_pending_request(id);
    CHECK_FALSE(cancel_request(id));
}

TEST_CASE("cancel nonexistent request returns false") {
    CHECK_FALSE(cancel_request(999));
}

TEST_CASE("string request id") {
    json id = "req-abc";
    auto flag = register_pending_request(id);
    CHECK(cancel_request(json("req-abc")));
    CHECK(flag->load());
    unregister_pending_request(id);
}

} // TEST_SUITE
