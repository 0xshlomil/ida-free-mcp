#ifndef IDA_MCP_TESTING
#include "ida_pre.h"
#endif

#include "sync.h"

#ifndef IDA_MCP_TESTING

#include <kernwin.hpp>

#include <cstdlib>
#include <future>
#include <string>

namespace idasync {

double get_tool_timeout_seconds() {
    const char* val = std::getenv("IDA_MCP_TOOL_TIMEOUT_SEC");
    if (val) {
        try {
            double t = std::stod(val);
            if (t > 0) return t;
        } catch (...) {}
    }
    return 15.0; // Default
}

json execute_on_main_thread(
    std::function<json()> func,
    std::shared_ptr<std::atomic<bool>> cancel_flag,
    double timeout_sec) {

    if (timeout_sec < 0) {
        timeout_sec = get_tool_timeout_seconds();
    }

    // exec_request_t subclass for IDA's execute_sync
    struct SyncRequest : public exec_request_t {
        std::function<json()> func;
        std::promise<json> promise;

        ssize_t idaapi execute() override {
            try {
                json result = func();
                promise.set_value(std::move(result));
            } catch (...) {
                promise.set_exception(std::current_exception());
            }
            return 0;
        }
    };

    auto req = std::make_shared<SyncRequest>();
    req->func = std::move(func);

    auto future = req->promise.get_future();

    // Schedule execution on IDA main thread
    execute_sync(*req, MFF_WRITE);

    if (timeout_sec > 0) {
        auto deadline = std::chrono::milliseconds(
            static_cast<int64_t>(timeout_sec * 1000));
        auto status = future.wait_for(deadline);

        if (status == std::future_status::timeout) {
            char buf[128];
            qsnprintf(buf, sizeof(buf), "Tool timed out after %.2fs",
                      timeout_sec);
            throw IDASyncError(buf);
        }
    }

    // This will re-throw any exception from the main thread
    return future.get();
}

} // namespace idasync

#else // IDA_MCP_TESTING

namespace idasync {

double get_tool_timeout_seconds() { return 15.0; }

json execute_on_main_thread(
    std::function<json()> func,
    std::shared_ptr<std::atomic<bool>>,
    double) {
    // In test mode, just call directly
    return func();
}

} // namespace idasync

#endif // IDA_MCP_TESTING
