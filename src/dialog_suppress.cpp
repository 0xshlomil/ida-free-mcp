#ifndef IDA_MCP_TESTING
#include "ida_pre.h"
#endif

#include "dialog_suppress.h"

#ifndef IDA_MCP_TESTING

#include <idp.hpp>
#include <kernwin.hpp>
#include <atomic>

namespace idasync {

// Reference count of active SuppressDialogs guards.
// When > 0, the UI hook auto-dismisses dialogs.
static std::atomic<int> g_suppress_count{0};

struct dialog_listener_t : public event_listener_t {
    ssize_t idaapi on_event(ssize_t code, va_list) override {
        if (g_suppress_count.load(std::memory_order_relaxed) <= 0)
            return 0;

        switch (code) {
        case ui_mbox:
            // Suppress warning/info message boxes (e.g. "not found" from bin_search).
            msg("[MCP] Auto-dismissed dialog (ui_mbox) during tool execution\n");
            return 1;

        case ui_ask_buttons:
            // Auto-answer "Yes" to yes/no dialogs (ASKBTN_YES == 1).
            msg("[MCP] Auto-answered Yes to dialog (ui_ask_buttons) during tool execution\n");
            return 1;

        default:
            break;
        }
        return 0;
    }
};

static dialog_listener_t g_listener;
static bool g_hook_installed = false;

SuppressDialogs::SuppressDialogs() {
    g_suppress_count.fetch_add(1, std::memory_order_relaxed);
}

SuppressDialogs::~SuppressDialogs() {
    g_suppress_count.fetch_sub(1, std::memory_order_relaxed);
}

void install_dialog_hook() {
    if (!g_hook_installed) {
        hook_event_listener(HT_UI, &g_listener, nullptr);
        g_hook_installed = true;
    }
}

void uninstall_dialog_hook() {
    if (g_hook_installed) {
        unhook_event_listener(HT_UI, &g_listener);
        g_hook_installed = false;
    }
}

} // namespace idasync

#endif // !IDA_MCP_TESTING
