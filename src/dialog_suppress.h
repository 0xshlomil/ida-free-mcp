#pragma once

// Dialog auto-dismiss for MCP tool execution.
//
// IDA sometimes pops modal dialogs (warnings, yes/no prompts) during
// operations like bin_search(). These block the main thread and prevent
// MCP tool handlers from returning.
//
// SuppressDialogs is a RAII guard that activates a UI notification hook
// which intercepts and auto-answers these dialogs while active.

#ifndef IDA_MCP_TESTING

#include <atomic>

namespace idasync {

/// RAII guard: while alive, IDA dialogs are auto-dismissed.
/// Use in tool handlers that may trigger blocking dialogs.
class SuppressDialogs {
public:
    SuppressDialogs();
    ~SuppressDialogs();
    SuppressDialogs(const SuppressDialogs&) = delete;
    SuppressDialogs& operator=(const SuppressDialogs&) = delete;
};

/// Install the UI notification hook. Call once at plugin startup.
void install_dialog_hook();

/// Uninstall the UI notification hook. Call at plugin shutdown.
void uninstall_dialog_hook();

} // namespace idasync

#else // IDA_MCP_TESTING

namespace idasync {

class SuppressDialogs {
public:
    SuppressDialogs() = default;
    ~SuppressDialogs() = default;
    SuppressDialogs(const SuppressDialogs&) = delete;
    SuppressDialogs& operator=(const SuppressDialogs&) = delete;
};

inline void install_dialog_hook() {}
inline void uninstall_dialog_hook() {}

} // namespace idasync

#endif // IDA_MCP_TESTING
