#pragma once

// IDA SDK master include. Includes <ida.hpp> then undoes the dangerous macro
// redefinitions from pro.h that would break third-party headers
// (nlohmann/json, cpp-httplib, std library).
//
// In our own code, use qsnprintf/qgetenv/qstrncpy explicitly.

#ifndef IDA_MCP_TESTING

#include <ida.hpp>

// pro.h redefines standard C functions to force IDA-specific alternatives.
// Undo them so third-party headers (and std:: calls) compile normally.
#undef snprintf
#undef sprintf
#undef getenv
#undef setenv
#undef putenv
#undef strcpy
#undef stpcpy
#undef strncpy
#undef strcat
#undef strncat
#undef gets
#undef strtok
#undef strlwr
#undef strupr
#undef strcmpi
#undef strncmpi
#undef waitid
#undef waitpid
#undef wait
#ifdef wsprintfA
#undef wsprintfA
#endif

#endif // !IDA_MCP_TESTING
