#pragma once

// IDA SDK master include. Includes <ida.hpp> and <fpro.h> then undoes the
// dangerous macro redefinitions from pro.h/fpro.h that would break
// third-party headers (nlohmann/json, cpp-httplib, std library).
//
// IMPORTANT: fpro.h is explicitly included here so that its macros are
// defined (and then undef'd) before any other code. Without this, later
// IDA headers (kernwin.hpp, loader.hpp, etc.) would include fpro.h for
// the first time AFTER our undefs, re-poisoning standard identifiers.
//
// In our own code, use qsnprintf/qgetenv/qstrncpy/qfopen explicitly.

#ifndef IDA_MCP_TESTING

#include <ida.hpp>
#include <fpro.h>

// pro.h and fpro.h redefine standard C functions to force IDA-specific
// alternatives. Undo them so third-party headers (and std:: calls) compile
// normally. In our own code, use the IDA-prefixed functions (qsnprintf, etc.).

// pro.h: string functions
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

// pro.h: strtoull → _strtoui64 on Windows (breaks nlohmann/json on MSVC)
#ifdef strtoull
#undef strtoull
#endif

// fpro.h: stdio functions (breaks <fstream> and other std headers)
#undef fopen
#undef fclose
#undef fread
#undef fwrite
#undef ftell
#undef fseek
#undef fflush
#undef fputc
#undef fgetc
#undef fgets
#undef fputs
#undef fprintf
#undef fscanf
#undef vfprintf
#undef vfscanf
#undef stdin
#undef stdout
#undef stderr

#endif // !IDA_MCP_TESTING
