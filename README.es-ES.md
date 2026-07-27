# IDA Free MCP

Un plugin nativo de C++ que integra la IA en tu flujo de trabajo de ingeniería inversa en IDA.

Expone las capacidades de análisis de IDA a través del [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), una interfaz estándar que permite que los LLMs se comuniquen con herramientas. El plugin ejecuta un servidor HTTP dentro del proceso de IDA, permitiendo que tu asistente de IA lea el desensamblado, decompile funciones, siga referencias cruzadas, renombre variables, parchee bytes y más.

## Uso

1. Abre un binario en IDA.
2. **Edit > Plugins > MCP** (o **Ctrl+Alt+M**) para iniciar el servidor.
3. Conecta tu cliente MCP a `http://127.0.0.1:13337/mcp`.
4. Presiona **Ctrl+Alt+M** nuevamente para detenerlo.

### Conexión de un cliente MCP

```bash
# Claude Code
claude mcp add --transport http ida-mcp http://127.0.0.1:13337/mcp
```

Para otros clientes (Claude Desktop, Cursor, Windsurf, etc.), añade lo siguiente a tu configuración de MCP:

```json
{
  "mcpServers": {
    "ida-mcp": {
      "url": "http://127.0.0.1:13337/mcp"
    }
  }
}
```

### Múltiples instancias de IDA

Se pueden ejecutar varias sesiones de IDA con MCP simultáneamente; el puerto se incrementa automáticamente si ya está en uso (hasta 10 intentos). Cada instancia escribe su puerto, PID y ruta del IDB en `~/.ida-mcp/instances/<pid>.json`. Los archivos obsoletos de sesiones caídas se limpian automáticamente.

### Variables de entorno

| Variable | Descripción | Predeterminado |
|---|---|---|
| `IDA_MCP_PORT` | Puerto base para el servidor HTTP | `13337` |
| `IDA_MCP_TOOL_TIMEOUT_SEC` | Tiempo de espera de ejecución de la herramienta en segundos | — |
| `IDA_MCP_URL` | URL base de descarga para salidas grandes | `http://127.0.0.1:<port>` |

## Requisitos

- **CMake** 3.16+, compilador **C++17** (GCC, Clang o MSVC)
- **IDA SDK** (para compilar el plugin; no es necesario para las pruebas)
- **IDA Pro / IDA Free** 9.0+

## Compilación

### Inicio rápido

```bash
# Linux / macOS
./build.sh

# Windows (Developer Command Prompt)
build.bat
```

Ambos scripts compilan las pruebas, las ejecutan, compilan el plugin y lo instalan. Define `IDASDK` para anular la ruta del SDK (predeterminado: submódulo `idasdk/src`).

### Compilación manual

```bash
# Solo pruebas (no requiere IDA SDK)
cmake -S . -B build/tests -DBUILD_PLUGIN=OFF -DBUILD_TESTS=ON
cmake --build build/tests --config Release

# Plugin
cmake -S . -B build/plugin -DBUILD_PLUGIN=ON -DBUILD_TESTS=OFF -DIDASDK=/path/to/idasdk
cmake --build build/plugin --config Release
```

Copia el plugin compilado (`ida_mcp.so` / `.dll` / `.dylib`) al directorio `plugins/` de tu IDA.

Los binarios precompilados están disponibles en la [página de releases](https://github.com/0xshlomil/ida-free-mcp/releases).

## Arquitectura

```
IDA Plugin (plugin.cpp)
  └─ McpPlugmod
       ├─ McpProtocol (mcp.h)        ← Registro de herramientas/recursos, métodos MCP
       │    └─ JsonRpcRegistry        ← Despacho JSON-RPC 2.0
       └─ McpHttpServer (server.h)    ← Rutas HTTP, CORS, SSE
```

Todas las llamadas al SDK de IDA se envían al hilo principal de IDA mediante `execute_sync(MFF_WRITE)` con soporte para tiempo de espera y cancelación.

**Transportes:** HTTP transmitible (`POST /mcp`) y SSE (`GET /sse`).

## Herramientas y Recursos

**37 herramientas** organizadas en 7 grupos. Cada herramienta se ejecuta en el hilo principal de IDA a través de `execute_sync` para garantizar la seguridad de los hilos.

| Grupo | Herramientas |
|---|---|
| **Core** | `int_convert`, `lookup_funcs`, `list_funcs`, `list_globals`, `imports`, `find_regex` |
| **Analysis** | `disasm`, `xrefs_to`, `xrefs_to_field`, `callees`, `callgraph`, `basic_blocks`, `find`, `find_bytes`, `export_funcs` |
| **Memory** | `get_bytes`, `get_string`, `get_int`, `get_global_value`, `patch`, `put_int` |
| **Modify** | `set_comments`, `rename`, `patch_asm`, `define_func`, `define_code`, `undefine` |
| **Types** | `declare_type`, `read_struct`, `search_structs`, `set_type` |
| **Stack** | `stack_frame`, `declare_stack`, `delete_stack` |
| **Decompiler** | `decompile`, `hexrays_diag`, `debug_mode` |

> **Nota:** La herramienta `decompile` funciona tanto en IDA Pro como en IDA Free. Utiliza la descompilación basada en GUI (activa F5 y lee el widget de pseudocódigo), por lo que no requiere la inicialización del SDK de Hex-Rays. La herramienta `hexrays_diag` informa el estado del SDK solo para diagnóstico; `init_hexrays_plugin: false` es lo esperado en IDA Free y no afecta la descompilación.

**11 recursos MCP** para acceso de lectura al estado de IDA: `ida://idb/metadata`, `ida://idb/segments`, `ida://idb/entrypoints`, `ida://cursor`, `ida://selection`, `ida://types`, `ida://structs`, `ida://struct/{name}`, `ida://import/{name}`, `ida://export/{name}`, `ida://xrefs/from/{addr}`.

## Dependencias

Todas incluidas en `deps/` (solo cabeceras): [nlohmann/json](https://github.com/nlohmann/json), [cpp-httplib](https://github.com/yhirose/cpp-httplib), [doctest](https://github.com/doctest/doctest).

## Licencia

Consulta el archivo [LICENSE](LICENSE).
