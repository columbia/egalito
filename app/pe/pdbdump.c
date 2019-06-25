//------------------------------------------------------------------------------
// pdbdump.c - dump symbols from .pdb and executable files (public domain).
//           - to compile; cl.exe /Ox /Zi pdbdump.c
//           -
//           - Martin Ridgers, pdbdump 'at' fireproofgravy.co.uk
//------------------------------------------------------------------------------

#include <stdio.h>
#include <Windows.h>
#include <DbgHelp.h>

#pragma comment(lib, "dbghelp.lib")

//------------------------------------------------------------------------------
const char* g_usage =
"pdbdump.exe - dump symbols from .pdb and executable files."                 "\n"
"  Martin Ridgers, pdbdump 'at' fireproofgravy.co.uk"                        "\n"
                                                                             "\n"
"    Usage: pdbdump.exe [-csv] [-sasnf] [-r] pdb_or_exe[:BASE]"              "\n"
"       -t: Enumerate types."                                                "\n"
"     -csv: Output comma-separated-values format."                           "\n"
" -s[asnf]: Sort by (a)ddress, (s)ize, (n)ame, or (f)ile. ASNF to reverse."  "\n"
"       -r: Resolve names and addresses read from stdin."                    "\n"
"  -w[...]: Wildcard to use when enumerating symbols."                       "\n"
                                                                             "\n"
" By default modules (.pdb or .exe files) are loaded with a base address of" "\n"
" 0x400000. This can be overriden by adding a :BASE suffix to the module's"  "\n"
" file name. For example; my_project.pdb:0x20030000."                        "\n"
                                                                             "\n"
" Examples: 1. Output all symbols from a.pdb and b.dll;"                     "\n"
"               > pdbdump.exe a.pdb b.dll"                                   "\n"
"           2. Output all of a.pdb's function symbols in CSV format;"        "\n"
"               > pdbdump.exe -csv a.pdb | findstr SymTagFunction"           "\n"
"           3. List all symbols starting with 'is_enab';"                    "\n"
"               > pdbdump.exe -wis_enab* a.pdb"                              "\n"
"           4. Resolve two symbols by name and by address;"                  "\n"
"               > echo 0x401000 is_enabled | pdbdump.exe -r a.pdb"           "\n"
;

//------------------------------------------------------------------------------
#define ENABLE_DEBUG_OUTPUT     0
#define ASSERT(x, m, ...)       if (!(x)) { fprintf(stderr, m, __VA_ARGS__);    \
                                    exit(-1); }
#define ONE_MB                  (1024 * 1024)

//------------------------------------------------------------------------------
enum e_mode
{
    e_mode_resolve_stdin,
    e_mode_enum_symbols,
};

//------------------------------------------------------------------------------
enum e_enum_type
{
    e_enum_type_symbols,
    e_enum_type_types
};

//------------------------------------------------------------------------------
struct _sym_info
{
    DWORD64     addr;
    int         size;
    char*       name;
    char*       file;
    int         tag     : 8;
    int         line    : 24;
};
typedef struct _sym_info sym_info_t;

//------------------------------------------------------------------------------
struct _pool
{
    char*   base;
    int     committed;
    int     size;
    int     used;
};
typedef struct _pool pool_t;

//------------------------------------------------------------------------------
typedef int (sort_func_t)(const sym_info_t*, const sym_info_t*);

int                 g_page_size             = 0;
HANDLE              g_handle                = (HANDLE)0x493;
int                 g_csv_output            = 0;
int                 g_sym_count             = 0;
enum e_mode         g_mode                  = e_mode_enum_symbols;
int                 g_sort_order            = 1;
sort_func_t*        g_sort_func             = NULL;
enum e_enum_type    g_enum_type             = e_enum_type_symbols;
const char*         g_wildcard              = "*";
pool_t              g_symbol_pool;
pool_t              g_string_pool;
extern const char*  g_sym_tag_names[];      /* ...at end of file */

//------------------------------------------------------------------------------
void pool_create(pool_t* pool, int size)
{
    pool->base = (char*)VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_READWRITE);
    pool->size = size;
    pool->committed = 0;
    pool->used = 0;
}

//------------------------------------------------------------------------------
void pool_destroy(pool_t* pool)
{
    VirtualFree(pool->base, 0, MEM_RELEASE);
}

//------------------------------------------------------------------------------
void pool_clear(pool_t* pool)
{
    pool->used = 0;
}

//------------------------------------------------------------------------------
void* pool_alloc(pool_t* pool, int size)
{
    int i;
    char* addr;

    ASSERT(size < g_page_size, "Allocation to large!");

    i = pool->used + size;
    if (i >= pool->committed)
    {
        ASSERT(i < pool->size, "Memory pool exhausted.");
        VirtualAlloc((void*)(pool->base + pool->committed), g_page_size,
            MEM_COMMIT, PAGE_READWRITE
        );
        pool->committed += g_page_size;
    }

    addr = pool->base + pool->used;
    pool->used += size;
    return addr;
}

//------------------------------------------------------------------------------
int sort_addr(const sym_info_t* lhs, const sym_info_t* rhs)
{
    return (int)(lhs->addr - rhs->addr) * g_sort_order;
}

//------------------------------------------------------------------------------
int sort_size(const sym_info_t* lhs, const sym_info_t* rhs)
{
    return (lhs->size - rhs->size) * g_sort_order;
}

//------------------------------------------------------------------------------
int sort_name(const sym_info_t* lhs, const sym_info_t* rhs)
{
    return _stricmp(lhs->name, rhs->name) * g_sort_order;
}

//------------------------------------------------------------------------------
int sort_file(const sym_info_t* lhs, const sym_info_t* rhs)
{
    return _stricmp(lhs->file, rhs->file) * g_sort_order;
}

//------------------------------------------------------------------------------
void print_info(const char* info, ...)
{
    va_list va;

    va_start(va, info);
    vfprintf(stderr, info, va);
    va_end(va);
}

//------------------------------------------------------------------------------
void dbghelp_to_sym_info(SYMBOL_INFO* info, sym_info_t* sym_info)
{
    BOOL ok;
    DWORD disp;
    IMAGEHLP_LINE64 line;

    // General properties
    sym_info->addr = info->Address;
    sym_info->size = info->Size;
    sym_info->tag = info->Tag;

    // Symbol name
    sym_info->name = pool_alloc(&g_string_pool, info->NameLen + 1);
    strcpy(sym_info->name, info->Name);

    // Get file and line number info.
    line.SizeOfStruct = sizeof(line);
    ok = SymGetLineFromAddr64(g_handle, info->Address, &disp, &line);
    if ((ok != FALSE) && line.FileName)
    {
        sym_info->line = line.LineNumber;
        sym_info->file = pool_alloc(&g_string_pool, strlen(line.FileName) + 1);
        strcpy(sym_info->file, line.FileName);
    }
    else
    {
        sym_info->line = 0;
        sym_info->file = "?";
    }
}

//------------------------------------------------------------------------------
BOOL CALLBACK enum_proc(SYMBOL_INFO* info, ULONG size, void* param)
{
    sym_info_t* sym_info;

    sym_info = (sym_info_t*)pool_alloc(&g_symbol_pool, sizeof(sym_info_t));
    dbghelp_to_sym_info(info, sym_info);

    if (!(g_sym_count % 100))
    {
        print_info("\r%d", g_sym_count);
    }
    ++g_sym_count;

    return TRUE;
}

//------------------------------------------------------------------------------
void print_symbol(const sym_info_t* sym_info)
{
    const char* format;

    format = "%016llx %10d %-21s %-32s %s(%d)\n";
    if (g_csv_output)
    {
        format = "\"%llx\",%d,\"%s\",\"%s\",\"%s\",%d\n";
    }

    printf(
        format, sym_info->addr, sym_info->size, g_sym_tag_names[sym_info->tag],
        sym_info->name, sym_info->file, sym_info->line
    );
}

//------------------------------------------------------------------------------
int create_pools(uintptr_t base_addr)
{
    BOOL ok;
    FILE* in;
    int size, i;
    const char* guide;

    // Fetch PDB file for the module.
    IMAGEHLP_MODULE64 module = { sizeof(module) };
    ok = SymGetModuleInfo64(g_handle, base_addr, &module);
    ASSERT(ok != FALSE, "Unexpected failure from SymGetSymbolFile().");

    guide = module.LoadedPdbName;

    // An .exe with no symbols available?
    if (!guide || guide[0] == '\0')
    {
        return 0;
    }

    // Get file size.
    in = fopen(guide, "rb");
    ASSERT(in != NULL, "Failed to open pool-size guide file.");

    fseek(in, 0, SEEK_END);
    size = ftell(in);
    fclose(in);

    // Use anecdotal evidence to guess at suitable pool sizes :).
    i = size / 4;
    pool_create(&g_string_pool, (i < ONE_MB) ? ONE_MB : i);

    i = size / 25;
    pool_create(&g_symbol_pool, (i < ONE_MB) ? ONE_MB : i);

    return 1;
}

//------------------------------------------------------------------------------
uintptr_t load_module(const char* pdb_file)
{
    char buffer[512];
    char* colon;
    uintptr_t base_addr = 0x400000;

    strncpy(buffer, pdb_file, 512);
    buffer[sizeof(buffer) - 1] = '\0';

    // Is there a base address tag on the end of the file name?
    colon = strrchr(buffer, ':');
    if (colon && (ptrdiff_t)(colon - buffer) > 1)
    {
        *colon++ = '\0';
        base_addr = (uintptr_t)_strtoui64(colon, NULL, 0);
    }

    base_addr = (size_t)SymLoadModuleEx(g_handle, NULL, buffer, NULL,
        base_addr, 0x7fffffff, NULL, 0
    );

    return base_addr;
}

//------------------------------------------------------------------------------
void output_symbols(const char* pdb_file)
{
    int i;
    uintptr_t base_addr;
    DWORD ok;

    // Load module.
    base_addr = load_module(pdb_file);
    if (!base_addr)
    {
        print_info("Failed to load symbols for '%s' (Error %d)", pdb_file,
            GetLastError()
        );
        return;
    }

    if (!create_pools(base_addr))
    {
        print_info("No symbols found for '%s'", pdb_file);
        return;
    }

    g_sym_count = 0;

    // Do the enumeration.
    print_info("Enumerating...\n");
    switch (g_enum_type)
    {
    case e_enum_type_symbols:
        SymEnumSymbols(g_handle, base_addr, g_wildcard, enum_proc, NULL);
        break;

    case e_enum_type_types:
        SymEnumTypes(g_handle, base_addr, enum_proc, NULL);
        break;
    }
    print_info("\r%d\n...Done!\n", g_sym_count);

    // Done.
    ok = SymUnloadModule64(g_handle, (DWORD64)base_addr);
    ASSERT(ok != FALSE, "Failed unloading module.");

    // Sort.
    if (g_sort_func != NULL)
    {
        qsort(g_symbol_pool.base, g_sym_count, sizeof(sym_info_t),
            (int (*)(const void*, const void*))g_sort_func
        );
    }

    // Print to stdout
    for (i = 0; i < g_sym_count; ++i)
    {
        sym_info_t* sym_info = ((sym_info_t*)g_symbol_pool.base) + i;
        print_symbol(sym_info);
    }

    pool_destroy(&g_string_pool);
    pool_destroy(&g_symbol_pool);
}

//------------------------------------------------------------------------------
void resolve_stdin()
{
    pool_create(&g_string_pool, g_page_size);

    while (!feof(stdin))
    {
        int i;
        int state;
        char buffer[256];
        BOOL ok;

        struct {
            SYMBOL_INFO info;
            char name_buf[256];
        } si;

        si.info.SizeOfStruct = sizeof(si.info);
        si.info.MaxNameLen = sizeof(si.name_buf);

        // Parse things on the command line.
        state = 0;
        i = 0;
        while (!feof(stdin) && (i < sizeof(buffer) - 1))
        {
            fread(buffer + i, 1, 1, stdin);
            if (!!isspace(buffer[i]) == state)
            {
                if (++state > 1)
                {
                    break;
                }
            }

            i += state;
        }
        
        buffer[i] = '\0';
        if (i == 0)
        {
            continue;
        }

        if (isdigit(buffer[0]))
        {
            DWORD64 addr = (DWORD64)_strtoui64(buffer, NULL, 0);  
            ok = SymFromAddr(g_handle, addr, NULL, &si.info);
        }
        else
        {
            ok = SymFromName(g_handle, buffer, &si.info);
        }

        pool_clear(&g_string_pool);
        if (ok != FALSE)
        {
            sym_info_t sym_info;
            dbghelp_to_sym_info(&si.info, &sym_info);
            print_symbol(&sym_info);
        }
    }

    pool_destroy(&g_string_pool);
}

//------------------------------------------------------------------------------
void parse_args(int argc, char** argv)
{
    int i;

    for (i = 0; i < argc; ++i)
    {
        const char* arg = argv[i];
        if (strcmp(arg, "-csv") == 0)
        {
            g_csv_output = 1;
        }
        else if (strncmp(arg, "-s", 2) == 0)
        {
            char c = arg[2];
            c = isupper(c) ? tolower(c) : c;
            switch (c)
            {
            case '\0':
            case 'a':   g_sort_func = sort_addr;    break;
            case 's':   g_sort_func = sort_size;    break;
            case 'n':   g_sort_func = sort_name;    break;
            case 'f':   g_sort_func = sort_file;    break;
            }

            g_sort_order = (arg[2] < 'a') ? -1 : 1;
        }
        else if (strcmp(arg, "-r") == 0)
        {
            g_mode = e_mode_resolve_stdin;
        }
        else if (strcmp(arg, "-t") == 0)
        {
            g_enum_type = e_enum_type_types;
        }
        else if (strncmp(arg, "-w", 2) == 0)
        {
            if (arg[2] != '\0')
            {
                g_wildcard = arg + 2;
            }
        }
    }
}

//------------------------------------------------------------------------------
int main(int argc, char** argv)
{
    int i;
    BOOL ok;
    DWORD options;
    SYSTEM_INFO sys_info;

    if (argc <= 1)
    {
        puts(g_usage);
        return -1;
    }

    --argc;
    ++argv;
    parse_args(argc, argv);

    // Get page size.
    GetSystemInfo(&sys_info);
    g_page_size = sys_info.dwPageSize;

    // Initialise DbgHelp
    options = SymGetOptions();
    options &= ~SYMOPT_DEFERRED_LOADS;
    options |= SYMOPT_LOAD_LINES;
    options |= SYMOPT_IGNORE_NT_SYMPATH;
#if ENABLE_DEBUG_OUTPUT
    options |= SYMOPT_DEBUG;
#endif
    options |= SYMOPT_UNDNAME;
    SymSetOptions(options);

    ok = SymInitialize(g_handle, NULL, FALSE);
    ASSERT(ok != FALSE, "Failed to initialise symbol handler.");

    // Output each .PDB file specified on the command line.
    switch (g_mode)
    {
    case e_mode_enum_symbols:
        for (i = 0; i < argc; ++i)
        {
            const char* arg = argv[i];
            if (arg[0] != '-')
            {
                output_symbols(arg);
            }
        }
        break;

    case e_mode_resolve_stdin:
        for (i = 0; i < argc; ++i)
        {
            const char* arg = argv[i];
            if (arg[0] != '-')
            {
                load_module(arg);
            }
        }
        resolve_stdin();
        break;
    }

    SymCleanup(g_handle);
    return 0;
}

//------------------------------------------------------------------------------
const char* g_sym_tag_names[] = { 
    "SymTagNull", "SymTagExe", "SymTagCompiland", "SymTagCompilandDetails",
    "SymTagCompilandEnv", "SymTagFunction", "SymTagBlock", "SymTagData",
    "SymTagAnnotation", "SymTagLabel", "SymTagPublicSymbol", "SymTagUDT",
    "SymTagEnum", "SymTagFunctionType", "SymTagPointerType", "SymTagArrayType",
    "SymTagBaseType", "SymTagTypedef", "SymTagBaseClass", "SymTagFriend",
    "SymTagFunctionArgType", "SymTagFuncDebugStart", "SymTagFuncDebugEnd",
    "SymTagUsingNamespace", "SymTagVTableShape", "SymTagVTable", "SymTagCustom",
    "SymTagThunk", "SymTagCustomType", "SymTagManagedType", "SymTagDimension"
};
