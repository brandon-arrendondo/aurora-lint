/*
 * Rule: WIN04-C
 * Source: testcases
 * Status: FAIL - Should trigger WIN04-C violation
 *
 * A GetProcAddress result is a function pointer by definition. Storing it
 * raw -- by assignment to an already-declared pointer, by a typedef'd
 * declaration, or from inside a helper macro's body -- is the same
 * unencrypted store the declaration-only check already reports for
 * `int (*p)(...) = printf;`. Shapes are Ventoy2Disk's (DiskService.c:311,
 * Utility.c:323, process.h PF_INIT).
 */

typedef void *HMODULE;
typedef int (*FARPROC)(void);
FARPROC GetProcAddress(HMODULE module, const char *name);
HMODULE GetModuleHandleA(const char *name);

typedef int (*PFORMATEX)(const char *, int);
typedef int (*LPFN_ISWOW64PROCESS)(void *, int *);

static PFORMATEX FormatEx;

int load_format_entry(HMODULE ifsModule) {
    /* VIOLATION: assignment of a cast GetProcAddress result to a global */
    FormatEx = (PFORMATEX)GetProcAddress(ifsModule, "FormatEx");
    if (FormatEx == 0) {
        return 0;
    }
    return FormatEx("C:", 1);
}

int is_wow64(void *process) {
    /* VIOLATION: typedef'd function-pointer declaration filled by GetProcAddress */
    LPFN_ISWOW64PROCESS fnIsWow64Process =
        (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
    int wow = 0;
    if (fnIsWow64Process != 0) {
        fnIsWow64Process(process, &wow);
    }
    return wow;
}

/* VIOLATION: the macro body stores a raw GetProcAddress result at every use */
#define PF_INIT(proc, name) \
    if (pf##proc == 0) pf##proc = (proc##_t)GetProcAddress(GetModuleHandleA(#name), #proc)
