/*
 * Rule: WIN04-C
 * Source: testcases
 * Status: PASS - Should NOT trigger WIN04-C violation
 *
 * Every GetProcAddress result here is either wrapped by EncodePointer in
 * the store itself, or re-encoded before the function returns; a plain
 * non-function-pointer assignment and a GetProcAddress call that is only
 * compared, never stored, are not stores at all.
 */

typedef void *HMODULE;
typedef int (*FARPROC)(void);
FARPROC GetProcAddress(HMODULE module, const char *name);
void *EncodePointer(void *ptr);
void *DecodePointer(void *ptr);

typedef int (*PFORMATEX)(const char *, int);

static void *g_encoded_format;
static PFORMATEX g_raw;

int load_encoded(HMODULE ifsModule) {
    /* COMPLIANT: encoded in the store */
    g_encoded_format = EncodePointer((void *)GetProcAddress(ifsModule, "FormatEx"));
    return g_encoded_format != 0;
}

int load_then_encode(HMODULE ifsModule) {
    /* COMPLIANT: raw store immediately re-encoded in the same function */
    g_raw = (PFORMATEX)GetProcAddress(ifsModule, "FormatEx");
    if (g_raw == 0) {
        return 0;
    }
    g_encoded_format = EncodePointer((void *)g_raw);
    return 1;
}

int probe_only(HMODULE ifsModule) {
    int count = 0;
    /* not a function-pointer store: the result is tested, never kept */
    if (GetProcAddress(ifsModule, "FormatEx") != 0) {
        count = 1;
    }
    /* a plain integer assignment is not a function pointer */
    count = count + 1;
    return count;
}

int use_decoded(void) {
    PFORMATEX fn = (PFORMATEX)DecodePointer(g_encoded_format);
    return fn("C:", 0);
}
