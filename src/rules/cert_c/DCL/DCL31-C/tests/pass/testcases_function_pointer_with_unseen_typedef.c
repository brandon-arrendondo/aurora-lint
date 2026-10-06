/*
 * Rule: DCL31-C
 * Source: real-world (curl lib/cw-out.c)
 * Status: PASS - Should NOT trigger DCL31-C violation
 */

/*
 * Reason: a callee that names a parameter, a local or a file-scope object is
 * declared, whatever its type spelling. curl's `curl_write_callback wcb`
 * parameter is called as `wcb(...)`; its typedef lives in a header the scan
 * may never resolve, so recognising it by type alone left the call looking
 * undeclared. The callee is resolved to its declaration instead (ADR-0006).
 * `write_cb` below is deliberately never defined in this file.
 */

#include "unseen_api.h" /* would declare: typedef size_t (*write_cb)(char *, size_t, size_t, void *); */

static size_t call_param(write_cb wcb, char *buf, size_t len, void *ud)
{
    return wcb(buf, 1, len, ud);
}

static write_cb registered;

size_t call_global(char *buf, size_t len)
{
    return registered(buf, 1, len, 0);
}

size_t call_local(write_cb from, char *buf, size_t len)
{
    write_cb local = from;
    return local(buf, 1, len, 0) + call_param(from, buf, len, 0);
}
