/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. `get_current_host`
 * fills both outputs on every path -- the bail-out arm writes them directly,
 * and the remaining path hands them to `f->query` through a function pointer
 * before the final `if` can skip its body. No analysis resolves that call, so
 * the callee never reaches the MUST-write set; withholding the caller's
 * initialization credit on that absence alone reports every caller of curl's
 * `Curl_conn_get_current_host` (task 1065 bug #3, tools_sqc). The conditional
 * -writer set is proof of an unwritten returning path, and there is none here.
 */
#include <stddef.h>

struct filter {
    int (*query)(struct filter *f, const char **phost, int *pport);
    struct filter *next;
};

struct ctx {
    struct filter *proxy;
    const char *host;
    int port;
    int connected;
};

static void get_current_host(struct ctx *c, const char **phost, int *pport)
{
    struct filter *f;

    if (!c->connected) {
        *phost = "";
        *pport = -1;
        return;
    }

    f = c->proxy;
    if (!f || f->query(f, phost, pport)) {
        *phost = c->host;
        *pport = c->port;
    }
}

void caller(struct ctx *c, void (*use)(const char *, int))
{
    const char *hostname;
    int port;

    get_current_host(c, &hostname, &port);
    use(hostname, port);
}
