/*
 * Rule: EXP34-C
 * Source: synthetic
 * Status: PASS - Should NOT trigger EXP34-C violation
 *
 * DEBUGASSERT() is assert() in a debug build and empty otherwise. The
 * dereference in DEBUGASSERT(data->conn) exists only in a build where
 * DEBUGASSERT(data) has already asserted `data`, so the later test of
 * `data` does not follow an unguarded dereference.
 */
#include <assert.h>
#include <stddef.h>

#ifdef DEBUGBUILD
#define DEBUGASSERT(x) assert(x)
#else
#define DEBUGASSERT(x) do {} while(0)
#endif

struct conn { int fd; };
struct easy { struct conn *conn; };

int conn_fd(struct easy *data) {
    DEBUGASSERT(data);
    DEBUGASSERT(data->conn);
    if (data && data->conn)
        return data->conn->fd;
    return -1;
}
