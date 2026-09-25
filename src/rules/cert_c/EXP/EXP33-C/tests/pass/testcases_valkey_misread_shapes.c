/*
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation
 */

/*
 * Rule: EXP33-C - Do not read uninitialized memory
 * Status: PASS
 * Reason: Four shapes where nothing indeterminate is read, each distilled
 *         from valkey:
 *         - module.c: a `#if ... __has_include(<dlfcn.h>)` condition. Its
 *           mis-parse swallowed the assignment below the `#endif`, which then
 *           read as a use of `handle`.
 *         - setproctitle.c: `extern char **environ;` at block scope names the
 *           libc object; it declares nothing that could be uninitialized.
 *         - valkey-cli.c: `p = buf` then `read_byte(c, p, 1)` fills `*p`
 *           through the pointer exactly as passing `buf` would, and `p != buf`
 *           compares addresses.
 *         - evict.c: a variable declared inside a loop body is out of scope
 *           after it, so `db` there (a macro's type token) is not that
 *           variable.
 */

#include <stddef.h>

void *dlopen(const char *path, int flags);
int read_byte(void *c, char *buf, size_t len);
void trace(const char *event, long v);

#define TRACE_IF_NEEDED(type, event, var) trace(#type "_" #event, (var))

typedef struct {
    int id;
} db_t;

db_t *pick(int i);

int load(const char *path)
{
    void *handle;
    int flags = 1;
#if defined(__GLIBC__) && __has_include(<dlfcn.h>)
    flags |= 2;
#endif

    handle = dlopen(path, flags);
    return handle == NULL;
}

int env_moved(char **oldenv)
{
    extern char **environ;
    return environ != oldenv;
}

int read_line(void *c)
{
    char buf[64], *p;
    p = buf;
    while (1) {
        if (read_byte(c, p, 1) <= 0)
            return -1;
        if (*p == '\n' && p != buf)
            break;
        if (*p != '\n')
            p++;
        if (p >= buf + sizeof(buf) - 1)
            break;
    }
    *p = '\0';
    return (int)(p - buf);
}

int evict(int n)
{
    long latency = 0;
    while (n-- > 0) {
        db_t *db;
        if (n > 5)
            db = pick(n);
        if (n == 3)
            break;
    }
    TRACE_IF_NEEDED(db, eviction, latency);
    return 0;
}
