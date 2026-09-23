/*
 * Rule: ARR30-C
 * Source: real-world (hostap src/drivers/linux_ioctl.c:216, src/utils/trace.c:67,
 *         curl lib/http1.c:218)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: each index was range-checked by an early-return guard before the
 *         access -- `if (res < 0 || (size_t) res >= sizeof(buf)) return -1;`
 *         -- so control past the guard has both disjuncts false and
 *         `res < sizeof(buf)`. The bounds checks only looked at an `if` or
 *         `for` ENCLOSING the access; a guard that precedes it was invisible,
 *         and every `readlink()`-terminating `buf[res] = '\0'` in the corpus
 *         was reported. The cast on the index and the cast on the bound are
 *         both transparent, and `sizeof` of the very array being indexed is
 *         its byte size -- an element bound because the elements are bytes.
 */

#include <unistd.h>

int bridge_link(const char *path)
{
    char brlink[128];
    int res = readlink(path, brlink, sizeof(brlink));

    if (res < 0 || (size_t) res >= sizeof(brlink))
        return -1;
    brlink[res] = '\0';
    return 0;
}

void prg_name(const char *exe)
{
    char fname[512];
    int len = readlink(exe, fname, sizeof(fname) - 1);

    if (len < 0 || len >= (int) sizeof(fname)) {
        return;
    }
    fname[len] = '\0';
}

size_t rd_len(void);

int url_target(void)
{
    char tmp[8192];
    size_t target_len = rd_len();

    if (target_len >= sizeof(tmp))
        goto out;
    tmp[target_len] = '\0';
    return 0;
out:
    return -1;
}
