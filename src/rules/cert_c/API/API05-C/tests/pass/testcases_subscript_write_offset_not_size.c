/*
 * Rule: API05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger API05-C violation
 */

/*
 * Reason: `pkt[start]`/`pkt[start + 1]`/`pkt[start + 2]` treats `start` as a
 * write cursor/offset the caller advances between calls, not pkt's total
 * length -- a forward-offset subscript is not evidence that `start` bounds
 * `pkt`'s size (task 190; real example: curl's mqtt.c add_passwd()).
 */

#include <stddef.h>

static int add_passwd(const char *passwd, size_t plen, char *pkt, size_t start)
{
    if (plen > 0xffff)
        return 1;
    pkt[start] = (char)((plen >> 8) & 0xFF);
    pkt[start + 1] = (char)(plen & 0xFF);
    return 0;
}
