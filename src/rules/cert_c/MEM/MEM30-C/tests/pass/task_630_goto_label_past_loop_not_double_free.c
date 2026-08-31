/*
 * Rule: MEM30-C
 * Source: task_630
 * Status: PASS - Should NOT trigger MEM30-C violation
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: PASS
 * Reason: hostap src/eap_peer/eap_sim.c:274 pattern. A forward `goto
 * invalid;` inside a loop jumps PAST the loop to a label placed after the
 * normal fallthrough path's own `free()` + `return`. The label is reached
 * ONLY via the goto (the immediately preceding statement is an
 * unconditional `return`, so fallthrough into the label is impossible),
 * so its own `free()` is a separate, mutually exclusive path from the
 * fallthrough one -- not a double-free, and previously mis-flagged
 * because the checker's linear state walk carried the fallthrough path's
 * "already freed" state across the label boundary.
 */

#include <stdlib.h>
#include <string.h>

extern int hexstr2bin(const char *s, unsigned char *out, unsigned int len);

int parse_response(char *resp, unsigned char *out, unsigned int n) {
    char *pos = resp;
    unsigned int i;

    for (i = 0; i < n; i++) {
        if (hexstr2bin(pos, out, 4) < 0)
            goto invalid;
        pos += 8;
    }

    free(resp);
    return 0;

invalid:
    free(resp);
    return -1;
}
