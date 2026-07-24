/*
 * Rule: MEM01-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM01-C violation (task 319)
 * Description: A free() immediately followed by return; inside a
 * #ifdef-gated block must not be treated as reaching the unconditional
 * free() that follows the #endif. sqc has no preprocessor, so both
 * branches of a conditional-compilation directive are ordinary reachable
 * AST -- the CFG builder must still recognize the nested return as a
 * real path terminator (hostap hostapd_ctrl_iface_receive() shape).
 */

#include <stdlib.h>

void handle_reply(int cookie_bad, int cookie_mismatch, char *reply) {
#ifdef CONFIG_CTRL_IFACE_UDP
    if (cookie_bad) {
        free(reply);
        return;
    }
    if (cookie_mismatch) {
        free(reply);
        return;
    }
#endif
    free(reply);
}
