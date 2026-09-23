/*
 * Rule: INT32-C
 * Source: real-world (hostapd/config_file.c:2598 `val * 8` with `int val =
 *         atoi(pos)`, masked by another function's `unsigned long val`;
 *         valkey cluster_legacy.c:736 `j + 1` masked by `unsigned int j`)
 * Status: FAIL - `val * 8` on an unbounded `int val = atoi(pos)` is a signed
 *         multiplication that can overflow.
 *
 * The mirror image of the PASS fixture: this function is declared through
 * a two-argument macro (hostap's `SM_STATE(M, S)` shape; a one-argument
 * macro still parses as a `macro_type_specifier`), so it is not a parsed
 * `function_definition` and the rule used its
 * file-wide, name-keyed type map, which handed it the OTHER function's
 * `unsigned long val` and silently skipped the multiplication as unsigned.
 * Resolving the occurrence to its own `int` declaration restores the
 * finding. The `atoi` source makes the operand risky enough to report; the
 * other function's arithmetic is unsigned and stays quiet, so this is the
 * only flaggable line.
 */

#include <stdlib.h>

#define HANDLER(group, name) static void handle_##group##_##name(const char *pos, int *out)

HANDLER(config, bits)
{
    int val = atoi(pos);
    *out = val * 8;
}

unsigned long parse_mask(const char *pos)
{
    char *endp;
    unsigned long val = strtoul(pos, &endp, 0);
    return val * 8;
}
