/*
 * Rule: MEM31-C
 * Source: custom
 * Status: FAIL - Should trigger MEM31-C violation
 * Description: A cleanup label entered from two gotos, only one of which
 * freed the pointer first. The label's free is a double free on that path
 * and only that path.
 *
 * The goto that has NOT freed `p` comes first on purpose: the label's
 * must-freed entry state is the intersection over its gotos, {} ∩ {p} = {},
 * so a must-only reading can never report line 30. The rule also carries the
 * UNION of the gotos' freed states into the label (`goto_maybe_freed`), and
 * a free of a pointer in the union but not the intersection is reported as a
 * possible double free naming the path. Twin of tests/pass/
 * testcases_goto_label_free_on_no_incoming_path.c, where no goto freed it.
 */

#include <stdlib.h>

int finish(int c) {
    char *p = malloc(8);
    if (!p) return -1;
    if (c == 2) goto out;
    if (c == 1) {
        free(p);
        goto out;
    }
    return 0;
out:
    if (p) free(p);
    return 1;
}
