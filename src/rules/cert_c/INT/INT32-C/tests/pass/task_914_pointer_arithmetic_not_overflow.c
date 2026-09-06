/*
 * Rule: INT32-C
 * Source: task 914 (pure-ftpd ftpd.c:2824, hostap ctrl_iface.c:8346)
 * Status: PASS - Should NOT trigger INT32-C violation
 * Reason: `resolved_path + n` offsets a file-scope pointer and
 *         `head_u8(resp) + start` offsets a pointer-returning call's result.
 *         Pointer arithmetic is well defined and bounded by the pointee
 *         object; it is not signed integer overflow.
 */

#include <stdlib.h>

static char *resolved_path;

char *offset_global(void) {
    int n = atoi(getenv("N"));
    return resolved_path + n;
}

unsigned char *head_u8(void *buf);

unsigned char *offset_call_result(void *resp) {
    int start = atoi(getenv("S"));
    return head_u8(resp) + start;
}
