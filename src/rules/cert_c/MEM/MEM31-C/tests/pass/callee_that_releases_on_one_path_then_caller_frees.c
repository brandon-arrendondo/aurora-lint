/*
 * Rule: MEM31-C
 * Source: real-world (sqlite: sqlite3_result_error(ctx, zMsg, -1) copies
 *         the message, then the caller releases its own copy)
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: `set_result` takes ownership of `text` only when told the
 * block is its to keep; otherwise it copies into the caller's buffer. A
 * caller that passes 0 and then frees its own block frees it once. A callee
 * that releases its argument on some path only cannot back a double-free
 * accusation.
 */
#include <stdlib.h>
#include <string.h>

void set_result(char *out, size_t size, char *text, int take)
{
    strncpy(out, text, size - 1);
    out[size - 1] = '\0';
    if (take) {
        free(text);
    }
}

void report(char *out, size_t size, const char *what)
{
    char *msg = malloc(64);
    if (msg == NULL) {
        return;
    }
    strncpy(msg, what, 63);
    msg[63] = '\0';
    set_result(out, size, msg, 0);
    free(msg);
}
