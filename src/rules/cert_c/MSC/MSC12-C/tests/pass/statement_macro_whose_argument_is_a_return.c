/*
 * Rule: MSC12-C
 * Source: custom
 * Status: PASS - Should NOT trigger MSC12-C violation
 * Description: A fault-injection macro takes a statement as its argument
 * and expands it only in a test build, as in `FAULT_INJECT( return ERR_IO );`
 * below. The macro is defined in a header this file does not show, so the
 * parser sees the invocation as written. The `;` ends a macro call, not an
 * empty statement, so there is no stray semicolon to report. Blanking the
 * invocation as a non-C annotation argument once left the `;` alone in the
 * if-block.
 */

int read_block(int fd, char *buf, int len)
{
    FAULT_INJECT( return ERR_IO );
    if (len <= 0) {
        FAULT_INJECT(return ERR_EMPTY);
    }
    buf[0] = (char)fd;
    return len;
}
