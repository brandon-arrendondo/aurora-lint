/*
 * Rule: FIO30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger FIO30-C violation
 */

/*
 * Rule: FIO30-C - Exclude user input from format strings
 * Status: PASS
 * Reason: The format is found and judged by what the argument holds, not by
 *         how it is spelled. A comment between arguments is not an argument,
 *         so the literal after it is still the format. A cast converts the
 *         value it is given, so a cast literal is a literal. Parentheses or
 *         a cast around a forwarded format parameter still forward the
 *         parameter, as the bare parameter does.
 */

#include <stdarg.h>
#include <stdio.h>

void log_msg(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vprintf((format), ap);
    va_end(ap);
}

void log_msg_cast(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vprintf((const char *)format, ap);
    va_end(ap);
}

int main(int argc, char *argv[])
{
    char buf[64];

    snprintf(buf, sizeof(buf), /* TODO: widen the field */ "%d", argc);
    snprintf(buf, sizeof(buf),
             /* a note on the format */
             "%s", argv[0]);
    printf((const char *)"cast literal\n");
    printf((const char *)("parenthesized cast literal %d\n"), argc);
    puts(buf);
    return 0;
}
