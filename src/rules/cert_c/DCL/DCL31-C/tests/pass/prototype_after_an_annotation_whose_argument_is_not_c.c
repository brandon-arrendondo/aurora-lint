/*
 * Rule: DCL31-C
 * Source: custom
 * Status: PASS - Should NOT trigger DCL31-C violation
 * Description: An annotation language can write a postcondition as a macro
 * argument naming `return`, as in `CHECKED_RESULT ON_SUCCESS(return == 0)`
 * below. The macros are defined in a header this file does not show, so the
 * parser sees the invocation as written. No C expression holds `return`
 * between parentheses, so the invocation is blanked before the file is
 * read, and both prototypes and their calls must still be read as declared.
 * In a header the same shape had hidden the prototype from the prescan
 * (read as the declarator of a function named ON_SUCCESS, with the
 * prototype as a call inside it).
 */

typedef int status_t;
typedef struct record record;

CHECKED_RESULT
ON_SUCCESS(return == 0)
status_t open_record(record **out, const char *name);

ON_SUCCESS(return != 0)
CHECKED_RESULT
status_t close_record(record *r);

int use(void)
{
    record *r = 0;
    if (open_record(&r, "a") != 0) {
        return -1;
    }
    return close_record(r);
}
