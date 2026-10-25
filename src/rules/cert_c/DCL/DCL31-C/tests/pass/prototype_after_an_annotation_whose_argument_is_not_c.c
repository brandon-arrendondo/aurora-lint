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
 * prototype as a call inside it). With an export macro and a calling
 * convention between the annotations and the name, as in open_file and
 * probe, the same misreading reached this file's own prototypes too, and
 * an annotation nested in another's argument (WHEN(...)) is blanked whole.
 */

typedef int status_t;
typedef struct record record;

CHECKED_RESULT
ON_SUCCESS(return == 0)
status_t open_record(record **out, const char *name);

ON_SUCCESS(return != 0)
CHECKED_RESULT
status_t close_record(record *r);

CHECKED_RESULT ON_SUCCESS(return == 0) EXPORTED status_t CALLCONV
open_file(record **out, const char *path, const char *mode);

WHEN(flags > 0, ON_SUCCESS(return != 0)) EXPORTED int CALLCONV probe(int flags);

int reopen(record **r)
{
    if (probe(1) == 0) {
        return -1;
    }
    return open_file(r, "b", "r");
}

int use(void)
{
    record *r = 0;
    if (open_record(&r, "a") != 0) {
        return -1;
    }
    return close_record(r);
}
