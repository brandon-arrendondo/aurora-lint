/*
 * Rule: DCL31-C
 * Source: custom
 * Status: FAIL - recovering a prototype from behind an annotation whose
 * argument names `return` must not hide a call that nothing declares.
 *
 * open_record is declared behind `ON_SUCCESS(return == 0)`; never_declared
 * is not, and is still reported.
 */

typedef int status_t;
typedef struct record record;

CHECKED_RESULT
ON_SUCCESS(return == 0)
status_t open_record(record **out, const char *name);

int use(void)
{
    record *r = 0;
    if (open_record(&r, "a") != 0) {
        return -1;
    }
    return never_declared(r);
}
