/*
 * Rule: MEM31-C
 * Source: task_580
 * Status: FAIL - Should trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: FAIL
 * Reason: Task 580's value-local exclusion keys off pointer *evidence*, not
 * the declarator alone, so a pointer typedef declared without a `*` is still
 * tracked: dereferencing it (`h->field`) or NULL-checking it proves it holds
 * a pointer, and the missing free is a genuine leak.
 */

struct obj {
    int field;
};
typedef struct obj *obj_handle;

obj_handle obj_new(void);

void leak_through_pointer_typedef(void)
{
    obj_handle h = obj_new();
    h->field = 1;
}

void leak_through_null_checked_typedef(void)
{
    obj_handle g = obj_new();
    if (g == NULL) {
        return;
    }
}
