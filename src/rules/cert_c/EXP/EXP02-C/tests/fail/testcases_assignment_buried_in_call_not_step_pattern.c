/*
 * Rule: EXP02-C
 * Source: task 1151/1154 (fail-twin guard: an assignment buried inside a
 *   call's own argument is not the "assign-and-test" idiom -- the boolean
 *   chain never examines the assigned value, so a skipped occurrence is a
 *   silent miss, not a self-contained test)
 * Status: FAIL - Should trigger EXP02-C violation
 */
int risky(void);
int record_value(int v);

int guarded_record(int flag, int x) {
    if (flag && record_value(x = risky())) {
        return 1;
    }
    return 0;
}
