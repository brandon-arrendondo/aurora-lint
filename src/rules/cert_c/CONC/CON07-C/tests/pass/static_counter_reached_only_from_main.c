/*
 * Rule: CON07-C
 * Source: testcases
 * Status: PASS - Should NOT trigger CON07-C violation
 */

/*
 * Rule: CON07-C - Ensure that compound operations on shared variables are atomic
 * Status: PASS
 * Reason: The compound operation is in a static function whose only caller is
 * main(), and nothing creates a thread. main() is called once, at program
 * startup, by the execution environment (C11 5.1.2.2), so the increment only
 * ever runs on the initial thread.
 */

static int event_count;

static void record_event(void)
{
    event_count++;
}

int main(void)
{
    record_event();
    return 0;
}
