/*
 * Rule: CON07-C
 * Source: testcases
 * Status: FAIL - Should trigger CON07-C violation
 */

/*
 * Rule: CON07-C - Ensure that compound operations on shared variables are atomic
 * Status: FAIL
 * Reason: No thread is created anywhere in this file, but record_event() has
 * external linkage: code outside the scanned source calls it, from whatever
 * thread it likes, so nothing shows the increment runs on one thread only.
 */

static int event_count;

void record_event(void)
{
    event_count++;
}
