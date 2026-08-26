/*
 * Rule: ARR02-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR02-C violation
 */

/* Genuinely ambiguous: no initializer at all determines the bound, and
 * this is not `extern` (whose definition-site size is elsewhere). This is
 * the true "unspecified/ambiguous bound" case ARR02-C targets (task 567). */
int ambiguous_bound[];

int main() {
    return ambiguous_bound[0];
}
