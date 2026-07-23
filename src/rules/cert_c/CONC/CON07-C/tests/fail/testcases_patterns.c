/* Rule: CON07-C
 * Source: testcases
 * Status: FAIL - Compound operations on shared variables without atomicity
 */

/* Case 1: Two static variables accessed in one function without mutex */
static int x;
static int y;

int get_product(void) {
    return x * y;
}

void set_xy(int nx, int ny) {
    x = nx;
    y = ny;
}

/* Case 2: Compound assignment (+=) on static variable without protection */
static int total;

void accumulate(int value) {
    total += value;
}

/* Case 3: Increment on static variable without protection */
static int event_count;

void log_event(void) {
    event_count++;
}
