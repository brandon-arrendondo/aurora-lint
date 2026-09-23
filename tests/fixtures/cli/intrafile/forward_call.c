/* Calls two functions before their definitions further down the SAME file.
 * DCL31-C's sequential walk sees each call before any declaration; only a
 * prescan of this very file makes them known. A scan with no -d must build
 * that context for its own target. */
void caller_function(void) {
    int result = helper_compute(42);
    process_buffer("hello", 5);
    (void)result;
}

int helper_compute(int value) {
    return value * 2;
}

void process_buffer(const char *buf, int len) {
    (void)buf;
    (void)len;
}
