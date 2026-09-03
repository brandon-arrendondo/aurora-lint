/*
 * Rule: MSC12-C
 * Status: PASS - none of these guards is provably dead
 *
 * Companion to fail/testcases_subsumed_guard.c. Each case is one reason
 * check_subsumed_guard deliberately declines to fire (task 612).
 */

int read_byte(void);
int poll_ready(volatile int *reg);

/* Different subscript: not the same test. */
int distinct_subconditions(const char *z, int i, int n) {
    if (i + 3 >= n || (z[i + 1] & 0xC0) != 0x80 || (z[i + 2] & 0xC0) != 0x80) {
        return 1;
    }
    if ((z[i + 3] & 0xC0) != 0x80) {
        return 1;
    }
    return 0;
}

/* The first guard has an else, so falling through says nothing. */
int guard_has_else(int a, int b) {
    if (a > 0 || b > 0) {
        return 1;
    } else {
        a = 0;
    }
    if (b > 0) {
        return 2;
    }
    return 0;
}

/* The first guard's body does not leave the block. */
int guard_does_not_leave(int a, int b) {
    int r = 0;
    if (a > 0 || b > 0) {
        r = 1;
    }
    if (b > 0) {
        r = 2;
    }
    return r;
}

/* Calls may return something different on the second evaluation. */
int impure_condition(int n) {
    if (read_byte() < 0 || n < 0) {
        return 1;
    }
    if (read_byte() < 0) {
        return 2;
    }
    return 0;
}

/* A volatile object is re-read by design. */
int volatile_operand(volatile int *reg, int n) {
    if (*reg == 0 || n < 0) {
        return 1;
    }
    if (*reg == 0) {
        return 2;
    }
    return 0;
}

/* An intervening statement can change the answer. */
int intervening_statement(int a, int b) {
    if (a > 0 || b > 0) {
        return 1;
    }
    b = -b;
    if (b > 0) {
        return 2;
    }
    return 0;
}

/* A single-disjunct guard is check_duplicate_conditions' territory. */
int single_disjunct(int b) {
    if (b > 0) {
        return 1;
    }
    if (b > 0) {
        return 2;
    }
    return 0;
}
