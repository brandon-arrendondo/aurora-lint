/*
 * Rule: INT30-C
 * Source: regression
 * Status: FAIL - no data model is declared
 *
 * A linear congruential generator: after the first step the seed is at least
 * 12345, and 12345 * 1103515245 exceeds what any unsigned int can hold, so the
 * second and third steps wrap whatever the width of unsigned int. Without a
 * declared data model the seed's range has no upper end (ISO C does not bound
 * unsigned int above), and the product's range leaves what the analysis can
 * represent; its lower end alone already shows the wrap, and is still
 * reported. The first step is not: the seed starts at zero.
 */

struct timeval_like {
    long tv_usec;
    long tv_sec;
};

void seed(struct timeval_like *now, unsigned int *out) {
    static unsigned int randseed;
    static int seeded = 0;

    if (!seeded) {
        randseed += (unsigned int)now->tv_usec + (unsigned int)now->tv_sec;
        randseed = randseed * 1103515245 + 12345;
        randseed = randseed * 1103515245 + 12345; /* VIOLATION */
        randseed = randseed * 1103515245 + 12345; /* VIOLATION */
        seeded = 1;
    }
    *out = randseed;
}
