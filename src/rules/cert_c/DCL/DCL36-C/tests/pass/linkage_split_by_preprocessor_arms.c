/*
 * Rule: DCL36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL36-C violation
 *
 * Each identifier is declared once per arm of an #if/#else. No translation
 * unit holds both arms, so the two declarations never meet.
 */

#ifdef BUILD_SHARED
int log_level;
#else
static int log_level;
#endif

#if defined(USE_POOL)
static int pool_size = 64;
#elif defined(USE_HEAP)
int pool_size = 0;
#else
extern int pool_size;
#endif

int main(void) {
    return log_level + pool_size;
}
