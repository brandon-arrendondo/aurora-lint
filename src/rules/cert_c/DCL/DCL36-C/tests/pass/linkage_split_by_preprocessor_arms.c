/*
 * Rule: DCL36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger DCL36-C violation
 *
 * Each identifier is declared once per arm of an #if/#else. No translation
 * unit holds both arms, so the two declarations never meet, and an extern
 * after the chain agrees with whichever arm a configuration keeps.
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

/* An extern after the chain takes the linkage of whichever arm the
 * configuration kept, so it agrees with each arm on its own. */
#ifdef BUILD_LOCAL
static int event_count;
#else
int event_count;
#endif
extern int event_count;

int main(void) {
    return log_level + pool_size + event_count;
}
