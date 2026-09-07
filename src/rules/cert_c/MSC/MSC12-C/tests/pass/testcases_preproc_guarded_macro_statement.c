/*
 * Rule: MSC12-C
 * Status: PASS - a macro invoked as a bare statement under the guard that
 *         tests for it. The #if is the codebase asserting the name is a
 *         macro; sqlite3MemoryBarrier() is written exactly this way.
 *         Nothing local #defines it, so is_known_macro cannot see it.
 */

void memory_barrier(void)
{
#if defined(SQC_TEST_MEMORY_BARRIER)
    SQC_TEST_MEMORY_BARRIER;
#endif
}
