/*
 * Rule: ARR30-C
 * Source: task 912 (sel4 src/machine/profiler.c:63,78,79,81)
 * Status: PASS - Should NOT trigger ARR30-C violation
 * Reason: `profiler_entries` is declared in BOTH arms of one #ifdef, at two
 *         different sizes. Which arm compiles depends on a macro this
 *         analysis does not evaluate, and the name-keyed buffer map simply
 *         kept whichever declaration it saw last -- so these accesses,
 *         inside the #ifdef arm, were reported against the #else arm's far
 *         larger array. Neither size is a fact about the built program, so
 *         no bound is claimed for this name at all.
 *
 *         The indices here are deliberately NOT bounded by the array size
 *         (`max_checkpoint` and `checkpoint` are separate globals), which is
 *         what made the real findings fire and state the wrong size.
 */

#define MAX_UNIQUE_CHECKPOINTS 2000
#define MAX_UNIQUE_INSTRUCTIONS 94349

typedef struct {
    unsigned long pc;
    unsigned long count;
} profiler_entry_t;

volatile unsigned int checkpoint;
unsigned int max_checkpoint;

#ifdef CHECKPOINT_PROFILER
profiler_entry_t profiler_entries[MAX_UNIQUE_CHECKPOINTS];
#else
profiler_entry_t profiler_entries[MAX_UNIQUE_INSTRUCTIONS];
#endif

#ifdef CHECKPOINT_PROFILER
void profiler_list(void) {
    unsigned int i;
    for (i = 0; i <= max_checkpoint; i++) {
        if (profiler_entries[i].pc != 0) {
            profiler_entries[i].count++;
        }
    }
}

void profiler_record_sample(void) {
    if (!profiler_entries[checkpoint].pc) {
        profiler_entries[checkpoint].pc = 1;
    }
    profiler_entries[checkpoint].count++;
}
#endif
