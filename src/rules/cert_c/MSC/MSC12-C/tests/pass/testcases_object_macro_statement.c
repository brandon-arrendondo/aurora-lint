/*
 * Rule: MSC12-C
 * Status: PASS - A bare identifier statement that is actually a
 * parenthesis-less object-like macro invocation (`NODE_LOCK_SYS;`) may
 * expand to real code (e.g. a lock acquire/release, a memory-barrier
 * instruction) that tree-sitter can't see without preprocessing. A macro
 * with a real `#define` in this file is not a no-effect bare identifier.
 */

#define NODE_LOCK_SYS do { acquire_lock(); } while (0)

void f(void) {
    NODE_LOCK_SYS;
}
