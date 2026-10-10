/* A macro whose loop condition is the last thing in its body; the argument has no side effect. */
#define SPIN_UNTIL(c) do { } while (!(c))
int ready;
void wait_ready(void) { SPIN_UNTIL(ready); }
