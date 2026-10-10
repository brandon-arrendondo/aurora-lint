/* Malformed: the macro body's loop condition never closes its parenthesis. */
#define SPIN_UNTIL(c) do { } while (!(c)
int ready;
void wait_ready(void) { SPIN_UNTIL(ready); }
