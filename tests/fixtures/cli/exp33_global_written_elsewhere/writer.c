extern int globalFalse;

/* Another file writes the flag, so it is not a constant. */
void enable(void) {
    globalFalse = 1;
}
