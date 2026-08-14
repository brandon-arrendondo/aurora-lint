/*
 * Rule: EXP33-C
 * Status: PASS - Should NOT trigger EXP33-C violation
 */

/*
 * Reason (task 391, hostap's rfkill.c): `read(fd, buf, count)`'s output
 * buffer is argument index 1, not 0 -- unlike `fread(ptr, ...)`, whose
 * buffer really is argument 0. `get_output_arg_indices` previously
 * hardcoded index 0 for "read"/"recv" too, so `read(fd, &event,
 * sizeof(event))` never marked `event` as initialized (index 0 is the file
 * descriptor, a plain int).
 */

struct rfkill_event {
    unsigned int idx;
    unsigned char type;
    unsigned char op;
};

int read(int fd, void *buf, unsigned long count);

void process_event(int fd)
{
    struct rfkill_event event;
    long len;

    len = read(fd, &event, sizeof(event));
    if (len < 0)
        return;

    if (event.op == 0)
        return;
}
