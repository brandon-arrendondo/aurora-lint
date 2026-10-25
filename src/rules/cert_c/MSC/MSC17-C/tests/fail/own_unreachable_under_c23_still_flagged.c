/*
 * Rule: MSC17-C
 * Source: synthetic, following MSC37-C's reading of C23 unreachable() (C23 7.21.1) and its EX2 helper
 * Status: FAIL - a file's own function named unreachable is not C23's, so it does not end the section
 * Settings: c_standard=c23
 */

void log_message(const char *msg);

static void unreachable(void)
{
    log_message("unreachable");
}

int classify(int op)
{
    int r = 0;
    switch (op) {
    case 1:
        r = 10;
        unreachable();
    case 2:
        r = 20;
        break;
    }
    return r;
}
