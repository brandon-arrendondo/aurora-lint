/*
 * Rule: MSC17-C
 * Source: synthetic, following MSC37-C's reading of C23 unreachable() (C23 7.21.1)
 * Status: FAIL - GNU __builtin_unreachable() is no ISO C call, so even under a declared C23 edition it does not end the section
 * Settings: c_standard=c23
 */

int classify(int op)
{
    int r = 0;
    switch (op) {
    case 1:
        r = 10;
        __builtin_unreachable();
    case 2:
        r = 20;
        break;
    }
    return r;
}
