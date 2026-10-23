/*
 * Rule: DCL36-C
 * Source: testcases
 * Status: FAIL - Should trigger DCL36-C violation
 *
 * `extern` with no prior declaration gives external linkage (C23 6.2.2 p4),
 * so a later `static` declaration of the same name is a conflict. The
 * second pair sits outside the #ifdef, so both declarations are in every
 * translation unit.
 */

extern int y;
static int y;

int z;
#ifdef FEATURE_Z
int z_enabled;
#endif
static int z;

int main(void) {
    return y + z;
}
