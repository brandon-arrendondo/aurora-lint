/*
 * Rule: MEM05-C
 * Source: synthetic
 * Status: PASS - A size too large to read in the work budget is not a VLA
 *
 * Each macro names the one before it twice, so the expansion doubles per
 * level and outruns the test's work budget. The size is a constant, and
 * running out of budget does not show otherwise, so it is not reported.
 */
#define M0 1
#define M1 (M0 + M0)
#define M2 (M1 + M1)
#define M3 (M2 + M2)
#define M4 (M3 + M3)
#define M5 (M4 + M4)
#define M6 (M5 + M5)
#define M7 (M6 + M6)
#define M8 (M7 + M7)
#define M9 (M8 + M8)
#define M10 (M9 + M9)
#define M11 (M10 + M10)
#define M12 (M11 + M11)
#define M13 (M12 + M12)

void sink(char *p);

void fixed_size(void)
{
    char big[M13];
    sink(big);
}
