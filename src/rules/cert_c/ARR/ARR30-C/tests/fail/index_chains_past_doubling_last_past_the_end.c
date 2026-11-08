/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - Past forty chains, the last one stores past the end
 * Expect: count=1
 *
 * One value out of range survives however many ways reach it.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#ifdef A0
    i = 0;
#endif
#ifdef A1
    i = 1;
#endif
#ifdef A2
    i = 2;
#endif
#ifdef A3
    i = 3;
#endif
#ifdef A4
    i = 0;
#endif
#ifdef A5
    i = 1;
#endif
#ifdef A6
    i = 2;
#endif
#ifdef A7
    i = 3;
#endif
#ifdef A8
    i = 0;
#endif
#ifdef A9
    i = 1;
#endif
#ifdef A10
    i = 2;
#endif
#ifdef A11
    i = 3;
#endif
#ifdef A12
    i = 0;
#endif
#ifdef A13
    i = 1;
#endif
#ifdef A14
    i = 2;
#endif
#ifdef A15
    i = 3;
#endif
#ifdef A16
    i = 0;
#endif
#ifdef A17
    i = 1;
#endif
#ifdef A18
    i = 2;
#endif
#ifdef A19
    i = 3;
#endif
#ifdef A20
    i = 0;
#endif
#ifdef A21
    i = 1;
#endif
#ifdef A22
    i = 2;
#endif
#ifdef A23
    i = 3;
#endif
#ifdef A24
    i = 0;
#endif
#ifdef A25
    i = 1;
#endif
#ifdef A26
    i = 2;
#endif
#ifdef A27
    i = 3;
#endif
#ifdef A28
    i = 0;
#endif
#ifdef A29
    i = 1;
#endif
#ifdef A30
    i = 2;
#endif
#ifdef A31
    i = 3;
#endif
#ifdef A32
    i = 0;
#endif
#ifdef A33
    i = 1;
#endif
#ifdef A34
    i = 2;
#endif
#ifdef A35
    i = 3;
#endif
#ifdef A36
    i = 0;
#endif
#ifdef A37
    i = 1;
#endif
#ifdef A38
    i = 2;
#endif
#ifdef A39
    i = 3;
#endif
#ifdef LAST
    i = 9;
#endif
    return buf[i];
}
