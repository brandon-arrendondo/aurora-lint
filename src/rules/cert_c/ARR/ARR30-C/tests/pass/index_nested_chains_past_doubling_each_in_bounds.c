/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: PASS - Forty nested chains each store an in-bounds value
 *
 * Nesting doubles the ways through in the same way.
 */

int buf[4];
int c;

int element(void)
{
    int i = 1;
#ifdef A0
#ifdef B0
    i = 0;
#endif
#endif
#ifdef A1
#ifdef B1
    i = 1;
#endif
#endif
#ifdef A2
#ifdef B2
    i = 2;
#endif
#endif
#ifdef A3
#ifdef B3
    i = 3;
#endif
#endif
#ifdef A4
#ifdef B4
    i = 0;
#endif
#endif
#ifdef A5
#ifdef B5
    i = 1;
#endif
#endif
#ifdef A6
#ifdef B6
    i = 2;
#endif
#endif
#ifdef A7
#ifdef B7
    i = 3;
#endif
#endif
#ifdef A8
#ifdef B8
    i = 0;
#endif
#endif
#ifdef A9
#ifdef B9
    i = 1;
#endif
#endif
#ifdef A10
#ifdef B10
    i = 2;
#endif
#endif
#ifdef A11
#ifdef B11
    i = 3;
#endif
#endif
#ifdef A12
#ifdef B12
    i = 0;
#endif
#endif
#ifdef A13
#ifdef B13
    i = 1;
#endif
#endif
#ifdef A14
#ifdef B14
    i = 2;
#endif
#endif
#ifdef A15
#ifdef B15
    i = 3;
#endif
#endif
#ifdef A16
#ifdef B16
    i = 0;
#endif
#endif
#ifdef A17
#ifdef B17
    i = 1;
#endif
#endif
#ifdef A18
#ifdef B18
    i = 2;
#endif
#endif
#ifdef A19
#ifdef B19
    i = 3;
#endif
#endif
#ifdef A20
#ifdef B20
    i = 0;
#endif
#endif
#ifdef A21
#ifdef B21
    i = 1;
#endif
#endif
#ifdef A22
#ifdef B22
    i = 2;
#endif
#endif
#ifdef A23
#ifdef B23
    i = 3;
#endif
#endif
#ifdef A24
#ifdef B24
    i = 0;
#endif
#endif
#ifdef A25
#ifdef B25
    i = 1;
#endif
#endif
#ifdef A26
#ifdef B26
    i = 2;
#endif
#endif
#ifdef A27
#ifdef B27
    i = 3;
#endif
#endif
#ifdef A28
#ifdef B28
    i = 0;
#endif
#endif
#ifdef A29
#ifdef B29
    i = 1;
#endif
#endif
#ifdef A30
#ifdef B30
    i = 2;
#endif
#endif
#ifdef A31
#ifdef B31
    i = 3;
#endif
#endif
#ifdef A32
#ifdef B32
    i = 0;
#endif
#endif
#ifdef A33
#ifdef B33
    i = 1;
#endif
#endif
#ifdef A34
#ifdef B34
    i = 2;
#endif
#endif
#ifdef A35
#ifdef B35
    i = 3;
#endif
#endif
#ifdef A36
#ifdef B36
    i = 0;
#endif
#endif
#ifdef A37
#ifdef B37
    i = 1;
#endif
#endif
#ifdef A38
#ifdef B38
    i = 2;
#endif
#endif
#ifdef A39
#ifdef B39
    i = 3;
#endif
#endif
    return buf[i];
}
