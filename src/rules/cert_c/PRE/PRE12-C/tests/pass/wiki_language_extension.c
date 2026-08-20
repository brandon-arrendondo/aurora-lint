/*
 * Rule: PRE12-C
 * Source: wiki
 * Status: PASS - Should NOT trigger PRE12-C violation
 */

#define ABS(x) __extension__ ({ __typeof (x) __tmp = x; __tmp < 0 ? - __tmp : __tmp; })
