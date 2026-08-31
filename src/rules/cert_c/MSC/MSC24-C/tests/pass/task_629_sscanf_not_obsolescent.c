/*
 * Rule: MSC24-C
 * Source: task_629
 * Status: PASS - Should NOT trigger MSC24-C violation
 */

/*
 * Rule: MSC24-C - Do not use deprecated or obsolescent functions
 * Status: PASS
 * Reason: sscanf is not on CERT's actual MSC24-C obsolescent-function
 * table, and its suggested Annex K replacement (sscanf_s()) is optional
 * and unavailable on glibc -- flagging it was a 100% FP class in
 * real-world ground_truth (task 629, 47 hostap findings).
 */

#include <stdio.h>

int parse_int(const char *buf)
{
    int value = 0;
    sscanf(buf, "%d", &value);
    return value;
}
