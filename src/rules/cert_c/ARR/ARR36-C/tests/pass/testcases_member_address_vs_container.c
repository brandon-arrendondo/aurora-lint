/*
 * Rule: ARR36-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR36-C violation
 */

/*
 * Rule: ARR36-C - Do not subtract or compare two pointers that do not refer to
 *       the same array
 * Status: PASS
 * Reason: The address of a member and the address of the object holding it are
 *         one object (ARR36-C-EX1), however deep the member sits. Keeping
 *         "just the struct instance" by stripping ONE member from the path is
 *         right for '&d.member1' and wrong for '&iwe_buf.u.data.length',
 *         which strips to 'iwe_buf.u.data' and then reads as a second array
 *         against '&iwe_buf'.
 *
 *         Distilled from hostap src/drivers/driver_wext.c, which computes the
 *         WE-19 header length exactly this way, twice.
 *
 *         The counterpart is fail/testcases_nested_struct.c: two SIBLING
 *         members are still two arrays, because neither one contains the
 *         other.
 */

struct iw_data {
    unsigned int length;
    unsigned int flags;
};

struct iw_event {
    unsigned short len;
    unsigned short cmd;
    union {
        struct iw_data data;
        unsigned char raw[8];
    } u;
};

int event_prefix_len(void)
{
    struct iw_event iwe_buf;
    char *dpos = (char *) &iwe_buf.u.data.length;

    return (int) (dpos - (char *) &iwe_buf);
}

int main(void)
{
    return event_prefix_len();
}
