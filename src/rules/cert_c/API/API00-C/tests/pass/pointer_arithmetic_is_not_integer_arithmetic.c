/*
 * Rule: API00-C
 * Source: custom
 * Status: PASS - Should NOT trigger API00-C violation
 * Description: A length parameter whose only "arithmetic" is forming a
 * pointer bound (`end = ies + ies_len`) is not doing integer arithmetic at
 * all -- a pointer operand cannot produce an integer overflow, so the
 * premise of the finding does not hold (task 738, hostap's
 * wpa_ft_parse_ies / ieee802_1x_kay_get_status). Any real length check
 * belongs on the pointer difference `end - pos`, which stays in bounds by
 * construction.
 *
 * Also covers the array-subscript half: an unvalidated index is an
 * index-validation question (ARR30-C), never an integer-overflow one, so
 * `names[monitor]` yields no arithmetic site here.
 */

typedef unsigned char u8;
typedef unsigned long size_t;

static const char *monitor_names[8];

int wpa_ft_parse_ies(const u8 *ies, size_t ies_len)
{
    const u8 *pos, *end;

    if (ies == 0)
        return -1;

    pos = ies;
    end = ies + ies_len;
    while (pos < end)
        pos++;

    return 0;
}

int ieee802_1x_kay_get_status(char *buf, size_t buflen)
{
    char *pos, *end;

    if (buf == 0)
        return -1;

    pos = buf;
    end = buf + buflen;
    if (end - pos < 4)
        return -1;

    return 0;
}

const char *get_monitor_name(int monitor)
{
    return monitor_names[monitor];
}
