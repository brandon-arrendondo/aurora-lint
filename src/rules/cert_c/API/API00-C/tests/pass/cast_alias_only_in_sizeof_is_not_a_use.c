/*
 * Description: a cast alias that appears only as the operand of sizeof is
 * never dereferenced, so the handle is not used unvalidated
 *
 * The length-check idiom `if (len < sizeof(*hdr))` names the alias inside
 * sizeof, which C never evaluates. The helper does nothing else with it.
 */
#include <stddef.h>

struct frame_hdr {
    unsigned short type;
    unsigned short length;
};

static int frame_fits(const void *buf, size_t len)
{
    const struct frame_hdr *hdr = (const struct frame_hdr *)buf;
    if (len < sizeof(*hdr)) {
        return 0;
    }
    return 1;
}

int frame_ok(const void *buf, size_t len)
{
    return frame_fits(buf, len);
}
