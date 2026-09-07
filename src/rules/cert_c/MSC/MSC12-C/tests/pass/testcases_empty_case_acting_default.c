/*
 * Rule: MSC12-C
 * Status: PASS - Should NOT trigger MSC12-C violation
 */

/*
 * Reason: `case WIDTH_160_80PLUS80: break;` is not removable when the switch
 * has a `default:` that does real work. Delete the case and that value stops
 * matching a label, falls to the default handler, and gets masked out -- a
 * behaviour change, so the case is not "code that has no effect" (task 999;
 * real example: hostap's src/ap/ieee802_11_vht.c channel-width masking).
 *
 * The same file's `default:` is exempt for a second, independent reason:
 * MISRA C 2012 Rule 16.4 requires every switch to carry a default label.
 */

#define WIDTH_MASK              0x0c
#define WIDTH_160_80PLUS80MHZ   0x08
#define WIDTH_160MHZ            0x04

unsigned mask_unsupported_widths(unsigned cap, unsigned own_cap)
{
    switch (own_cap & WIDTH_MASK) {
    case WIDTH_160_80PLUS80MHZ:
        break;
    case WIDTH_160MHZ:
        cap |= WIDTH_160MHZ;
        break;
    default:
        cap &= ~WIDTH_MASK;
        break;
    }
    return cap;
}
