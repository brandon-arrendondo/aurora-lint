/*
 * Rule: MSC13-C
 * Source: synthetic (curl's amigaos.c shape)
 * Status: FAIL - `iface` starts as a copy of the file's `static` pointer, declared inside an #ifdef, which is a variable's value and no default, and every path overwrites it before a read
 */

#ifdef USE_IFACE
struct iface;
static struct iface *current_iface = 0;
#endif

#ifdef USE_IFACE
struct iface *open_iface(void);

struct iface *pick(void)
{
    struct iface *iface = current_iface;
    iface = open_iface();
    return iface;
}
#endif
