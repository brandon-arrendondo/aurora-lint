#include <arch/machine.h>

int apic_init(void)
{
    return apic_lvt_new();
}
