/*
 * Rule: DCL06-C
 * Source: bmdb-757
 * Status: PASS - literal echoed in a sibling identifier's own name
 * Description: a mechanical table pairing each value with an identifier that
 * already names it (e.g. seL4's x86 IDT vector table, init_idt_entry(idt,
 * 0x19, int_19)) is not hidden logic -- the value's meaning is right there
 * in the sibling argument's name, so a symbolic constant adds nothing.
 */

void init_idt_entry(void *idt, int vector, void (*handler)(void));
void int_19(void);
void int_2a(void);

void init_idt(void *idt) {
    init_idt_entry(idt, 0x19, int_19);
    init_idt_entry(idt, 0x2a, int_2a);
}
