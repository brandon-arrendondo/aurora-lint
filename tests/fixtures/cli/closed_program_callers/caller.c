/* show_fixed's only caller passes a literal. show_by_pointer's does too,
 * but its address is also stored, so a call through the pointer is a call
 * site no scan collects. */
void show_fixed(const char *fmt);
void show_by_pointer(const char *fmt);

void (*handler)(const char *) = show_by_pointer;

void entry(void)
{
    show_fixed("ready\n");
    show_by_pointer("ready\n");
}
