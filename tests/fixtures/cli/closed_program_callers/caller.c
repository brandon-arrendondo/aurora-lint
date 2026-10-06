/* run_fixed's only caller passes a fixed command. run_by_pointer's does
 * too, but its address is also stored, so a call through the pointer is a
 * call site no scan collects. */
void run_fixed(char *cmd);
void run_by_pointer(char *cmd);

void (*handler)(char *) = run_by_pointer;

void entry(void)
{
    char cmd[] = "ls";
    run_fixed(cmd);
    run_by_pointer(cmd);
}
