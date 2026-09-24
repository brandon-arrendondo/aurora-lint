/* The only writer of g_cmd: a static whose name other.c also defines
 * static. This one stores a fixed command. */
char *g_cmd;

void sink(void);

static void run(void)
{
    char buf[100] = "ls";
    g_cmd = buf;
    sink();
}

void entry(void)
{
    run();
}
