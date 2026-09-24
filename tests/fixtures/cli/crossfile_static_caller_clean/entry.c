/* The only caller of relay(): a static whose name other.c also defines
 * static. This one passes a fixed command. */
void relay(char *cmd);

static void run(void)
{
    char cmd[] = "ls";
    relay(cmd);
}

void entry(void)
{
    run();
}
