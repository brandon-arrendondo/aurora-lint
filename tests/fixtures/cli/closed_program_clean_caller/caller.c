#include <string.h>

void run_command(char *cmd);

void entry(void)
{
    char cmd[100] = "";
    strcpy(cmd, "ls -la");
    run_command(cmd);
}
