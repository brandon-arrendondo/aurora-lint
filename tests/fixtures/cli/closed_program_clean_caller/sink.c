/* run_command's only caller has no untrusted input in its body, but what
 * it passes is a relative command, the defect itself. "The caller reads no
 * untrusted input" judges the caller, not the value, so declaring the scan
 * a closed program does not make it a proof (ADR-0011). */
#include <stdlib.h>

void run_command(char *cmd)
{
    system(cmd);
}
