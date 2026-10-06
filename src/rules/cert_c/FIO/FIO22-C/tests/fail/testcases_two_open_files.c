/*
 * Rule: FIO22-C
 * Description: Two files still open when a process is spawned; the finding names both, in name order
 * Status: FAIL - Should trigger FIO22-C violation
 */

#include <stdio.h>
#include <stdlib.h>

void run_editor(const char *log_name, const char *data_name) {
    FILE *zlog = fopen(log_name, "a");
    FILE *adata = fopen(data_name, "r");
    if (zlog == NULL || adata == NULL) {
        return;
    }
    (void)system("editor");
    fclose(adata);
    fclose(zlog);
}
