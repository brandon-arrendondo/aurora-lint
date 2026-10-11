#include "FreeRTOS.h"
#include "task.h"
#include <stdlib.h>

static void cleanup(void) {
    free(pvTaskGetThreadLocalStoragePointer(NULL, 0));
}

static void worker(void *params) {
    int *scratch = malloc(sizeof(int));
    if (scratch == NULL) {
        vTaskDelete(NULL);
    }
    vTaskSetThreadLocalStoragePointer(NULL, 0, scratch);
    (void)params;
    cleanup();
    vTaskDelete(NULL);
}
