#include "FreeRTOS.h"
#include "task.h"
#include <stdlib.h>

static void worker(void *params) {
    int *scratch = malloc(sizeof(int));
    if (scratch == NULL) {
        vTaskDelete(NULL);
    }
    vTaskSetThreadLocalStoragePointer(NULL, 0, scratch);
    (void)params;
    vTaskDelete(NULL);
}

void start(void) {
    xTaskCreate(worker, "worker", 256, NULL, 1, NULL);
}
