#include "FreeRTOS.h"
#include "task.h"

static int state;

static void worker(void *params) {
    void *scratch = pvPortMalloc(8);
    vTaskSetThreadLocalStoragePointer(NULL, 1, &state);
    vTaskSetThreadLocalStoragePointer(NULL, 2, NULL);
    vTaskSetThreadLocalStoragePointer(NULL, 3, scratch);
    (void)params;
    vPortFree(pvTaskGetThreadLocalStoragePointer(NULL, 3));
    vTaskDelete(NULL);
}
