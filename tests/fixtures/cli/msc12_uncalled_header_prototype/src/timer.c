#include <drivers/timer.h>

static void save_timer(int *v) { *v = 1; }
static void restore_timer(int *v) { *v = 0; }

void timer_init(void) {}
