/* Freestanding firmware shape: the timer interrupt handler and the main
 * loop share a file-scope counter and flag with no volatile and no
 * synchronization. */
static unsigned int tick_count = 0;
static int data_ready = 0;

__attribute__((interrupt)) void TIMER_IRQHandler(void)
{
    tick_count++;
    data_ready = 1;
}

int main(void)
{
    unsigned int last = 0;
    for (;;) {
        while (!data_ready) {
        }
        data_ready = 0;
        if (tick_count != last) {
            last = tick_count = 0;
        }
    }
    return 0;
}
