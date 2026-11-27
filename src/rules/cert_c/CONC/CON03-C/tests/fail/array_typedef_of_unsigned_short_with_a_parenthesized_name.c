/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `typedef unsigned short (sample_window)[16];` names an
 *         array type with its name in parentheses, which the parser reads as
 *         a function `short(sample_window)`: the typedef still defines the
 *         name
 */

#include <pthread.h>

typedef unsigned short (sample_window)[16];

static sample_window samples;

void *worker(void *arg) {
    samples[0] = 1;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    samples[1] = 2;
    pthread_join(t, 0);
    return (int)samples[0];
}
