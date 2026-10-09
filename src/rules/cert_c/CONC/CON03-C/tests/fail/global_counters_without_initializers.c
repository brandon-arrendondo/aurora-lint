/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - file-scope globals without initializers, two per line
 */

#include <pthread.h>

int samples_taken, samples_dropped;

void *sampler(void *arg) {
    samples_dropped++;
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, sampler, 0);
    pthread_join(t, 0);
    return samples_taken;
}
