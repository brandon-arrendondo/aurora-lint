/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `frame_count` is a typedef of `frame_index`, itself a
 *         typedef of `platform_size`, which nothing here defines: a typedef
 *         the scan read leads to the last name, so it is read by its
 *         spelling
 */

#include <pthread.h>

typedef platform_size frame_index;
typedef frame_index frame_count;

static frame_count frames;

void *worker(void *arg) {
    frames++;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    frames++;
    pthread_join(t, 0);
    return (int)frames;
}
