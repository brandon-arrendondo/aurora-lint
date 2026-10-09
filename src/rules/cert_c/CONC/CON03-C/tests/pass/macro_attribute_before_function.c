/* Rule: CON03-C
 * Source: testcases
 * Status: PASS - a section macro on the line before a function definition
 * is not a declaration of a variable named after the return type
 */

#include <pthread.h>

typedef unsigned long word_t;
#define INIT_TEXT __attribute__((section(".init.text")))
#define PURE __attribute__((pure))

INIT_TEXT
static word_t PURE scale(word_t value)
{
    return value * (word_t)sizeof(word_t);
}

void *worker(void *arg) {
    return (void *)scale((word_t)arg);
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    pthread_join(t, 0);
    return 0;
}
