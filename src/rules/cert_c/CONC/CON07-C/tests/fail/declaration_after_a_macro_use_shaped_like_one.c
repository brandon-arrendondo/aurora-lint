/*
 * Rule: CON07-C
 * Status: FAIL - a file-scope `REGISTER(*count)(int);` has the shape of a
 * function-pointer declaration tree-sitter reads as a call, but `int count;`
 * declares the name too, and both cannot in a valid program: the statement
 * is a macro use, and `count` is the shared int the threads both update.
 */

#include <pthread.h>

REGISTER(*count)(int);
int count;

void add(int v) {
    count = count + v;
}

void *worker(void *arg) {
    add(1);
    return 0;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    add(2);
    return 0;
}
