/* Rule: CON03-C
 * Source: testcases
 * Status: FAIL - `font_id` is an `unsigned long` typedef, and only under
 *         `USE_X11` a rename to a type nothing here defines: the typedef arm
 *         is an ordinary object, so the type is known to need
 *         synchronization
 */

#include <pthread.h>

#ifdef USE_X11
#define font_id x11_font_id
#endif
typedef unsigned long font_id;

static font_id current_font;

void *worker(void *arg) {
    current_font = 1;
    return arg;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    current_font = 2;
    pthread_join(t, 0);
    return (int)current_font;
}
