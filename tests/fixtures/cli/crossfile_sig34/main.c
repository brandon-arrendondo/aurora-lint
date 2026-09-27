#include <signal.h>
#include "handlers.h"

int main(void) {
    signal(SIGINT, on_int);
    return 0;
}
