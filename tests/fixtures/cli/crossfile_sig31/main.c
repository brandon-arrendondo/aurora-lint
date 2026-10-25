#include <signal.h>
#include "handlers.h"

int main(void) {
    signal(SIGTERM, on_term);
    return 0;
}
