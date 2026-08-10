#include <string.h>
#include <stdio.h>

void funcB(const char *src) {
    char buf[3] = "abc";      /* no room for '\0': unsafe, recorded at this line */
    printf("%s\n", buf);      /* REAL BUG: buf never null-terminated, used as string */
}

void funcA(const char *src) {
    char buf[10];
    strncpy(buf, src, sizeof(buf));  /* marks buf unsafe, overwrites array_locations["buf"] to this later line */
    buf[9] = '\0';                    /* legitimate null-termination for funcA's buf, but line number is later
                                          than the recorded (overwritten) location, so it removes "buf" from the
                                          GLOBAL unsafe_arrays set entirely */
}
