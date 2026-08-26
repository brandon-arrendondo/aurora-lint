/**
 * Rule: EXP33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger EXP33-C violation. `&mime->boundary[N]`
 * takes the address of an array element to pass as an output-parameter
 * buffer; it is not itself a content read of `mime`, mirroring curl's
 * lib/mime.c:1193 `Curl_rand_alnum(easy, (unsigned char
 * *)&mime->boundary[MIME_BOUNDARY_DASHES], ...)` (task 457).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BOUNDARY_DASHES 24
#define BOUNDARY_LEN 40

typedef struct {
    char boundary[BOUNDARY_LEN];
} Mime;

extern void fill_random(unsigned char *buf, int len);

void f(void) {
    Mime *mime = (Mime *)malloc(sizeof(Mime));
    if (mime == NULL) return;
    memset(mime->boundary, '-', BOUNDARY_DASHES);
    fill_random((unsigned char *)&mime->boundary[BOUNDARY_DASHES],
                BOUNDARY_LEN - BOUNDARY_DASHES);
    printf("%s\n", mime->boundary);
}
