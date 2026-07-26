/*
 * Rule: MSC12-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

int func(int condition) {
    char *s = NULL;
    if (condition) {
        s = (char *)malloc(10);
        if (s == NULL) {
           /* Handle error */
        }
        /* Process s */
    }
    /* Code that doesn't touch s */
    if (s) {
        /* This code is now reachable */
    }
    return 0;
}