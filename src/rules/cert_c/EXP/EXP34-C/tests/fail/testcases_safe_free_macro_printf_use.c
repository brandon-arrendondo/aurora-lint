/*
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP34-C violation
 */

/*
 * Rule: EXP34-C - Do not dereference null pointers
 * Status: FAIL
 * Reason: A function-like "safe free" macro (the mosquitto_FREE/
 * Curl_safefree/SAFE_FREE idiom: free the argument, then null it) nulls
 * auth_method. The freed pointer is then passed as a printf %s argument
 * with no intervening NULL check -- printing a NULL char* via %s is
 * undefined behavior, squarely EXP34-C territory. Mirrors mosquitto's
 * src/handle_auth.c:101-105 (the `mosquitto_FREE(auth_method);` at line 101
 * followed by the `log__printf(...auth_method)` at line 104-105).
 */

#include <stdio.h>
#include <stdlib.h>

#define mosquitto_FREE(A) do{ free((void *)(A)); (A) = NULL; }while(0)

void handle_auth(char *auth_method, const char *client_id) {
    mosquitto_FREE(auth_method);

    /* auth_method is now definitely NULL -- passing it as a %s argument
     * is a null-pointer misuse. */
    printf("Protocol error from %s: auth-method %s\n", client_id, auth_method);
}
