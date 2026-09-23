/*
 * Rule: MEM31-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM31-C violation
 * Description: A callee with no body in the scan leaves its NAME as the only
 * evidence, and `is_deallocation_call_name` reads six verbs of which only
 * free/destroy/delete mean deallocation. librtmp's `RTMP_Close(r)` shuts the
 * stream down and `RTMP_Free(r)` is what frees `r` (curl lib/curl_rtmp.c's
 * rtmp_conn_dtor); a COM `_Release` decrements a refcount; and
 * `mbedtls_gcm_free(ctx); free(ctx);` releases contents and then the struct.
 * Two DIFFERENT deallocator names on one pointer is the paired-teardown
 * idiom, so a guessed mark from the first does not make the second a double
 * free. An earlier fix.
 */

#include <stdlib.h>

struct rtmp;
extern struct rtmp *RTMP_Alloc(void);
extern void RTMP_Close(struct rtmp *r);
extern void RTMP_Free(struct rtmp *r);

void close_then_free(void *entry) {
    struct rtmp *r = entry;
    RTMP_Close(r);
    RTMP_Free(r);
}

struct gcm;
extern void mbedtls_gcm_free(struct gcm *ctx);

void contents_then_struct(void) {
    struct gcm *ctx = malloc(64);
    if (ctx == NULL) {
        return;
    }
    mbedtls_gcm_free(ctx);
    free(ctx);
}

struct wbem;
extern struct wbem *wbem_query(void);
extern void IWbemClassObject_Release(struct wbem *o);
extern void wbem_object_cleanup(struct wbem *o);

void release_then_cleanup(void) {
    struct wbem *o = wbem_query();
    IWbemClassObject_Release(o);
    wbem_object_cleanup(o);
}
