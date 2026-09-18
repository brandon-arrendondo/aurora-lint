/*
 * Rule: MEM30-C
 * Source: custom
 * Status: PASS - Should NOT trigger MEM30-C violation
 * Description: two more shapes from curl (task 1233). socks_sspi.c frees
 * `tok[1].pvBuffer` on the success path and `tok[0].pvBuffer` right after;
 * the lvalue key drops the index, so that read as a double-free -- a member
 * of ONE element is now untracked, the policy `free(arr[i])` already had.
 * curl_addrinfo.c frees the same pointer in each arm of an
 * `#ifdef/#elif/#else` chain; the linear walk saw arm two "use" what arm
 * one freed. Double-free across a preprocessor split has been suppressed
 * since task 251; use-after-free across one now is too.
 */

#include <stdlib.h>

struct buf { void *pvBuffer; unsigned cbBuffer; };
void FreeContextBuffer(void *p);
void lwip_freeaddrinfo(void *p);
void r_freeaddrinfo(void *p);
void freeaddrinfo(void *p);
void copy_out(void *dst, void *src, unsigned n);

void release(struct buf tok[2], void *socksreq)
{
    copy_out(socksreq, tok[1].pvBuffer, tok[1].cbBuffer);
    FreeContextBuffer(tok[1].pvBuffer);
    free(tok[0].pvBuffer);
}

void dbg_freeaddrinfo(void *freethis, int use_fake)
{
#ifdef USE_LWIPSOCK
    lwip_freeaddrinfo(freethis);
#elif defined(USE_FAKE_GETADDRINFO)
    if(use_fake)
        r_freeaddrinfo(freethis);
    else
        freeaddrinfo(freethis);
#else
    freeaddrinfo(freethis);
#endif
}
