/*
 * Rule: API05-C
 * Source: testcases
 * Status: PASS - Should NOT trigger API05-C violation
 */

/*
 * Reason: the four-parameter stdio callback signature
 *   (T *buf, size_t s1, size_t s2, void *userdata)
 * -- shared by fread/fwrite and libcurl's CURLOPT_{READ,WRITE,HEADER}FUNCTION
 * callbacks -- carries a byte count of s1 * s2, not s1. C99 conformant-array
 * syntax cannot name a product bound, so flagging `buf[s1]` is wrong (task
 * 1007, tools_sqc). Real instances at curl @3e198f75: mime_file_read
 * (lib/mime.c:617), tool_header_cb (src/tool_cb_hdr.c:426), tool_write_cb
 * (src/tool_cb_wrt.c:240), tool_mime_stdin_read (src/tool_formparse.c:195).
 */

#include <stddef.h>

typedef struct _IO_FILE FILE;
extern FILE *stdin;
extern size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
extern void *memcpy(void *dest, const void *src, size_t n);

size_t mime_file_read(char *buffer, size_t size, size_t nitems, void *instream)
{
    FILE *fp = (FILE *)instream;
    return fread(buffer, size, nitems, fp);
}

size_t tool_header_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void)userdata;
    (void)ptr;
    return size * nmemb;
}

size_t tool_write_cb(char *buffer, size_t sz, size_t nmemb, void *userdata)
{
    size_t bytes = sz * nmemb;
    char tmp[16];
    (void)userdata;
    if (bytes > sizeof(tmp))
        bytes = sizeof(tmp);
    memcpy(tmp, buffer, bytes);
    return sz * nmemb;
}

size_t tool_mime_stdin_read(char *buffer, size_t size, size_t nitems, void *arg)
{
    (void)arg;
    return fread(buffer, size, nitems, stdin);
}
