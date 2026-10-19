/*
 * Rule: STR31-C
 * Source: testcases
 * Status: PASS - Should not trigger STR31-C violation
 *
 * None of these copies a string into storage too small for it. A main
 * that takes argv without reading it copies nothing; an array of fewer
 * than two elements holds no string unless one is copied into it; a
 * memcpy of a struct, or of strlen(src) + 1 bytes, copies the terminator
 * or no string at all; and strncpy with a count equal to the buffer is a
 * question of termination, not of space.
 */

#include <string.h>
#include <wchar.h>

struct buffer {
    char data[16];
    int len;
};

struct header {
    int count;
    int items[0];
};

int flags[1];

void copy_struct(struct buffer *buf_cpy, const struct buffer *buf) {
    memcpy(buf_cpy, buf, sizeof(struct buffer));
}

void copy_with_terminator(char *buffer, const char *str) {
    memcpy(buffer, str, strlen(str) + 1);
}

void copy_wide_with_terminator(wchar_t *wbuffer, const wchar_t *wstr) {
    wmemcpy(wbuffer, wstr, wcslen(wstr) + 1);
}

void copy_count_equals_buffer(const char *src) {
    char dest[10];
    strncpy(dest, src, 10);
    dest[9] = '\0';
}

int main(int argc, char *argv[]) {
    int zz[0];
    char one[1];
    (void)zz;
    one[0] = '\0';
    flags[0] = 0;
    return 0;
}
