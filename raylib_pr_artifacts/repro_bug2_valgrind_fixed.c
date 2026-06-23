// Valgrind-visible repro of raylib TextReplaceBetween() overflow.
//
// The real bug overflows a `static char buffer[MAX_TEXT_BUFFER_LENGTH]` (a GLOBAL),
// which valgrind memcheck does NOT instrument (no red zones on globals) — so the
// unfixed function appears clean under valgrind even though it writes far past the
// buffer (see repro_bug2.c under ASan: WRITE of size 2001 past a 1024 buffer).
//
// To make the SAME out-of-bounds write observable to memcheck, this repro changes
// ONLY the storage class of `buffer` from static to a heap block of the identical
// size MAX_TEXT_BUFFER_LENGTH. The copy logic, indices, and inputs are unchanged,
// so the "Invalid write" valgrind reports is exactly the overflow the static
// version performs silently.
//
// Build:  cc -g repro_bug2_valgrind.c -o repro_bug2_valgrind
// Run:    valgrind --error-exitcode=99 ./repro_bug2_valgrind   # exits 99 (Invalid write)
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TEXT_BUFFER_LENGTH 1024  // value from rtext.c:104

unsigned int TextLength(const char *text)
{
    unsigned int length = 0;
    if (text != NULL) { while (text[length] != '\0') length++; }
    return length;
}

int TextFindIndex(const char *text, const char *search)
{
    int position = -1;
    if (text != NULL)
    {
        char *ptr = (char *)strstr(text, search);
        if (ptr != NULL) position = (int)(ptr - text);
    }
    return position;
}

// Logic verbatim from rtext.c TextReplaceBetween; ONLY `buffer` is heap (size identical)
// so the existing out-of-bounds strncpy is visible to valgrind memcheck.
char *TextReplaceBetween(char *buffer, const char *text, const char *begin, const char *end, const char *replacement)
{
    memset(buffer, 0, MAX_TEXT_BUFFER_LENGTH);

    if ((text != NULL) && (begin != NULL) && (end != NULL))
    {
        int beginIndex = TextFindIndex(text, begin);
        if (beginIndex > -1)
        {
            int beginLen = TextLength(begin);
            int endIndex = TextFindIndex(text + beginIndex + beginLen, end);
            if (endIndex > -1)
            {
                endIndex += (beginIndex + beginLen);
                int textLen = TextLength(text);
                int replaceLen = (replacement == NULL)? 0 : TextLength(replacement);

                if ((beginIndex + beginLen + replaceLen + (textLen - endIndex)) < (MAX_TEXT_BUFFER_LENGTH - 1)) {
                strncpy(buffer, text, beginIndex + beginLen);
                if (replacement != NULL) strncpy(buffer + beginIndex + beginLen, replacement, replaceLen);
                strncpy(buffer + beginIndex + beginLen + replaceLen, text + endIndex, textLen - endIndex); }
            }
        }
    }
    return buffer;
}

int main(void)
{
    char *buffer = malloc(MAX_TEXT_BUFFER_LENGTH);   // same capacity as the static buffer

    // Ordinary public-API-shaped input: "B" "E" + 2000 'x' tail. No malformed input.
    size_t tail = 2000;
    char *text = malloc(2 + tail + 1);
    text[0] = 'B'; text[1] = 'E';
    memset(text + 2, 'x', tail);
    text[2 + tail] = '\0';

    char *out = TextReplaceBetween(buffer, text, "B", "E", NULL);  // <-- Invalid write here
    printf("out len = %u (buffer capacity = %d)\n", TextLength(out), MAX_TEXT_BUFFER_LENGTH);

    free(text);
    free(buffer);
    return 0;
}
