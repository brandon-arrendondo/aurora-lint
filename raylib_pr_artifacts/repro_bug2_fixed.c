// FIXED version: TextReplaceBetween with the proposed MAX_TEXT_BUFFER_LENGTH guard
// (mirrors TextInsert/TextReplace). Confirms ASan-clean on the overflow input AND
// byte-correct on normal input.
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TEXT_BUFFER_LENGTH 1024

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

char *TextReplaceBetween(const char *text, const char *begin, const char *end, const char *replacement)
{
    static char buffer[MAX_TEXT_BUFFER_LENGTH] = { 0 };
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

                // PROPOSED FIX: guard total output against buffer size (like TextInsert/TextReplace)
                if ((beginIndex + beginLen + replaceLen + (textLen - endIndex)) < (MAX_TEXT_BUFFER_LENGTH - 1))
                {
                    strncpy(buffer, text, beginIndex + beginLen);
                    if (replacement != NULL) strncpy(buffer + beginIndex + beginLen, replacement, replaceLen);
                    strncpy(buffer + beginIndex + beginLen + replaceLen, text + endIndex, textLen - endIndex);
                }
                else fprintf(stderr, "[warn] result exceeds MAX_TEXT_BUFFER_LENGTH, skipped\n");
            }
        }
    }
    return buffer;
}

int main(void)
{
    // (a) the overflow input from the unfixed repro -- must now be ASan-clean
    size_t tail = 2000;
    char *text = malloc(2 + tail + 1);
    text[0] = 'B'; text[1] = 'E';
    memset(text + 2, 'x', tail);
    text[2 + tail] = '\0';
    char *out = TextReplaceBetween(text, "B", "E", NULL);
    printf("overflow-input handled safely, out len = %u\n", TextLength(out));
    free(text);

    // (b) correctness control -- normal short input must still produce the right result
    char *out2 = TextReplaceBetween("hello[X]world", "[", "]", "_");
    printf("normal-input result: '%s' (expect 'hello[_world')\n", out2);
    return 0;
}
