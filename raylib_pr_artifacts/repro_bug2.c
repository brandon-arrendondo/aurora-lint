// ASan repro for raylib TextReplaceBetween() static-buffer overflow.
// Functions copied VERBATIM from raylib src/rtext.c @ 962bbfc (current master):
//   TextLength, TextFindIndex, TextReplaceBetween — only deps are <string.h>.
// Build:  cc -g -fsanitize=address repro_bug2.c -o repro_bug2 && ./repro_bug2
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TEXT_BUFFER_LENGTH 1024  // value from rtext.c:104

// --- verbatim from rtext.c ---
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
                strncpy(buffer, text, beginIndex + beginLen);
                if (replacement != NULL) strncpy(buffer + beginIndex + beginLen, replacement, replaceLen);
                strncpy(buffer + beginIndex + beginLen + replaceLen, text + endIndex, textLen - endIndex);
            }
        }
    }
    return buffer;
}
// --- end verbatim ---

int main(void)
{
    // Ordinary public-API call: a string with "begin"/"end" markers and a long
    // tail after "end". No malformed input, no files — just a large string.
    // Layout: "B" "E" + 2000 'x'  -> the post-"end" copy is ~2001 bytes into a 1024 buffer.
    size_t tail = 2000;
    char *text = malloc(2 + tail + 1);
    text[0] = 'B';            // begin marker
    text[1] = 'E';            // end marker
    memset(text + 2, 'x', tail);
    text[2 + tail] = '\0';

    printf("input length = %zu, buffer capacity = %d\n", strlen(text), MAX_TEXT_BUFFER_LENGTH);
    char *out = TextReplaceBetween(text, "B", "E", NULL);
    printf("survived (no overflow detected): out len = %u\n", TextLength(out));
    free(text);
    return 0;
}
