/*
 * Rule: ARR30-C
 * Source: synthetic
 * Status: FAIL - An array sized before a chain the parser nests in an earlier one
 * Expect: count=2
 *
 * The extern "C" brace, opened in one arm and closed in another, leads the
 * parser to run the first #if defined(_WIN32) chain on over the function.
 * The function's own #if defined(_WIN32) chain is then inside that chain's
 * opening arm, not a second asking after it, so the #elif arm still compiles
 * with the array's declaration. Nothing bounds len below the size in either
 * arm, and readlink can fill all of dir, leaving dir[len] one past the end.
 */

#include <unistd.h>

#if defined(_WIN32)
    #if defined(__cplusplus)
    extern "C" {
    #endif
    unsigned long get_module_name(char *name, unsigned long size);
    #if defined(__cplusplus)
    }
    #endif
#endif

const char *program_directory(void)
{
    static char dir[64] = { 0 };
#if defined(_WIN32)
    int len = (int)get_module_name(dir, sizeof(dir));
    if (len > 0)
    {
        for (int i = len; i >= 0; i--)
        {
            if (dir[i] == '\\') { dir[i + 1] = '\0'; break; }
        }
    }
#elif defined(__linux__)
    ssize_t len = readlink("/proc/self/exe", dir, sizeof(dir));
    if (len > 0)
    {
        for (int i = len; i >= 0; i--)
        {
            if (dir[i] == '/') { dir[i + 1] = '\0'; break; }
        }
    }
#endif
    return dir;
}
