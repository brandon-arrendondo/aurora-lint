/*
 * Rule: STR11-C
 * Source: testcases
 * Status: FAIL - Should trigger STR11-C violation
 *
 * Each initializer fills its bounded array to the literal's size or
 * beyond: adjacent literals joined, a braced literal, bounds written as a
 * macro, an enumerator or a suffixed constant, a multibyte UTF-8
 * character, a wide literal, an array of arrays, a typedef'd array, and
 * structure members by position and by designator.
 */
#include <wchar.h>

#define LEN 3
enum { WIDTH = 3 };

char joined[6] = "abc" "de";
char braced[3] = {"abc"};
char by_macro[LEN] = "abc";
char by_enum[WIDTH] = "abc";
char suffixed[3u] = "abc";
char multibyte[2] = "\u00e9";
wchar_t wide[3] = L"abc";
char rows[2][3] = {"abc", "def"};

typedef char tag_t[4];
tag_t tag = "abc";

struct entry {
    char code[3];
    int value;
};
struct entry by_position = {"abc", 1};
struct entry by_designator = {.value = 2, .code = "xyz"};
