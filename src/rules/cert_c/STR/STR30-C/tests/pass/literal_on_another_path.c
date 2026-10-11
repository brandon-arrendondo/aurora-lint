/*
 * Rule: STR30-C
 * Source: synthetic
 * Status: PASS - The literal and the write are never on one path
 *
 * The literal is assigned in one arm of an if/else, or one case of a
 * switch that does not fall through, and the write is in the other.
 */

#include <string.h>

char *split(char *buf)
{
    char *path = strchr(buf, '/');
    if (path == NULL) {
        path = "/";
    } else {
        *path = '\0';
    }
    return path;
}

void fill(char *buf, int kind)
{
    char *z = buf;
    switch (kind) {
    case 0:
        z = "(null)";
        break;
    case 1:
        z[0] = 'x';
        break;
    }
}
