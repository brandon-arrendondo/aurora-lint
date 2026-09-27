/*
 * Rule: PRE05-C
 * Source: testcases
 * Status: FAIL - Should trigger PRE05-C violation
 *
 * The // is inside a string literal and starts no comment, so the body
 * goes on to #p: SHOW(PORT) prints "PORT", not "80".
 */

void show(const char *base, const char *what);

#define PORT 80
#define SHOW(p) show("http://example.org", #p)

void show_port(void)
{
    SHOW(PORT); /* VIOLATION */
}
