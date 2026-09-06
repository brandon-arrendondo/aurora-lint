/* Passes two DIFFERENT declared arrays, so `end - pos` inside span() is
 * undefined whenever this path runs. */
extern long span(const char *pos, const char *end);

static char first[16];
static char second[16];

long measure(void)
{
    return span(first, second);
}
