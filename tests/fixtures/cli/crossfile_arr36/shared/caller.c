/* Passes a cursor and its bound derived from ONE buffer -- the idiom the
 * parameter model exists to keep quiet. */
extern long span(const char *pos, const char *end);

static char buffer[16];

long measure(void)
{
    return span(buffer, buffer + sizeof(buffer));
}
