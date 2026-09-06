/* The callee under check. Nothing in this file says whether `pos` and `end`
 * denote one object or two -- the fact lives in whoever calls it, and no
 * caller is in this file. */
long span(const char *pos, const char *end)
{
    return end - pos;
}
