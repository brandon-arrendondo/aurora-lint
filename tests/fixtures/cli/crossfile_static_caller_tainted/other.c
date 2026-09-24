/* An unrelated static of the same name, with nothing tainted in it. It
 * never calls relay(), so its cleanliness must not vouch for sink(). */
static void run(void)
{
}

void other(void)
{
    run();
}
