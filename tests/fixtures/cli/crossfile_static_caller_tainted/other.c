/* An unrelated static of the same name, with nothing tainted in it. It
 * never calls sink(), so its cleanliness must not vouch for it. */
static void run(void)
{
}

void other(void)
{
    run();
}
