/* An unrelated static of the same name that writes nothing sink() reads. */
static void run(void)
{
}

void other(void)
{
    run();
}
