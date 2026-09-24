/* A pass-through in its own file: the walk from sink() climbs past it to
 * the static caller in entry.c. */
void sink(char *cmd);

void relay(char *cmd)
{
    sink(cmd);
}
