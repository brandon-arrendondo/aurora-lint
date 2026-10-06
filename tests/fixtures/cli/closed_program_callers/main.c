/* show_arg is reached from main's argv. main calls itself, so it has an
 * in-tree caller, but the execution environment calls it too, with
 * arguments no scanned call site passes: it stays open in a closed program. */
void show_arg(const char *fmt);

int main(int argc, char **argv)
{
    if (argc > 1) {
        show_arg(argv[1]);
        return main(argc - 1, argv + 1);
    }
    return 0;
}
