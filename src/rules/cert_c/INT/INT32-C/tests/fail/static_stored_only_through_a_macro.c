/*
 * Rule: INT32-C
 * Source: aurora-lint
 * Status: FAIL - write_some's address is stored through IO_METHODS, so
 *         calls reach it that the scan never sees, and its parameters are
 *         not bounded by the one direct caller's constants
 * Expect: count=3
 *
 * A replacement list is one token to the parser, so the address escape is
 * read from the macro text: the WRITE argument is DEFAULT_WRITE, which names
 * write_some as a value.
 */
struct io_methods {
    int (*write)(int amount, int offset);
};

static int write_some(int amount, int offset) {
    int wrote = amount / 2;
    amount -= wrote;  /* Expect: here */
    offset += wrote;  /* Expect: here */
    return amount + offset;  /* Expect: here */
}

#define IO_METHODS(NAME, WRITE) static const struct io_methods NAME = { WRITE }
#define DEFAULT_WRITE write_some

IO_METHODS(unix_io, DEFAULT_WRITE);

const struct io_methods *default_io(void) {
    return &unix_io;
}

int write_header(void) {
    return write_some(4, 0);
}
