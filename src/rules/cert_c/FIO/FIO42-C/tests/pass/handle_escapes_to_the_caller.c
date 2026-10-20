/*
 * Rule: FIO42-C
 *
 * Status: PASS - Should NOT trigger FIO42-C violation
 *
 * Each function hands the handle it opens to something that outlives the
 * call: it returns it (directly, in parentheses, or through a copy), stores
 * it through a pointer, into a field or into a file-scope variable, takes
 * its address, or passes it to a function whose body keeps it. Closing it is
 * then the job of whoever holds it.
 */
#include <stdio.h>
#include <fcntl.h>

struct conn {
    FILE *f;
    int fd;
};

FILE *log_file;

void conn_keep(struct conn *c, FILE *f)
{
    c->f = f;
}

FILE *open_returned(const char *path)
{
    FILE *f = fopen(path, "r");
    return f;
}

FILE *open_returned_in_parentheses(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return NULL;
    return (f);
}

FILE *open_returned_through_a_copy(const char *path)
{
    FILE *f = fopen(path, "r");
    FILE *result;
    result = f;
    return result;
}

int open_descriptor_returned(const char *path)
{
    int fd = open(path, O_RDONLY);
    return fd;
}

void open_into_a_field(struct conn *c, const char *path)
{
    FILE *f = fopen(path, "r");
    c->f = f;
}

void open_straight_into_fields(struct conn *c, const char *path)
{
    c->fd = open(path, O_RDONLY);
    c->f = fopen(path, "r");
}

void open_through_an_out_parameter(FILE **out, const char *path)
{
    *out = fopen(path, "r");
}

void open_copied_through_an_out_parameter(FILE **out, const char *path)
{
    FILE *f = fopen(path, "r");
    *out = f;
}

void open_into_a_file_scope_variable(const char *path)
{
    log_file = fopen(path, "a");
}

void open_into_a_static(const char *path)
{
    static FILE *f;
    f = fopen(path, "a");
}

void open_handed_to_a_function_that_keeps_it(struct conn *c, const char *path)
{
    FILE *f = fopen(path, "r");
    conn_keep(c, f);
}

void open_in_an_initializer(struct conn *out, const char *path)
{
    FILE *f = fopen(path, "r");
    struct conn c = { f, -1 };
    *out = c;
}

void open_closed_through_a_copy(const char *path)
{
    FILE *f = fopen(path, "r");
    FILE *g = f;
    fclose(g);
}
