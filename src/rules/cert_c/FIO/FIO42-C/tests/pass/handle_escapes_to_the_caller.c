/*
 * Rule: FIO42-C
 *
 * Status: PASS - Should NOT trigger FIO42-C violation
 *
 * Each function hands the handle it opens to something that outlives the
 * call: it returns it (directly, in parentheses, or through a copy), stores
 * it through a pointer, into a field or into a file-scope variable, takes
 * its address or the address of a local array holding it, or passes it to a
 * function whose body keeps it. Closing it is then the job of whoever holds
 * it.
 */
#include <stdio.h>
#include <fcntl.h>

struct conn {
    FILE *f;
    int fd;
};

FILE *log_file;

void stream_adopt(FILE **slot);

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

void open_address_handed_over(const char *path)
{
    FILE *f = fopen(path, "r");
    stream_adopt(&f);
}

union stream_slot {
    FILE *in;
    FILE *out;
};

union stream_slot open_returned_inside_a_local_union(const char *path)
{
    union stream_slot slot;
    FILE *f = fopen(path, "r");
    slot.in = f;
    return slot;
}

void open_closed_through_a_copy(const char *path)
{
    FILE *f = fopen(path, "r");
    FILE *g = f;
    fclose(g);
}

void open_closed_through_a_pointer_to_a_local(const char *path)
{
    FILE *f;
    FILE **slot = &f;
    {
        FILE *opened = fopen(path, "r");
        *slot = opened;
    }
    fclose(*slot);
}

void open_stored_through_an_output_array(FILE **out, const char *path)
{
    FILE *f = fopen(path, "r");
    out[0] = f;
}

void open_closed_through_a_local_array(const char *path)
{
    FILE *streams[2];
    FILE *f = fopen(path, "r");
    streams[0] = f;
    fclose(streams[0]);
}

void stream_table_close(FILE *streams[])
{
    fclose(streams[2]);
}

void open_handed_over_in_a_local_array(const char *path)
{
    FILE *streams[3];
    FILE *f = fopen(path, "r");
    streams[2] = f;
    stream_table_close(streams);
}
