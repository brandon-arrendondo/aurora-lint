/*
 * Rule: EXP33-C
 * Source: aurora-lint
 * Status: PASS - every read takes elements a write covered
 *
 * A terminator written at element 0 is all a string read of the buffer
 * needs. A read of an element that was written is defined. And a write
 * the offset does not describe -- memset, a callee handed the buffer or a
 * pointer into it, a fill by a variable index -- covers the whole buffer
 * as before. So does a pointer to it stored elsewhere or stepped, since
 * writes through it are not counted from the buffer's start. A store
 * through a pointer sum covers its element, writes at constant offsets
 * that cover the whole allocation cover the buffer, and a variable index
 * whose values stay among the elements written reads only those.
 */

struct holder {
    int *buf;
};

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fill(int *p);
void fill_bytes(unsigned char *p);

void append_after_the_terminator(const char *src) {
    char *data = malloc(100 * sizeof(char));
    if (data == NULL) {
        return;
    }
    data[0] = '\0';
    strcat(data, src);
    free(data);
}

int elements_that_were_written(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    d[1] = 2;
    return d[0] + d[1] + *d;
}

int written_whole_by_memset(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    memset(d, 0, 10 * sizeof *d);
    return d[5];
}

int written_by_a_callee(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    fill(d);
    return d[5];
}

int written_by_a_variable_index(int n) {
    int i;
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    for (i = 1; i < n; i++) {
        d[i] = i;
    }
    return d[5];
}

int each_branch_wrote_it(int c) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    if (c) {
        d[2] = 1;
    } else {
        memset(d, 0, 4 * sizeof *d);
    }
    return d[2];
}

void read_after_a_terminator(void) {
    char *data = malloc(100 * sizeof(char));
    if (data == NULL) {
        exit(-1);
    }
    data[0] = '\0';
    {
        size_t dataLen = strlen(data);
        if (100 - dataLen > 1) {
            if (fgets(data + dataLen, (int)(100 - dataLen), stdin) != NULL) {
                dataLen = strlen(data);
                if (dataLen > 0 && data[dataLen - 1] == '\n') {
                    data[dataLen - 1] = '\0';
                }
            }
        }
    }
    free(data);
}

int written_by_a_callee_past_the_start(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    fill(d + 1);
    return d[5];
}

int written_by_a_callee_from_an_offset_first(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    fill(1 + d);
    return d[5];
}

int written_by_a_callee_at_an_element_address(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    fill(&d[2]);
    return d[5];
}

int written_by_a_callee_through_a_cast(void) {
    int *d = malloc(10 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    fill_bytes((unsigned char *)(d + 1));
    return d[5];
}

int written_through_an_assigned_copy(void) {
    int *q;
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    q = d;
    q[3] = 7;
    return d[3];
}

int written_through_an_initialized_copy(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    int *q = d;
    q[3] = 7;
    return d[3];
}

int written_through_a_copy_of_an_element_address(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    int *q = &d[1];
    q[2] = 7;
    return d[3];
}

int written_through_a_copy_past_the_start(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    int *q = d + 1;
    q[2] = 7;
    return d[3];
}

int written_through_a_member_copy(void) {
    struct holder h;
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    h.buf = d;
    h.buf[3] = 7;
    return d[3];
}

int read_after_a_step(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[1] = 1;
    d++;
    return d[0];
}

int written_through_a_pointer_sum(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    *(d + 2) = 5;
    *(1 + d) = 2;
    return d[0] + d[1] + d[2] + *(d + 1);
}

int every_element_written(void) {
    int i;
    int s = 0;
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 0;
    d[1] = 0;
    d[2] = 0;
    d[3] = 0;
    for (i = 0; i < 4; i++) {
        s += d[i];
    }
    return s;
}

int index_within_the_elements_written(void) {
    int i;
    int s = 0;
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    d[1] = 2;
    for (i = 0; i < 2; i++) {
        s += d[i];
    }
    return s;
}

int index_known_to_be_written(void) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 1;
    int i = 0;
    return d[i];
}

int every_element_written_unknown_index(int n) {
    int *d = malloc(4 * sizeof *d);
    if (d == NULL) {
        return 0;
    }
    d[0] = 0;
    d[1] = 0;
    d[2] = 0;
    d[3] = 0;
    return d[n];
}
