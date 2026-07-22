/*
 * Rule: DCL13-C
 * Source: task 3 (field-sensitive alias/points-to infrastructure)
 * Status: PASS - Should NOT trigger DCL13-C violation
 * Reason: `buf` is stored into a struct field (rb->data = buf), and the
 * field is later written through elsewhere. The parameter's identity has
 * escaped into the struct, so it must not be recommended as const, even
 * though it is never written through directly. Mirrors CERT wiki's
 * ringbuffer.c:275 ptrBuffer example.
 */

struct ringbuf {
    char *data;
};

void ringbuf_init(struct ringbuf *rb, char *buf) {
    rb->data = buf;
}

void writer(struct ringbuf *rb) {
    rb->data[0] = 'x';
}
