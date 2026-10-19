// MSC04-C pass: the only path from `dispatch` back to itself runs through a
// call via a struct field that happens to share a function's name. A call
// through a field is opaque dispatch, so neither end is reported: not
// `dispatch`, whose own call is the field call, and not `relay`, whose
// path back runs through it.
struct ops {
    void (*relay)(int);
};

void dispatch(struct ops *o, int n) {
    o->relay(n);
}

void relay(int n) {
    dispatch(0, n);
}
