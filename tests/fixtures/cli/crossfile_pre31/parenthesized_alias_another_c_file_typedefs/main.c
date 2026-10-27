int step(int);

#define STEP step
#define TWICE(x) ((x) + (x))

static int wrap(int v) {
    return (STEP) (v);
}

int use(void) {
    return TWICE(wrap(1));
}
