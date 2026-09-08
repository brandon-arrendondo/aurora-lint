/**
 * Rule: EXP34-C
 * Source: testcases
 * Status: FAIL - Should trigger EXP34-C violation. The correlated-exit-guard
 * exemption (task 1074) is exact or it does not apply. Each of these breaks one
 * of its requirements, and the pointer really can be null at the dereference.
 */
struct s { int flags; };

void use(int v);

/* the guard does not exit, so falling past it establishes no negation */
int guard_does_not_exit(int f, struct s *p) {
    if (f && (!p || p->flags == 0)) {
        use(0);
    }
    if (f)
        use(p->flags);
    return 0;
}

/* the flag is not held at the dereference: p may be null when f is false */
int flag_not_held(int f, struct s *p) {
    if (f && (!p || p->flags == 0))
        return 1;

    use(p->flags);
    return 0;
}

/* a DIFFERENT flag holds at the dereference */
int other_flag(int f, int g, struct s *p) {
    if (f && (!p || p->flags == 0))
        return 1;

    if (g)
        use(p->flags);
    return 0;
}

/* the guard has an else, so it is a branch and not a bail-out */
int guard_has_else(int f, struct s *p) {
    if (f && (!p || p->flags == 0))
        return 1;
    else
        use(9);
    if (f)
        use(p->flags);
    return 0;
}

/* three conjuncts, only one of the other two known true -- `!(f && g && X)`
   does not distribute to `!X` */
int one_conjunct_unknown(int f, int g, struct s *p) {
    if (f && g && (!p || p->flags == 0))
        return 1;

    if (f)
        use(p->flags);
    return 0;
}
