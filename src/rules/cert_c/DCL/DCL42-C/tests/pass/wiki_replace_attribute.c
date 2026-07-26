/*
 * Rule: DCL42-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

int to_add = 2;

int add_some(int x) [[reproducible]] {
    return x + to_add;
}

int main(void) {
    add_some(-1);
    to_add = 1;
    return add_some(-1);
}