/*
 * Rule: DCL42-C
 * Source: wiki
 * Status: FAIL - Should trigger DCL42-C violation
 */

int to_add = 2;

int add_some(int x) [[unsequenced]] {
    return x + to_add;
}

int main(void) {
    add_some(-1);
    to_add = 1;
    return add_some(-1);
}